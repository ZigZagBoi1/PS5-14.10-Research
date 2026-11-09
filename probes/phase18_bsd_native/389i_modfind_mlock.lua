-- CRASH_CLASS: LOW
-- PROBE 389i: modfind/modstat exploration + mlock with real args
--
-- Context: 389h found modfind(NULL)=0, mlock(0,0)=0, utrace(0,0)=0.
-- This probe explores what modules exist and if mlock works on real pages.

print("=== PROBE 389i: modfind/modstat + mlock ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Ignore SIGSYS
local sa = memory.alloc(32)
zero_buf(sa, 32)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local buf = memory.alloc(0x400)

-- ===================================================================
-- [A] modstat(378) — enumerate kernel modules by ID
-- ===================================================================
print("[A] modstat enumeration")

-- struct module_stat { int version; char name[32]; int refs; int id; ... }
-- On FreeBSD the struct is ~0x44 bytes, version should be set first
local sc_modstat = mk(378)
local sc_modfind = mk(379)
local sc_modfnext = mk(380) -- actually modfnext is 302

-- Try modstat for IDs 0-20
for modid = 0, 20 do
    if not alive() then break end
    zero_buf(buf, 0x100)
    -- Set version to the expected size
    wd(N(buf), 0x44)  -- version = sizeof(struct module_stat)
    local ok, rv = pcall(function() return sc_modstat(uint64(modid), buf) end)
    local r = ok and N(rv) or -999
    if r == 0 then
        -- Read the name (starts at offset 4, 32 bytes)
        local name_chars = {}
        for i = 0, 31 do
            local off = 4 + i
            local dw = rd(N(buf) + (off - off % 4))
            if dw then
                local shift = (off % 4) * 8
                local ch = math.floor(dw / (2 ^ shift)) % 256
                if ch == 0 then break end
                name_chars[#name_chars + 1] = string.char(ch)
            end
        end
        local name = table.concat(name_chars)
        local refs = rd(N(buf) + 0x24) or 0
        local mid = rd(N(buf) + 0x28) or 0
        print(string.format("  id=%d: name='%s' refs=%d mid=%d", modid, name, refs, mid))

        -- Dump raw for first few
        if modid <= 3 then
            for line = 0, 0x40, 16 do
                local parts = {}
                for i = line, line + 12, 4 do
                    local v = rd(N(buf) + i)
                    parts[#parts + 1] = string.format("%08X", v or 0)
                end
                print(string.format("    +%02X: %s", line, table.concat(parts, " ")))
            end
        end
    end
end

-- modfnext(302) — iterate modules
print("  modfnext chain:")
local sc_modfnext = mk(302)
local cur = 0
for i = 1, 30 do
    if not alive() then break end
    local ok, rv = pcall(function() return sc_modfnext(uint64(cur)) end)
    local r = ok and N(rv) or -999
    if r <= 0 then
        print(string.format("  modfnext(%d)=%d (end)", cur, r))
        break
    end
    print(string.format("  modfnext(%d)=%d", cur, r))
    cur = r
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] mlock with real addresses
-- ===================================================================
print("[B] mlock tests")

local sc_mlock = mk(203)
local sc_munlock = mk(204)

-- Allocate a heap page and try to lock it
local heap_page = memory.alloc(0x4000)  -- 16KB = 1 PS5 page
zero_buf(heap_page, 0x4000)
local heap_addr = N(heap_page)
-- Align to page boundary
local aligned = heap_addr
if aligned % 0x4000 ~= 0 then
    aligned = aligned + (0x4000 - (aligned % 0x4000))
end

print(string.format("  heap page: 0x%X (aligned: 0x%X)", heap_addr, aligned))

-- mlock the aligned page
local ok, rv = pcall(function() return sc_mlock(uint64(aligned), uint64(0x4000)) end)
print("  mlock(heap, 16K): ret=" .. (ok and N(rv) or -999))

-- munlock
ok, rv = pcall(function() return sc_munlock(uint64(aligned), uint64(0x4000)) end)
print("  munlock(heap, 16K): ret=" .. (ok and N(rv) or -999))

-- GPU mmap page
local sc_mmap = mk(477)
local gpu = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print(string.format("  GPU page: 0x%X%08X", gpu_h, gpu_l))

ok, rv = pcall(function() return sc_mlock(uint64(gpu_l), uint64(0x4000)) end)
print("  mlock(GPU, 16K): ret=" .. (ok and N(rv) or -999))

-- Try mlock on a kernel address (should fail)
ok, rv = pcall(function() return sc_mlock(uint64(string.format("0x%X%08X", 0xFFFF8000, 0)), uint64(0x4000)) end)
print("  mlock(kernel VA): ret=" .. (ok and N(rv) or -999))

-- mlockall(324) — lock ALL pages
ok, rv = pcall(function() return mk(324)(uint64(1)) end)  -- MCL_CURRENT=1
print("  mlockall(MCL_CURRENT): ret=" .. (ok and N(rv) or -999))

ok, rv = pcall(function() return mk(324)(uint64(2)) end)  -- MCL_FUTURE=2
print("  mlockall(MCL_FUTURE): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] utrace exploration
-- ===================================================================
print("[C] utrace")

local sc_utrace = mk(475)

-- utrace(addr, len) — sends len bytes at addr to DTrace/ktrace
-- With real data
local trace_buf = memory.alloc(64)
zero_buf(trace_buf, 64)
wd(N(trace_buf), 0x41414141)
wd(N(trace_buf) + 4, 0x42424242)

ok, rv = pcall(function() return sc_utrace(trace_buf, uint64(8)) end)
print("  utrace(8B data): ret=" .. (ok and N(rv) or -999))

ok, rv = pcall(function() return sc_utrace(trace_buf, uint64(64)) end)
print("  utrace(64B data): ret=" .. (ok and N(rv) or -999))

-- Large size to see if there's a limit
ok, rv = pcall(function() return sc_utrace(trace_buf, uint64(0x10000)) end)
print("  utrace(64K): ret=" .. (ok and N(rv) or -999))

ok, rv = pcall(function() return sc_utrace(uint64(0), uint64(0)) end)
print("  utrace(NULL,0): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] More targeted tests
-- ===================================================================
print("[D] more tests")

-- getloginclass(523)
zero_buf(buf, 256)
ok, rv = pcall(function() return mk(523)(buf, uint64(256)) end)
local r = ok and N(rv) or -999
print("  523 getloginclass: ret=" .. r)
if r == 0 then
    local chars = {}
    for i = 0, 63 do
        local off = i
        local dw = rd(N(buf) + (off - off % 4))
        if dw then
            local shift = (off % 4) * 8
            local ch = math.floor(dw / (2 ^ shift)) % 256
            if ch == 0 then break end
            chars[#chars + 1] = string.char(ch)
        end
    end
    print("    class: '" .. table.concat(chars) .. "'")
end

-- getresuid(360) — real/effective/saved uid
local ruid = memory.alloc(16)
local euid = memory.alloc(16)
local suid = memory.alloc(16)
zero_buf(ruid, 16); zero_buf(euid, 16); zero_buf(suid, 16)
ok, rv = pcall(function() return mk(360)(ruid, euid, suid) end)
print(string.format("  360 getresuid: ret=%d, r=%d e=%d s=%d",
    ok and N(rv) or -999, rd(N(ruid)) or -1, rd(N(euid)) or -1, rd(N(suid)) or -1))

-- getresgid(361)
local rgid = memory.alloc(16)
local egid = memory.alloc(16)
local sgid = memory.alloc(16)
zero_buf(rgid, 16); zero_buf(egid, 16); zero_buf(sgid, 16)
ok, rv = pcall(function() return mk(361)(rgid, egid, sgid) end)
print(string.format("  361 getresgid: ret=%d, r=%d e=%d s=%d",
    ok and N(rv) or -999, rd(N(rgid)) or -1, rd(N(egid)) or -1, rd(N(sgid)) or -1))

-- clock_getres(234) — timer resolution
local res = memory.alloc(16)
for _, clk in ipairs({{0,"REALTIME"},{4,"MONOTONIC"},{12,"MONOTONIC_FAST"},{13,"REALTIME_PRECISE"}}) do
    zero_buf(res, 16)
    ok, rv = pcall(function() return mk(234)(uint64(clk[1]), res) end)
    r = ok and N(rv) or -999
    if r == 0 then
        local nsec = rd(N(res) + 8)
        print(string.format("  234 clock_getres(%s): %d ns", clk[2], nsec or -1))
    end
end

-- ktimer_create(235) — already tested but let's see max count
print("  ktimer IDs:")
local sc_tc = mk(235)
local sc_td = mk(236)
local tev = memory.alloc(32)
local tid_buf = memory.alloc(8)
local timer_ids = {}
for i = 1, 30 do
    if not alive() then break end
    zero_buf(tev, 32)
    wd(N(tev), 1)  -- SIGEV_NONE
    zero_buf(tid_buf, 8)
    ok, rv = pcall(function() return sc_tc(uint64(0), tev, tid_buf) end)
    r = ok and N(rv) or -999
    if r ~= 0 then
        print(string.format("  ktimer ceiling at %d timers", i - 1))
        break
    end
    timer_ids[#timer_ids + 1] = rd(N(tid_buf))
end
if #timer_ids > 0 then
    local ids_str = {}
    for _, id in ipairs(timer_ids) do ids_str[#ids_str + 1] = tostring(id) end
    print("  IDs: " .. table.concat(ids_str, ","))
    -- Clean up
    for _, id in ipairs(timer_ids) do
        pcall(function() sc_td(uint64(id)) end)
    end
end

if not alive() then print("DEAD after [D]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389i COMPLETE ===")
