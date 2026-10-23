-- CRASH_CLASS: LOW
-- PROBE 389f: BSD safe sweep — with SIGSYS ignored + safe-only calls
--
-- Context: 389e sweep died on a lethal syscall. This probe:
-- 1. Ignores SIGSYS first (so nosys stubs return -1 instead of killing)
-- 2. Tests the specific interesting syscalls from 389e that didn't run
-- 3. Sweeps more BSD range with the safety net

print("=== PROBE 389f: BSD safe sweep ===")
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

local function is_kptr(val)
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000
end

local function scan_kptr(addr, count)
    local found = 0
    for i = 0, count - 1 do
        local v = rq(N(addr) + i * 8)
        if v and is_kptr(v) then
            local h, l = get_hi_lo(v)
            print(string.format("    *** KPTR +0x%X: 0x%X%08X ***", i * 8, h, l))
            found = found + 1
        end
    end
    return found
end

local function hex_line(addr, off, len)
    local parts = {}
    for i = off, off + len - 4, 4 do
        local v = rd(N(addr) + i)
        if v then parts[#parts + 1] = string.format("%08X", v) end
    end
    return string.format("  +%03X: %s", off, table.concat(parts, " "))
end

local sc_close = mk(6)

-- ===================================================================
-- [0] Ignore SIGSYS (signal 12) so nosys stubs don't kill us
-- ===================================================================
print("[0] ignoring SIGSYS")

local sc_sigaction = mk(416)
-- sigaction(12, {sa_handler=SIG_IGN(1)}, NULL)
local sa = memory.alloc(32)
zero_buf(sa, 32)
wq(N(sa), uint64(1))  -- sa_handler = SIG_IGN

local ok, rv = pcall(function() return sc_sigaction(uint64(12), sa, uint64(0)) end)
print("  sigaction(SIGSYS, SIG_IGN): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [0]"); return end
print("")

-- ===================================================================
-- [A] Specific tests from 389e that didn't run
-- ===================================================================
print("[A] specific tests")

local buf = memory.alloc(0x200)

-- thr_self(432)
zero_buf(buf, 16)
ok, rv = pcall(function() return mk(432)(buf) end)
local tid_self = rd(N(buf))
print(string.format("  thr_self(432): ret=%d, tid=%d", ok and N(rv) or -999, tid_self or -1))

-- issetugid(253)
ok, rv = pcall(function() return mk(253)() end)
print("  issetugid(253): ret=" .. (ok and N(rv) or -999))

-- getfsstat(394) — MNT_NOWAIT=1
zero_buf(buf, 0x200)
ok, rv = pcall(function() return mk(394)(buf, uint64(0x200), uint64(1)) end)
local r = ok and N(rv) or -999
print(string.format("  getfsstat(394, MNT_NOWAIT): ret=%d", r))
if r > 0 then
    print(hex_line(buf, 0, 32))
    print(hex_line(buf, 32, 32))
    scan_kptr(buf, 32)
end

-- getfsstat size query (NULL buf, MNT_NOWAIT)
ok, rv = pcall(function() return mk(394)(uint64(0), uint64(0), uint64(1)) end)
print("  getfsstat(NULL): ret=" .. (ok and N(rv) or -999) .. " (= count of filesystems)")

-- cpuset_getid(425) — CPU_LEVEL_WHICH=3, CPU_WHICH_PID=2, id=-1
local setid = memory.alloc(16)
zero_buf(setid, 16)
ok, rv = pcall(function() return mk(425)(uint64(3), uint64(2), uint64(0xFFFFFFFF), setid) end)
r = ok and N(rv) or -999
print(string.format("  cpuset_getid(425): ret=%d, setid=%d", r, rd(N(setid)) or -1))

-- cpuset_getaffinity(487) — CPU_LEVEL_WHICH=3, CPU_WHICH_PID=2, id=-1
local mask = memory.alloc(128)
zero_buf(mask, 128)
ok, rv = pcall(function() return mk(487)(uint64(3), uint64(2), uint64(0xFFFFFFFF), uint64(128), mask) end)
r = ok and N(rv) or -999
print(string.format("  cpuset_getaffinity(487): ret=%d", r))
if r == 0 then
    local bits = 0
    for i = 0, 7 do
        local w = rd(N(mask) + i * 4)
        if w then
            local c = 0
            local x = w
            while x > 0 do c = c + x % 2; x = math.floor(x / 2) end
            bits = bits + c
        end
    end
    print(string.format("  CPU affinity: %d cores set", bits))
    print(hex_line(mask, 0, 32))
end

-- modfind(379)
local name_buf = memory.alloc(64)
zero_buf(name_buf, 64)
local mname = "linuxelf"
for i = 0, #mname - 1, 4 do
    local d = 0
    for j = 0, 3 do
        if i + j < #mname then d = d + string.byte(mname, i + j + 1) * (256 ^ j) end
    end
    wd(N(name_buf) + i, d)
end
ok, rv = pcall(function() return mk(379)(name_buf) end)
print("  modfind('linuxelf'): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Broader sweep (with SIGSYS ignored)
-- ===================================================================
print("[B] broader BSD sweep (SIGSYS ignored)")

-- Test ALL numbers in groups, print any non-(-1) result
local interesting = {}

-- Group 1: 70-130 (misc)
for num = 70, 130 do
    if not alive() then break end
    -- Skip known-tested/lethal
    if num ~= 97 and num ~= 92 and num ~= 98 and num ~= 99 and num ~= 100
       and num ~= 101 and num ~= 102 and num ~= 125 then
        local sc = mk(num)
        ok, rv = pcall(function() return sc(uint64(0)) end)
        r = ok and N(rv) or -999
        if r ~= -1 and r ~= -999 then
            interesting[#interesting + 1] = string.format("%d:ret=%d", num, r)
        end
    end
end

-- Group 2: 130-200
for num = 130, 200 do
    if not alive() then break end
    if num ~= 140 and num ~= 165 then  -- skip adjtime, sysarch (tested)
        local sc = mk(num)
        ok, rv = pcall(function() return sc(uint64(0)) end)
        r = ok and N(rv) or -999
        if r ~= -1 and r ~= -999 then
            interesting[#interesting + 1] = string.format("%d:ret=%d", num, r)
        end
    end
end

-- Group 3: 200-300
for num = 200, 300 do
    if not alive() then break end
    if num ~= 202 and num ~= 240 and num ~= 253 then  -- skip sysctl, nanosleep, issetugid
        local sc = mk(num)
        ok, rv = pcall(function() return sc(uint64(0)) end)
        r = ok and N(rv) or -999
        if r ~= -1 and r ~= -999 then
            interesting[#interesting + 1] = string.format("%d:ret=%d", num, r)
        end
    end
end

-- Group 4: 300-530
for num = 300, 530 do
    if not alive() then break end
    -- Skip tested: 328,330,362,363,392,394,397,400-408,416,421,432,441,455,466
    if num ~= 328 and num ~= 330 and num ~= 362 and num ~= 363
       and num ~= 392 and num ~= 394 and num ~= 397
       and not (num >= 400 and num <= 408)
       and num ~= 416 and num ~= 421 and num ~= 432
       and num ~= 441 and num ~= 455 and num ~= 456 and num ~= 466 then
        local sc = mk(num)
        ok, rv = pcall(function() return sc(uint64(0)) end)
        r = ok and N(rv) or -999
        if r ~= -1 and r ~= -999 then
            interesting[#interesting + 1] = string.format("%d:ret=%d", num, r)
        end
    end
end

print("  non-(-1) results: " .. table.concat(interesting, ", "))

if not alive() then print("DEAD after [B]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389f COMPLETE ===")
