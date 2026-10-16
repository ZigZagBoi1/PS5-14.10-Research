-- CRASH_CLASS: MODERATE (unknown Sony syscall, may crash with bad args)
-- PROBE 44b: Sony syscall 557 deep investigation
--
-- 43g sweep found syscall 557 returns 0x4205 (16901) — the only Sony
-- syscall in the 540-650 range that returned a non-negative, non-zero value.
-- This probe investigates what 557 does by varying arguments.
--
-- Known Sony syscalls near 557:
--   538/539: evf_create/evf_delete
--   547-552: dmem operations
--   553-556: unknown
--   557: THIS ONE — returns 0x4205
--   558-570: unknown
--
-- Strategy: call with various argument patterns, buffer sizes, and
-- known object handles to determine its function.

print("=== PROBE 44b: SONY SYSCALL 557 DEEP INVESTIGATION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc557 = make_syscall(557)
local sc_getpid = make_syscall(20)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Reproduce baseline: 557 with no args
--------------------------------------------------------------------
print("")
print("=== A: BASELINE (no args) ===")
local ok, ret = pcall(function() return sc557() end)
local rv = ok and to_num(ret) or -999
print(string.format("557(): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))

-- Also try with 0 args explicitly
ok, ret = pcall(function() return sc557(uint64(0)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(0): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))

ok, ret = pcall(function() return sc557(uint64(0), uint64(0)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(0,0): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))

--------------------------------------------------------------------
-- B) Try with output buffer (might be a query/info syscall)
--------------------------------------------------------------------
print("")
print("=== B: WITH OUTPUT BUFFER ===")
local buf = memory.alloc(0x1000)
for i = 0, 0xFF do safe_wd(buf + i*4, 0) end

-- Pattern: syscall(buf, len)
ok, ret = pcall(function() return sc557(uint64(buf), uint64(0x1000)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(buf, 4096): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))

-- Check if buffer was modified
local changed = 0
for i = 0, 63 do
    local v = safe_rd(buf + i*4)
    if v and v ~= 0 then
        print(string.format("  buf+%03X: %08X", i*4, v))
        changed = changed + 1
    end
end
print(string.format("  changed dwords: %d", changed))

-- Zero and try: syscall(0, buf, len)
for i = 0, 0xFF do safe_wd(buf + i*4, 0) end
ok, ret = pcall(function() return sc557(uint64(0), uint64(buf), uint64(0x1000)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(0, buf, 4096): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))
changed = 0
for i = 0, 63 do
    local v = safe_rd(buf + i*4)
    if v and v ~= 0 then
        print(string.format("  buf+%03X: %08X", i*4, v))
        changed = changed + 1
    end
end
print(string.format("  changed dwords: %d", changed))

--------------------------------------------------------------------
-- C) Vary first argument (might be a type/command selector)
--------------------------------------------------------------------
print("")
print("=== C: VARY ARG1 ===")
local test_vals = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 64, 128, 255, 256, 512, 1024}
for _, v in ipairs(test_vals) do
    ok, ret = pcall(function() return sc557(uint64(v)) end)
    rv = ok and to_num(ret) or -999
    if rv ~= -999 then
        print(string.format("  557(%d): ret=%d (0x%X)", v, rv, rv >= 0 and rv or 0))
    else
        print(string.format("  557(%d): CRASHED", v))
    end
end

--------------------------------------------------------------------
-- D) Try with PID as argument
--------------------------------------------------------------------
print("")
print("=== D: WITH PID ===")
ok, ret = pcall(function() return sc557(uint64(pid)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(pid=%d): ret=%d (0x%X)", pid, rv, rv >= 0 and rv or 0))

ok, ret = pcall(function() return sc557(uint64(pid), uint64(buf), uint64(0x100)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(pid, buf, 256): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))
changed = 0
for i = 0, 63 do
    local v = safe_rd(buf + i*4)
    if v and v ~= 0 then
        print(string.format("  buf+%03X: %08X", i*4, v))
        changed = changed + 1
    end
end
if changed > 0 then print(string.format("  changed dwords: %d", changed)) end

--------------------------------------------------------------------
-- E) Decode 0x4205 — might be a bitfield or status code
--------------------------------------------------------------------
print("")
print("=== E: DECODE 0x4205 ===")
print(string.format("0x4205 = %d decimal", 0x4205))
print(string.format("  bits: %016s", "0100001000000101"))
print(string.format("  byte 0: 0x%02X (%d)", 0x05, 0x05))
print(string.format("  byte 1: 0x%02X (%d)", 0x42, 0x42))
print("  possible: type=0x42 (66), flags=0x05 (5)")
print("  possible: PS5 process type or sandbox level?")

--------------------------------------------------------------------
-- F) Neighbors 553-561 with safe calls
--------------------------------------------------------------------
print("")
print("=== F: NEIGHBORS 553-561 ===")
for n = 553, 561 do
    if n ~= 557 then
        ok, ret = pcall(function() return make_syscall(n)() end)
        rv = ok and to_num(ret) or -999
        local status = "ret=" .. rv
        if rv == -999 then status = "CRASHED/KILLED" end
        print(string.format("  %d: %s", n, status))
    end
end

--------------------------------------------------------------------
-- G) Try 557 with fd arguments (socket, /dev/hid, etc.)
--------------------------------------------------------------------
print("")
print("=== G: WITH FD ARGUMENTS ===")
-- Open a socket for testing
local sc_socket = make_syscall(97)
local sock_fd = -1
pcall(function()
    sock_fd = to_num(sc_socket(uint64(2), uint64(2), uint64(0)))
end)
print(string.format("test socket fd: %d", sock_fd))

if sock_fd > 0 then
    ok, ret = pcall(function() return sc557(uint64(sock_fd)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("557(sock_fd=%d): ret=%d (0x%X)", sock_fd, rv, rv >= 0 and rv or 0))

    ok, ret = pcall(function() return sc557(uint64(sock_fd), uint64(buf), uint64(0x100)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("557(sock_fd, buf, 256): ret=%d (0x%X)", rv, rv >= 0 and rv or 0))
end

-- Try with TID
print("")
print("=== H: WITH TID ===")
local sc_thrself = make_syscall(432)
local tid_buf = memory.alloc(8)
safe_wd(tid_buf, 0)
pcall(function() sc_thrself(uint64(tid_buf)) end)
local tid = safe_rd(tid_buf) or 0
print(string.format("tid: %d", tid))

ok, ret = pcall(function() return sc557(uint64(tid)) end)
rv = ok and to_num(ret) or -999
print(string.format("557(tid=%d): ret=%d (0x%X)", tid, rv, rv >= 0 and rv or 0))

print("")
print("=== PROBE 44b COMPLETE ===")
