-- CRASH_CLASS: RISKY
-- PROBE 79b: Isolated testing of sys 662-670 (one per connection)
--
-- Context: sys 661 instantly kills the process (probes 54c/54f). But 661 kills
-- at the FIRST call, so 662-670 were NEVER executed. The "AIO range dead" verdict
-- generalizes from n=1. The Relapse exploit's AIO prerequisite is in this range.
--
-- IMPORTANT: This probe tests ONE syscall per run. Change TEST_NUM before each run.
-- The PS5 may crash after each call. Reboot between runs.
--
-- Usage: Set TEST_NUM to the syscall number to test (662-670).
-- Run one at a time. If the process survives, we have a live AIO syscall.

local TEST_NUM = 662

print("=== PROBE 79b: AIO ISOLATION SWEEP ===")
print("TEST_NUM=" .. TEST_NUM)
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

if TEST_NUM < 662 or TEST_NUM > 670 then
    print("[!] TEST_NUM must be 662-670")
    print("=== PROBE 79b ABORTED ===")
    return
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Allocate buffers for various argument patterns
local buf1 = memory.alloc(0x200)
local buf2 = memory.alloc(0x200)
local buf3 = memory.alloc(0x200)
zero(buf1, 0x200)
zero(buf2, 0x200)
zero(buf3, 0x200)

local sc_test = make_syscall(TEST_NUM)

-- FreeBSD AIO syscall reference (standard numbers, Sony may differ):
-- aio_return = 314, aio_suspend = 315, aio_cancel = 316
-- aio_error = 317, oaio_read = 318, oaio_write = 319
-- lio_listio = 320, aio_read = 521, aio_write = 522
-- aio_waitcomplete = 559, aio_fsync = 565
-- Sony range 661-670 may be custom AIO variants

print("[1] Testing sys " .. TEST_NUM .. " with zero args...")
local ok1, rv1 = pcall(function()
    return sc_test(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("[1] ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

local c1_ok, c1_pid = canary()
print("[1] canary ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

if not c1_ok then
    print("[!] Process damaged after zero-arg call")
    print("=== PROBE 79b PARTIAL ===")
    return
end

-- Pattern 2: (buf, size, 0, 0, 0, 0) — buffer output pattern
print("")
print("[2] Testing sys " .. TEST_NUM .. " with (buf, size)...")
local ok2, rv2 = pcall(function()
    return sc_test(uint64(buf1), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("[2] ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))

-- Check if buf1 was written
local b1_d0 = rd(buf1)
local b1_d1 = rd(buf1 + 4)
local b1_d2 = rd(buf1 + 8)
print("[2] buf1: " .. string.format("0x%08X 0x%08X 0x%08X", b1_d0 or 0, b1_d1 or 0, b1_d2 or 0))

local c2_ok, c2_pid = canary()
print("[2] canary ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

if not c2_ok then
    print("[!] Process damaged after buf-arg call")
    print("=== PROBE 79b PARTIAL ===")
    return
end

-- Pattern 3: aiocb-like struct (FreeBSD struct aiocb)
-- struct aiocb has fd at +0, offset at +8, buf at +16, nbytes at +24
print("")
print("[3] Testing sys " .. TEST_NUM .. " with aiocb-like struct...")
zero(buf2, 0x200)
wd(buf2 + 0, 0xFFFFFFFF)  -- fd = -1
wq(buf2 + 8, uint64(0))   -- offset = 0
wq(buf2 + 16, uint64(buf3)) -- buf = output buffer
wq(buf2 + 24, uint64(0x100)) -- nbytes = 256
local ok3, rv3 = pcall(function()
    return sc_test(uint64(buf2), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("[3] ok=" .. tostring(ok3) .. " rv=" .. tostring(rv3))

local c3_ok, c3_pid = canary()
print("[3] canary ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

-- Pattern 4: (fd=-1, buf, nbytes, offset, 0, 0) — read/write pattern
print("")
print("[4] Testing sys " .. TEST_NUM .. " with (fd, buf, nbytes)...")
zero(buf3, 0x200)
local ok4, rv4 = pcall(function()
    return sc_test(uint64(0xFFFFFFFF), uint64(buf3), uint64(0x100), uint64(0), uint64(0), uint64(0))
end)
print("[4] ok=" .. tostring(ok4) .. " rv=" .. tostring(rv4))

local c4_ok, c4_pid = canary()
print("[4] canary ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

-- Final canary with sleep
print("")
local ts = memory.alloc(16)
wq(ts, 1); wq(ts + 8, 0)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
local cf_ok, cf_pid = canary()
print("[final] canary_1s ok=" .. tostring(cf_ok) .. " pid=" .. tostring(cf_pid))

print("")
print("=== PROBE 79b: sys " .. TEST_NUM .. " COMPLETE ===")
print("If process survived: sys " .. TEST_NUM .. " is NOT lethal (unlike 661)")
print("If PS5 crashed: sys " .. TEST_NUM .. " is also lethal")
print("=== PROBE 79b COMPLETE ===")
