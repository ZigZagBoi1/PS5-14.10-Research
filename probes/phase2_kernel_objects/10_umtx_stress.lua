-- 14.10 Recon Probe 10: umtx_op stress test
-- CVE-2024-43102 was a use-after-free in umtx shared memory handling
-- Target: UMTX_OP_SHM (25), UMTX_OP_ROBUST_LISTS (26), and
-- WAIT/WAKE races that can be triggered single-threaded via signals/timers
-- SAFE: probing error paths and observing kernel behavior

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: UMTX_OP STRESS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_umtx_op = 557,
    sc_mmap = 477, sc_munmap = 73,
    sc_pipe = 42, sc_close = 6, sc_read = 3, sc_write = 4,
    sc_socket = 97, sc_setsockopt = 105,
    sc_shm_open2 = 532,
    sc_ftruncate = 480,
    sc_thr_self = 434,
})

local UMTX_OP_LOCK       = 0
local UMTX_OP_UNLOCK     = 1
local UMTX_OP_WAIT       = 2
local UMTX_OP_WAKE       = 3
local UMTX_OP_MUTEX_TRYLOCK = 4
local UMTX_OP_MUTEX_LOCK = 5
local UMTX_OP_MUTEX_UNLOCK = 6
local UMTX_OP_SET_CEILING = 7
local UMTX_OP_CV_WAIT    = 8
local UMTX_OP_CV_SIGNAL  = 9
local UMTX_OP_CV_BROADCAST = 10
local UMTX_OP_WAIT_UINT  = 11
local UMTX_OP_RW_RDLOCK  = 12
local UMTX_OP_RW_WRLOCK  = 13
local UMTX_OP_RW_UNLOCK  = 14
local UMTX_OP_WAIT_UINT_PRIVATE = 15
local UMTX_OP_WAKE_PRIVATE = 16
local UMTX_OP_MUTEX_WAIT = 17
local UMTX_OP_MUTEX_WAKE = 18
local UMTX_OP_SEM_WAIT   = 19
local UMTX_OP_SEM_WAKE   = 20
local UMTX_OP_NWAKE_PRIVATE = 21
local UMTX_OP_MUTEX_WAKE2 = 22
local UMTX_OP_SEM2_WAIT  = 23
local UMTX_OP_SEM2_WAKE  = 24
local UMTX_OP_SHM        = 25
local UMTX_OP_ROBUST_LISTS = 26

-- Get our thread ID
local tid_buf = memory.alloc(8)
pcall(function() syscall.sc_thr_self(tid_buf) end)
local tid = memory.read_dword(tid_buf):tonumber()
log("tid: " .. tid)

-- ============================================================
-- STRESS 1: UMTX_OP_SHM — the CVE-2024-43102 family
-- This op creates/destroys shared memory keys tied to umtx.
-- The original bug was a race between SHM create and destroy.
-- Even single-threaded, we can stress the alloc/free path.
-- ============================================================
log("")
log("--- STRESS 1: UMTX_OP_SHM alloc/free churn ---")

-- UMTX_SHM_CREAT=1, UMTX_SHM_LOOKUP=2, UMTX_SHM_DESTROY=4, UMTX_SHM_ALIVE=8
local UMTX_SHM_CREAT   = 1
local UMTX_SHM_LOOKUP  = 2
local UMTX_SHM_DESTROY = 4
local UMTX_SHM_ALIVE   = 8

local shm_key = memory.alloc(256)
memory.write_dword(shm_key, 0x41414141)

local shm_results = { create_ok = 0, create_fail = 0, lookup_ok = 0,
    destroy_ok = 0, alive_ok = 0 }

-- Create, lookup, alive, destroy cycle
for round = 1, 100 do
    -- Create
    local ok1, r1 = pcall(function()
        return syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, UMTX_SHM_CREAT, 0, 0, 0)
    end)
    if ok1 then
        local rv = r1:tonumber()
        if rv >= 0 then
            shm_results.create_ok = shm_results.create_ok + 1
        else
            shm_results.create_fail = shm_results.create_fail + 1
        end
    else
        shm_results.create_fail = shm_results.create_fail + 1
    end

    -- Lookup
    local ok2 = pcall(function()
        return syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, UMTX_SHM_LOOKUP, 0, 0, 0)
    end)
    if ok2 then shm_results.lookup_ok = shm_results.lookup_ok + 1 end

    -- Alive check
    local ok3 = pcall(function()
        return syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, UMTX_SHM_ALIVE, 0, 0, 0)
    end)
    if ok3 then shm_results.alive_ok = shm_results.alive_ok + 1 end

    -- Destroy
    local ok4 = pcall(function()
        return syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, UMTX_SHM_DESTROY, 0, 0, 0)
    end)
    if ok4 then shm_results.destroy_ok = shm_results.destroy_ok + 1 end
end

log("  100 rounds: create=" .. shm_results.create_ok ..
    " lookup=" .. shm_results.lookup_ok ..
    " alive=" .. shm_results.alive_ok ..
    " destroy=" .. shm_results.destroy_ok ..
    " create_fail=" .. shm_results.create_fail)

-- Rapid create without destroy (resource exhaustion / leak test)
log("")
log("  rapid create without destroy...")
local create_count = 0
for i = 1, 200 do
    local key = memory.alloc(8)
    memory.write_dword(key, 0x42420000 + i)
    local ok = pcall(function()
        return syscall.sc_umtx_op(key, UMTX_OP_SHM, UMTX_SHM_CREAT, 0, 0, 0)
    end)
    if ok then create_count = create_count + 1 end
end
log("  created " .. create_count .. "/200 SHM keys without destroy")

-- Double destroy (UAF probe)
log("")
log("  double-destroy test...")
local dd_key = memory.alloc(8)
memory.write_dword(dd_key, 0xDEAD0001)
pcall(function() syscall.sc_umtx_op(dd_key, UMTX_OP_SHM, UMTX_SHM_CREAT, 0, 0, 0) end)
local dd1_ok, dd1_err = pcall(function()
    return syscall.sc_umtx_op(dd_key, UMTX_OP_SHM, UMTX_SHM_DESTROY, 0, 0, 0)
end)
log("  destroy 1: " .. (dd1_ok and "OK" or tostring(dd1_err):sub(1,40)))
local dd2_ok, dd2_err = pcall(function()
    return syscall.sc_umtx_op(dd_key, UMTX_OP_SHM, UMTX_SHM_DESTROY, 0, 0, 0)
end)
log("  destroy 2: " .. (dd2_ok and "OK" or tostring(dd2_err):sub(1,40)))
-- Lookup after double destroy
local dd3_ok, dd3_err = pcall(function()
    return syscall.sc_umtx_op(dd_key, UMTX_OP_SHM, UMTX_SHM_LOOKUP, 0, 0, 0)
end)
log("  lookup after dd: " .. (dd3_ok and "OK(!)" or tostring(dd3_err):sub(1,40)))

-- ============================================================
-- STRESS 2: UMTX_OP_ROBUST_LISTS
-- This registers a list of mutexes to clean up on thread exit.
-- Passing crafted pointers probes kernel's handling of userspace
-- memory references in the robust list path.
-- ============================================================
log("")
log("--- STRESS 2: UMTX_OP_ROBUST_LISTS ---")

-- struct umtx_robust_lists_params { size, robust_list_offset, robust_inact_offset }
local robust_params = memory.alloc(64)

-- Test 1: register with valid-looking structure
memory.write_qword(robust_params, 24)  -- size = sizeof(struct)
local dummy_list = memory.alloc(4096)
memory.write_qword(dummy_list, 0)  -- head = NULL (empty list)
memory.write_qword(robust_params + 8, dummy_list)  -- robust_list_offset
memory.write_qword(robust_params + 16, 0)          -- robust_inact_offset

local rob_ok, rob_err = pcall(function()
    return syscall.sc_umtx_op(robust_params, UMTX_OP_ROBUST_LISTS, 24, 0, 0, 0)
end)
log("  register robust list: " .. (rob_ok and "OK" or tostring(rob_err):sub(1,50)))

-- Test 2: register with oversized struct (bounds check)
memory.write_qword(robust_params, 4096)
local rob2_ok, rob2_err = pcall(function()
    return syscall.sc_umtx_op(robust_params, UMTX_OP_ROBUST_LISTS, 4096, 0, 0, 0)
end)
log("  oversized robust: " .. (rob2_ok and "ACCEPTED(!)" or tostring(rob2_err):sub(1,50)))

-- Test 3: register with zero size
memory.write_qword(robust_params, 0)
local rob3_ok, rob3_err = pcall(function()
    return syscall.sc_umtx_op(robust_params, UMTX_OP_ROBUST_LISTS, 0, 0, 0, 0)
end)
log("  zero-size robust: " .. (rob3_ok and "ACCEPTED" or tostring(rob3_err):sub(1,50)))

-- Test 4: register then re-register (double register)
memory.write_qword(robust_params, 24)
memory.write_qword(robust_params + 8, dummy_list)
pcall(function() syscall.sc_umtx_op(robust_params, UMTX_OP_ROBUST_LISTS, 24, 0, 0, 0) end)
local new_list = memory.alloc(4096)
memory.write_qword(new_list, 0)
memory.write_qword(robust_params + 8, new_list)
local rob4_ok = pcall(function()
    return syscall.sc_umtx_op(robust_params, UMTX_OP_ROBUST_LISTS, 24, 0, 0, 0)
end)
log("  double-register: " .. (rob4_ok and "OK (re-register works)" or "REJECTED"))

-- ============================================================
-- STRESS 3: WAIT_UINT_PRIVATE with timeout=0 (non-blocking)
-- Tests the umtx wait path without actually blocking.
-- The val argument is compared to *addr — if they match,
-- the thread blocks. We set them to not match so it returns.
-- ============================================================
log("")
log("--- STRESS 3: WAIT/WAKE churn ---")

local wait_addr = memory.alloc(256)
memory.write_dword(wait_addr, 0)

-- Timespec for immediate timeout
local ts = memory.alloc(16)
memory.write_qword(ts, 0)
memory.write_qword(ts + 8, 1) -- 1 nanosecond

local wait_ok = 0
local wait_timeout = 0
local wait_err_count = 0

for i = 1, 500 do
    -- Set value to i so it won't match val=0 => immediate return
    memory.write_dword(wait_addr, i)

    local ok, err = pcall(function()
        return syscall.sc_umtx_op(wait_addr, UMTX_OP_WAIT_UINT_PRIVATE, 0, 0, ts, 0)
    end)
    if ok then
        wait_ok = wait_ok + 1
    else
        local es = tostring(err)
        if es:find("ETIMEDOUT") or es:find("EWOULDBLOCK") then
            wait_timeout = wait_timeout + 1
        else
            wait_err_count = wait_err_count + 1
        end
    end

    -- Wake (should be no-op since nobody is waiting)
    pcall(function()
        syscall.sc_umtx_op(wait_addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0)
    end)
end
log("  500 wait/wake: ok=" .. wait_ok .. " timeout=" .. wait_timeout .. " err=" .. wait_err_count)

-- ============================================================
-- STRESS 4: MUTEX operations — trylock/unlock without owner
-- Tests the kernel's mutex state machine for logic errors
-- ============================================================
log("")
log("--- STRESS 4: mutex state machine ---")

-- umutex structure: volatile lwpid_t m_owner (4 bytes) + uint32_t m_flags (4) + ...
local umutex = memory.alloc(256)
memory.write_dword(umutex, 0)     -- m_owner = unowned
memory.write_dword(umutex + 4, 0) -- m_flags = 0
memory.write_dword(umutex + 8, 0) -- m_ceilings[0]
memory.write_dword(umutex + 12, 0) -- m_ceilings[1]
memory.write_dword(umutex + 16, 0) -- m_rb_lnk

-- Trylock (should succeed since unowned)
local tl_ok, tl_err = pcall(function()
    return syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_TRYLOCK, 0, 0, 0, 0)
end)
local owner_after_lock = memory.read_dword(umutex):tonumber()
log("  trylock: " .. (tl_ok and "OK" or tostring(tl_err):sub(1,30)) .. " owner=" .. owner_after_lock)

-- Unlock
local ul_ok, ul_err = pcall(function()
    return syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_UNLOCK, 0, 0, 0, 0)
end)
local owner_after_unlock = memory.read_dword(umutex):tonumber()
log("  unlock: " .. (ul_ok and "OK" or tostring(ul_err):sub(1,30)) .. " owner=" .. owner_after_unlock)

-- Double unlock (logic error probe)
local ul2_ok, ul2_err = pcall(function()
    return syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_UNLOCK, 0, 0, 0, 0)
end)
log("  double unlock: " .. (ul2_ok and "OK(!)" or tostring(ul2_err):sub(1,30)))

-- Lock with UMTX_OP_MUTEX_WAIT then immediately wake
memory.write_dword(umutex, tid) -- pretend we own it
local mw_ok = pcall(function()
    return syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_WAKE, 0, 0, 0, 0)
end)
log("  wake owned mutex: " .. (mw_ok and "OK" or "FAIL"))

-- MUTEX_WAKE2 with flags
memory.write_dword(umutex, 0) -- unowned
local mw2_ok = pcall(function()
    return syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_WAKE2, 0, 0, 0, 0)
end)
log("  wake2 unowned: " .. (mw2_ok and "OK" or "FAIL"))

-- Rapid lock/unlock churn
local churn_ok = 0
for i = 1, 200 do
    memory.write_dword(umutex, 0)
    local ok1 = pcall(function()
        syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_TRYLOCK, 0, 0, 0, 0)
    end)
    local ok2 = pcall(function()
        syscall.sc_umtx_op(umutex, UMTX_OP_MUTEX_UNLOCK, 0, 0, 0, 0)
    end)
    if ok1 and ok2 then churn_ok = churn_ok + 1 end
end
log("  200 lock/unlock rounds: " .. churn_ok .. " ok")

-- ============================================================
-- STRESS 5: SEM2 wait/wake (semaphore v2)
-- ============================================================
log("")
log("--- STRESS 5: SEM2 churn ---")

-- _usem2 structure: volatile uint32_t _count (4) + uint32_t _flags (4)
local usem2 = memory.alloc(256)
memory.write_dword(usem2, 1)     -- _count = 1 (available)
memory.write_dword(usem2 + 4, 0) -- _flags = 0

-- Wake (post)
local sem_ok = 0
for i = 1, 100 do
    memory.write_dword(usem2, 0) -- count=0
    local ok = pcall(function()
        syscall.sc_umtx_op(usem2, UMTX_OP_SEM2_WAKE, 0, 0, 0, 0)
    end)
    if ok then sem_ok = sem_ok + 1 end
end
log("  100 SEM2_WAKE: " .. sem_ok .. " ok")

-- ============================================================
-- STRESS 6: NWAKE_PRIVATE (wake N addresses at once)
-- The kernel iterates a userspace array of pointers.
-- Boundary testing: what if the array is huge or misaligned?
-- ============================================================
log("")
log("--- STRESS 6: NWAKE_PRIVATE ---")

-- Normal: array of 4 addresses to wake
local wake_array = memory.alloc(256)
local addr1 = memory.alloc(16)
local addr2 = memory.alloc(16)
local addr3 = memory.alloc(16)
local addr4 = memory.alloc(16)
memory.write_qword(wake_array, addr1)
memory.write_qword(wake_array + 8, addr2)
memory.write_qword(wake_array + 16, addr3)
memory.write_qword(wake_array + 24, addr4)

local nw_ok, nw_err = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 4, 0, 0, 0)
end)
log("  nwake 4 addrs: " .. (nw_ok and "OK" or tostring(nw_err):sub(1,40)))

-- Large count (kernel reads count*8 bytes from userspace)
local nw2_ok, nw2_err = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1000, 0, 0, 0)
end)
log("  nwake 1000 count: " .. (nw2_ok and "OK(!)" or tostring(nw2_err):sub(1,40)))

-- Zero count
local nw3_ok = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 0, 0, 0, 0)
end)
log("  nwake 0 count: " .. (nw3_ok and "OK" or "FAIL"))

-- Huge count (integer overflow probe)
local nw4_ok, nw4_err = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 0x7FFFFFFF, 0, 0, 0)
end)
log("  nwake INT_MAX: " .. (nw4_ok and "OK(!)" or tostring(nw4_err):sub(1,40)))

-- ============================================================
-- STRESS 7: CV (condition variable) signal without waiters
-- ============================================================
log("")
log("--- STRESS 7: CV signal/broadcast ---")

local ucond = memory.alloc(256)
memory.write_dword(ucond, 0) -- c_has_waiters
memory.write_dword(ucond + 4, 0) -- c_flags
memory.write_dword(ucond + 8, 0) -- c_clockid

local cv_sig_ok = 0
local cv_bcast_ok = 0
for i = 1, 100 do
    local ok1 = pcall(function()
        syscall.sc_umtx_op(ucond, UMTX_OP_CV_SIGNAL, 0, 0, 0, 0)
    end)
    local ok2 = pcall(function()
        syscall.sc_umtx_op(ucond, UMTX_OP_CV_BROADCAST, 0, 0, 0, 0)
    end)
    if ok1 then cv_sig_ok = cv_sig_ok + 1 end
    if ok2 then cv_bcast_ok = cv_bcast_ok + 1 end
end
log("  100 rounds: signal=" .. cv_sig_ok .. " broadcast=" .. cv_bcast_ok)

log("")
log("=== UMTX STRESS DONE ===")
return table.concat(out, "\n")
