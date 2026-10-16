-- 14.10 Recon Probe 19f: Just try aio_read, skip dangerous calls
-- 19e proved: aio_error works, aio_return on unsubmitted aiocb crashes
-- This probe: go straight to aio_read, only call aio_return AFTER submit

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO READ ONLY ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_close = 6,
    sc_write = 4,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_aio_read = 255,
    sc_aio_error = 315,
    sc_aio_return = 314,
    sc_aio_cancel = 316,
    sc_aio_multi_wait = 587,
    sc_aio_multi_cancel = 588,
})

-- Create socketpair
local sp = memory.alloc(8)
syscall.sc_socketpair(1, 1, 0, sp)
local fd0 = memory.read_dword(sp):tonumber()
local fd1 = memory.read_dword(sp + 4):tonumber()
log("socketpair: " .. fd0 .. ", " .. fd1)

-- Write data so aio_read can complete immediately
local wbuf = memory.alloc(64)
for i = 0, 63 do memory.write_byte(wbuf + i, 0x41 + (i % 26)) end
syscall.sc_write(fd1, wbuf, 32)
log("wrote 32 bytes")

-- ============================================================
-- PART 1: aio_read — THE test
-- ============================================================
log("")
log("--- PART 1: aio_read ---")

local aiocb = memory.alloc(512)
local rbuf = memory.alloc(256)

-- Zero everything
for i = 0, 511, 8 do memory.write_qword(aiocb + i, 0) end
for i = 0, 255 do memory.write_byte(rbuf + i, 0xDE) end

-- FreeBSD struct aiocb (amd64)
memory.write_dword(aiocb + 0, fd0)      -- aio_fildes
memory.write_qword(aiocb + 8, 0)        -- aio_offset
memory.write_qword(aiocb + 16, rbuf)    -- aio_buf
memory.write_qword(aiocb + 24, 16)      -- aio_nbytes
-- +40: sigev_notify = SIGEV_NONE = 0 (already zero)

local ar_ok, ar_ret = pcall(function()
    return syscall.sc_aio_read(aiocb)
end)

if ar_ok then
    local rv = ar_ret:tonumber()
    log("  aio_read: rv=" .. rv)

    -- EINPROGRESS = rv of 0 means submitted
    -- rv of -1 means error

    -- Check error
    local e_ok, e_ret = pcall(function() return syscall.sc_aio_error(aiocb) end)
    if e_ok then
        local err = e_ret:tonumber()
        log("  aio_error=" .. err)
        -- EINPROGRESS=36 means still running
        -- 0 means completed
        -- other = actual error

        if err == 0 or err == 36 then
            -- Try aio_return (safe because we submitted)
            local r_ok, r_ret2 = pcall(function() return syscall.sc_aio_return(aiocb) end)
            if r_ok then
                log("  aio_return=" .. r_ret2:tonumber())
                if r_ret2:tonumber() > 0 then
                    local b0 = memory.read_byte(rbuf):tonumber()
                    local b1 = memory.read_byte(rbuf + 1):tonumber()
                    log(string.format("  data: 0x%02x 0x%02x (expect 0x41 0x42)", b0, b1))
                end
            else
                log("  aio_return ERR: " .. tostring(r_ret2):sub(1, 50))
            end
        end
    else
        log("  aio_error ERR: " .. tostring(e_ret):sub(1, 50))
    end

    -- ============================================================
    -- PART 2: Stress test — submit and cancel rapidly
    -- ============================================================
    log("")
    log("--- PART 2: submit/cancel stress ---")

    local ok_count = 0
    local cancel_count = 0
    local double_count = 0

    for round = 1, 100 do
        -- Refill
        if round % 10 == 1 then
            for i = 1, 10 do
                pcall(function() syscall.sc_write(fd1, wbuf, 16) end)
            end
        end

        local cb = memory.alloc(512)
        local buf = memory.alloc(64)
        for i = 0, 511, 8 do memory.write_qword(cb + i, 0) end

        memory.write_dword(cb, fd0)
        memory.write_qword(cb + 16, buf)
        memory.write_qword(cb + 24, 8)

        local s_ok = pcall(function() syscall.sc_aio_read(cb) end)
        if s_ok then
            ok_count = ok_count + 1

            -- Cancel it
            local c_ok, c_rv = pcall(function() return syscall.sc_aio_cancel(fd0, cb) end)
            if c_ok then cancel_count = cancel_count + 1 end

            -- Collect
            pcall(function() syscall.sc_aio_return(cb) end)

            -- Double collect (UAF indicator)
            local d_ok, d_rv = pcall(function() return syscall.sc_aio_return(cb) end)
            if d_ok and d_rv:tonumber() >= 0 then
                double_count = double_count + 1
            end
        end
    end

    log("  submitted=" .. ok_count .. " cancelled=" .. cancel_count)
    log("  double_return=" .. double_count)
    if double_count > 0 then
        log("  *** POTENTIAL UAF ***")
    end

    -- ============================================================
    -- PART 3: aio_multi_cancel stress
    -- ============================================================
    log("")
    log("--- PART 3: aio_multi_cancel ---")

    -- Refill
    for i = 1, 20 do
        pcall(function() syscall.sc_write(fd1, wbuf, 16) end)
    end

    -- Submit batch
    local batch = {}
    for i = 1, 8 do
        local cb2 = memory.alloc(512)
        local buf2 = memory.alloc(64)
        for j = 0, 511, 8 do memory.write_qword(cb2 + j, 0) end
        memory.write_dword(cb2, fd0)
        memory.write_qword(cb2 + 16, buf2)
        memory.write_qword(cb2 + 24, 8)

        local s2_ok = pcall(function() syscall.sc_aio_read(cb2) end)
        if s2_ok then batch[#batch + 1] = cb2 end
    end
    log("  batch submitted: " .. #batch)

    -- Build ptr array — IMPORTANT: no zeros, valid ptrs only
    local arr = memory.alloc(#batch * 8)
    for i, cb in ipairs(batch) do
        memory.write_qword(arr + (i - 1) * 8, cb)
    end

    -- aio_multi_cancel — unknown prototype, try (array, count, ?, ?, ?, ?)
    -- Use 1 instead of 0 for padding args to avoid NULL crash
    local mc_ok, mc_ret = pcall(function()
        return syscall.sc_aio_multi_cancel(arr, #batch, 1, 1, 1, 1)
    end)
    log("  aio_multi_cancel: " ..
        (mc_ok and "rv=" .. mc_ret:tonumber() or "ERR: " .. tostring(mc_ret):sub(1, 50)))

    -- Collect results
    for i, cb in ipairs(batch) do
        local rr_ok, rr_ret = pcall(function() return syscall.sc_aio_return(cb) end)
        if rr_ok then
            log("    aio[" .. i .. "] return=" .. rr_ret:tonumber())
        end
    end

    -- ============================================================
    -- PART 4: Cancel-after-return (classic UAF pattern)
    -- ============================================================
    log("")
    log("--- PART 4: cancel after return ---")

    local uaf_count = 0
    for round = 1, 50 do
        pcall(function() syscall.sc_write(fd1, wbuf, 16) end)

        local cb3 = memory.alloc(512)
        local buf3 = memory.alloc(64)
        for i = 0, 511, 8 do memory.write_qword(cb3 + i, 0) end
        memory.write_dword(cb3, fd0)
        memory.write_qword(cb3 + 16, buf3)
        memory.write_qword(cb3 + 24, 8)

        -- Submit
        pcall(function() syscall.sc_aio_read(cb3) end)
        -- Wait for completion (data in buffer, should complete fast)
        -- Collect
        pcall(function() syscall.sc_aio_return(cb3) end)
        -- Cancel (already completed and returned)
        pcall(function() syscall.sc_aio_cancel(fd0, cb3) end)
        -- Double return
        local dr_ok, dr_ret = pcall(function() return syscall.sc_aio_return(cb3) end)
        if dr_ok and dr_ret:tonumber() >= 0 then
            uaf_count = uaf_count + 1
        end
    end
    log("  50 rounds, double-return: " .. uaf_count)
    if uaf_count > 0 then
        log("  *** UAF CONFIRMED ***")
    end
else
    log("  aio_read CRASHED: " .. tostring(ar_ret):sub(1, 80))
    log("")
    log("  aio_read crashed — checking if alive...")
    local alive = pcall(function() return syscall.sc_getpid() end)
    log("  alive: " .. tostring(alive))

    if alive then
        -- Dump aiocb to see what changed
        log("  aiocb after crash:")
        for i = 0, 167, 8 do
            local lo = memory.read_dword(aiocb + i):tonumber()
            local hi = memory.read_dword(aiocb + i + 4):tonumber()
            if lo ~= 0 or hi ~= 0 then
                log(string.format("    +%3d: 0x%08x%08x", i, hi, lo))
            end
        end
    end
end

-- Cleanup
pcall(function() syscall.sc_close(fd0) end)
pcall(function() syscall.sc_close(fd1) end)

log("")
log("=== AIO READ ONLY DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
