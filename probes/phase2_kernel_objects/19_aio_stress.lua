-- 14.10 Recon Probe 19: AIO syscall stress test
-- The Lapse exploit used aio_multi_wait race with kqueue to trigger UAF
-- CVE-2024-43102: race between aio completion and kqueue event delivery
-- Single-threaded approach: submit many AIOs on pipes, then cancel/wait
-- interleaved to stress the kernel's AIO completion + cleanup paths
-- SAFE: uses pipes (no external I/O), careful with argument validation

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO STRESS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_pipe = 42,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_aio_read = 255,
    sc_aio_return = 314,
    sc_aio_error = 315,
    sc_aio_cancel = 316,
    sc_aio_suspend = 315,  -- actually 341 on FreeBSD
    sc_aio_waitcomplete = 359,
    sc_aio_multi_wait = 587,   -- PS5 specific
    sc_aio_multi_cancel = 588, -- PS5 specific
    sc_socket = 97,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_mmap = 477,
})

-- ============================================================
-- PART 1: Create pipe pairs for AIO targets
-- ============================================================
log("")
log("--- PART 1: setup pipes ---")

local pipes = {}
local NPIPES = 20

for i = 1, NPIPES do
    local fds = memory.alloc(8)
    local ok = pcall(function() syscall.sc_pipe(fds) end)
    if ok then
        local rfd = memory.read_dword(fds):tonumber()
        local wfd = memory.read_dword(fds + 4):tonumber()
        pipes[#pipes + 1] = {rfd = rfd, wfd = wfd}
    end
end
log("  created " .. #pipes .. "/" .. NPIPES .. " pipe pairs")

if #pipes < 2 then
    log("FATAL: not enough pipes")
    return table.concat(out, "\n")
end

-- Write some data into each pipe so aio_read has something to complete on
for i, p in ipairs(pipes) do
    local wbuf = memory.alloc(64)
    for j = 0, 63 do
        memory.write_byte(wbuf + j, (i * 7 + j) % 256)
    end
    pcall(function() syscall.sc_write(p.wfd, wbuf, 64) end)
end
log("  wrote 64 bytes into each pipe")

-- ============================================================
-- PART 2: Test basic aio_read on a pipe
-- struct aiocb: fd(4) + pad(4) + offset(8) + buf(8) + nbytes(8)
--              + _1(4) + _2(4) + opcode(4) + reqprio(4) + _aiocb_private(?)
-- FreeBSD struct aiocb is ~168 bytes
-- ============================================================
log("")
log("--- PART 2: basic aio_read ---")

local AIOCB_SIZE = 256
local aiocb = memory.alloc(AIOCB_SIZE)
local readbuf = memory.alloc(4096)

-- Zero the aiocb
for i = 0, AIOCB_SIZE - 1, 8 do
    memory.write_qword(aiocb + i, 0)
end

-- Fill aiocb for pipe read
-- FreeBSD struct aiocb layout:
-- +0:  aio_fildes (int)
-- +8:  aio_offset (off_t, 8 bytes)
-- +16: aio_buf (volatile void*, 8 bytes)
-- +24: aio_nbytes (size_t, 8 bytes)
-- +32: aio_sigevent (struct sigevent, ~32 bytes)
-- +72: aio_lio_opcode (int)
-- +76: aio_reqprio (int)
-- +80: _aiocb_private (struct __aiocb_private, ~88 bytes)

memory.write_dword(aiocb, pipes[1].rfd)       -- aio_fildes
memory.write_qword(aiocb + 8, 0)              -- aio_offset
memory.write_qword(aiocb + 16, readbuf)       -- aio_buf
memory.write_qword(aiocb + 24, 64)            -- aio_nbytes

local aio_ok, aio_err = pcall(function()
    return syscall.sc_aio_read(aiocb)
end)
log("  aio_read: " .. (aio_ok and "OK rv=" .. aio_err:tonumber() or "ERR: " .. tostring(aio_err):sub(1, 40)))

-- Check aio_error
if aio_ok then
    local aerr_ok, aerr_ret = pcall(function()
        return syscall.sc_aio_error(aiocb)
    end)
    if aerr_ok then
        log("  aio_error: " .. aerr_ret:tonumber())
    end

    -- Get return value
    local aret_ok, aret_ret = pcall(function()
        return syscall.sc_aio_return(aiocb)
    end)
    if aret_ok then
        log("  aio_return: " .. aret_ret:tonumber())
        -- Check if data was read
        local b0 = memory.read_byte(readbuf):tonumber()
        local b1 = memory.read_byte(readbuf + 1):tonumber()
        log(string.format("  data: %02x %02x ...", b0, b1))
    end
end

-- ============================================================
-- PART 3: aio_multi_wait — PS5-specific batch AIO wait
-- This is the syscall the Lapse exploit targeted
-- ============================================================
log("")
log("--- PART 3: aio_multi_wait ---")

-- Submit multiple aio_reads
local aiocbs = {}
local aio_bufs = {}
for i = 1, 8 do
    local cb = memory.alloc(AIOCB_SIZE)
    local buf = memory.alloc(128)
    for j = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb + j, 0) end

    local pipe_idx = ((i - 1) % #pipes) + 1
    memory.write_dword(cb, pipes[pipe_idx].rfd)
    memory.write_qword(cb + 8, 0)
    memory.write_qword(cb + 16, buf)
    memory.write_qword(cb + 24, 64)

    local s_ok = pcall(function() syscall.sc_aio_read(cb) end)
    if s_ok then
        aiocbs[#aiocbs + 1] = cb
        aio_bufs[#aio_bufs + 1] = buf
    end
end
log("  submitted " .. #aiocbs .. " aio_reads")

-- Build the array of aiocb pointers for aio_multi_wait
local cb_array = memory.alloc(#aiocbs * 8 + 8)
for i, cb in ipairs(aiocbs) do
    memory.write_qword(cb_array + (i - 1) * 8, cb)
end

-- aio_multi_wait(aiocb_list, nent, timeout_or_flags?)
-- The exact prototype is PS5-specific. Try with just the array and count.
local mw_ok, mw_err = pcall(function()
    return syscall.sc_aio_multi_wait(cb_array, #aiocbs, 0, 0, 0, 0)
end)
log("  aio_multi_wait(" .. #aiocbs .. "): " ..
    (mw_ok and "rv=" .. mw_err:tonumber() or "ERR: " .. tostring(mw_err):sub(1, 40)))

-- Collect results
for i, cb in ipairs(aiocbs) do
    local re_ok, re_ret = pcall(function() return syscall.sc_aio_return(cb) end)
    if re_ok then
        local nbytes = re_ret:tonumber()
        if nbytes > 0 then
            log("    aio[" .. i .. "]: " .. nbytes .. " bytes read")
        end
    end
end

-- ============================================================
-- PART 4: aio_multi_cancel stress
-- Cancel AIOs that may be in-flight or already completed
-- This stresses the kernel's AIO cleanup/refcount path
-- ============================================================
log("")
log("--- PART 4: aio_multi_cancel stress ---")

-- Refill pipes
for i, p in ipairs(pipes) do
    local wbuf = memory.alloc(64)
    for j = 0, 63 do memory.write_byte(wbuf + j, 0x42) end
    pcall(function() syscall.sc_write(p.wfd, wbuf, 64) end)
end

-- Submit a batch, then immediately cancel
local cancel_ok_count = 0
local cancel_err_count = 0

for round = 1, 50 do
    -- Submit
    local cbs = {}
    for i = 1, 4 do
        local cb = memory.alloc(AIOCB_SIZE)
        local buf = memory.alloc(128)
        for j = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb + j, 0) end

        local pidx = ((round * 4 + i) % #pipes) + 1
        memory.write_dword(cb, pipes[pidx].rfd)
        memory.write_qword(cb + 16, buf)
        memory.write_qword(cb + 24, 32)

        pcall(function() syscall.sc_aio_read(cb) end)
        cbs[#cbs + 1] = cb
    end

    -- Build cancel array
    local cancel_arr = memory.alloc(#cbs * 8)
    for i, cb in ipairs(cbs) do
        memory.write_qword(cancel_arr + (i - 1) * 8, cb)
    end

    -- Cancel
    local mc_ok, mc_ret = pcall(function()
        return syscall.sc_aio_multi_cancel(cancel_arr, #cbs, 0, 0, 0, 0)
    end)
    if mc_ok then
        cancel_ok_count = cancel_ok_count + 1
    else
        cancel_err_count = cancel_err_count + 1
    end

    -- Also try aio_return on cancelled AIOs (double-free probe)
    for _, cb in ipairs(cbs) do
        pcall(function() syscall.sc_aio_return(cb) end)
    end

    -- Refill a pipe if needed
    if round % 5 == 0 then
        local pidx = (round % #pipes) + 1
        local wb = memory.alloc(64)
        for j = 0, 63 do memory.write_byte(wb + j, 0x43) end
        pcall(function() syscall.sc_write(pipes[pidx].wfd, wb, 64) end)
    end
end

log("  50 rounds: cancel_ok=" .. cancel_ok_count .. " cancel_err=" .. cancel_err_count)

-- ============================================================
-- PART 5: Submit-wait-cancel interleave (Lapse-like pattern)
-- The original bug: aio completes and delivers kqueue event
-- while another thread cancels it — refcount goes to -1 -> UAF
-- Single-threaded approximation: submit, partial wait, cancel
-- ============================================================
log("")
log("--- PART 5: submit-wait-cancel interleave ---")

local swc_ok = 0
local swc_err = 0

for round = 1, 100 do
    -- Submit 2 aio_reads on different pipes
    local cb1 = memory.alloc(AIOCB_SIZE)
    local cb2 = memory.alloc(AIOCB_SIZE)
    local buf1 = memory.alloc(128)
    local buf2 = memory.alloc(128)

    for j = 0, AIOCB_SIZE - 1, 8 do
        memory.write_qword(cb1 + j, 0)
        memory.write_qword(cb2 + j, 0)
    end

    local p1 = pipes[(round % #pipes) + 1]
    local p2 = pipes[((round + 1) % #pipes) + 1]

    memory.write_dword(cb1, p1.rfd)
    memory.write_qword(cb1 + 16, buf1)
    memory.write_qword(cb1 + 24, 32)

    memory.write_dword(cb2, p2.rfd)
    memory.write_qword(cb2 + 16, buf2)
    memory.write_qword(cb2 + 24, 32)

    pcall(function() syscall.sc_aio_read(cb1) end)
    pcall(function() syscall.sc_aio_read(cb2) end)

    -- Wait for cb1 only (with timeout 0 = non-blocking)
    local wait_arr = memory.alloc(16)
    memory.write_qword(wait_arr, cb1)

    local ts = memory.alloc(16)
    memory.write_qword(ts, 0)
    memory.write_qword(ts + 8, 1) -- 1 nanosecond timeout

    pcall(function()
        syscall.sc_aio_multi_wait(wait_arr, 1, ts, 0, 0, 0)
    end)

    -- Immediately cancel cb2 (might be completed or in-flight)
    local cancel_arr2 = memory.alloc(8)
    memory.write_qword(cancel_arr2, cb2)
    pcall(function()
        syscall.sc_aio_multi_cancel(cancel_arr2, 1, 0, 0, 0, 0)
    end)

    -- Collect cb1 result
    pcall(function() syscall.sc_aio_return(cb1) end)

    -- Double-collect cb2 (cancelled — should return ECANCELED or error)
    local d_ok, d_ret = pcall(function()
        return syscall.sc_aio_return(cb2)
    end)
    if d_ok then
        local drv = d_ret:tonumber()
        if drv >= 0 then
            swc_ok = swc_ok + 1
        else
            swc_err = swc_err + 1
        end
    else
        swc_err = swc_err + 1
    end

    -- Try aio_return AGAIN on cb2 (should fail — already collected)
    -- If this succeeds, it's a double-free indicator
    local dd_ok, dd_ret = pcall(function()
        return syscall.sc_aio_return(cb2)
    end)
    if dd_ok and dd_ret:tonumber() >= 0 then
        log("  *** DOUBLE aio_return succeeded at round " .. round .. "! ***")
    end

    -- Refill pipes periodically
    if round % 10 == 0 then
        for _, p in ipairs(pipes) do
            local wb = memory.alloc(64)
            for j = 0, 63 do memory.write_byte(wb + j, 0x44) end
            pcall(function() syscall.sc_write(p.wfd, wb, 64) end)
        end
    end
end

log("  100 rounds: ok=" .. swc_ok .. " err=" .. swc_err)

-- ============================================================
-- PART 6: aio_cancel on already-completed AIO
-- If the kernel doesn't check completion state before cancelling,
-- it might free a buffer that's already been returned to the caller
-- ============================================================
log("")
log("--- PART 6: cancel after completion ---")

local cac_double = 0
for round = 1, 100 do
    local cb = memory.alloc(AIOCB_SIZE)
    local buf = memory.alloc(128)
    for j = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb + j, 0) end

    local pidx = (round % #pipes) + 1
    memory.write_dword(cb, pipes[pidx].rfd)
    memory.write_qword(cb + 16, buf)
    memory.write_qword(cb + 24, 16)

    -- Submit
    pcall(function() syscall.sc_aio_read(cb) end)

    -- Wait for completion (data is in the pipe, should complete fast)
    local w_arr = memory.alloc(8)
    memory.write_qword(w_arr, cb)
    pcall(function() syscall.sc_aio_multi_wait(w_arr, 1, 0, 0, 0, 0) end)

    -- Collect the result
    pcall(function() syscall.sc_aio_return(cb) end)

    -- NOW cancel it (already completed and collected)
    local c_arr = memory.alloc(8)
    memory.write_qword(c_arr, cb)
    local c_ok, c_ret = pcall(function()
        return syscall.sc_aio_multi_cancel(c_arr, 1, 0, 0, 0, 0)
    end)

    -- And try to collect AGAIN
    local r2_ok, r2_ret = pcall(function()
        return syscall.sc_aio_return(cb)
    end)
    if r2_ok and r2_ret:tonumber() >= 0 then
        cac_double = cac_double + 1
    end

    -- Refill
    if round % 10 == 0 then
        local wb = memory.alloc(64)
        for j = 0, 63 do memory.write_byte(wb + j, 0x44) end
        pcall(function() syscall.sc_write(pipes[pidx].wfd, wb, 64) end)
    end
end

log("  100 rounds, double-return after cancel: " .. cac_double)
if cac_double > 0 then
    log("  *** POTENTIAL UAF: aio_return succeeded after cancel+return ***")
end

-- ============================================================
-- PART 7: socketpair AIO (different code path than pipes)
-- ============================================================
log("")
log("--- PART 7: socketpair AIO ---")

local sp_fds = memory.alloc(8)
local sp_ok = pcall(function()
    syscall.sc_socketpair(1, 1, 0, sp_fds) -- AF_UNIX, SOCK_STREAM
end)

if sp_ok then
    local sp0 = memory.read_dword(sp_fds):tonumber()
    local sp1 = memory.read_dword(sp_fds + 4):tonumber()
    log("  socketpair: " .. sp0 .. ", " .. sp1)

    -- Write data
    local spw = memory.alloc(64)
    for j = 0, 63 do memory.write_byte(spw + j, 0x55) end
    pcall(function() syscall.sc_write(sp1, spw, 64) end)

    -- AIO read from socket
    local spcb = memory.alloc(AIOCB_SIZE)
    local spbuf = memory.alloc(128)
    for j = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(spcb + j, 0) end

    memory.write_dword(spcb, sp0)
    memory.write_qword(spcb + 16, spbuf)
    memory.write_qword(spcb + 24, 64)

    local sp_aio_ok, sp_aio_err = pcall(function()
        return syscall.sc_aio_read(spcb)
    end)
    log("  aio_read on socket: " ..
        (sp_aio_ok and "rv=" .. sp_aio_err:tonumber() or "ERR: " .. tostring(sp_aio_err):sub(1, 40)))

    if sp_aio_ok then
        -- Wait
        local sp_warr = memory.alloc(8)
        memory.write_qword(sp_warr, spcb)
        pcall(function() syscall.sc_aio_multi_wait(sp_warr, 1, 0, 0, 0, 0) end)

        -- Return
        local sp_ret_ok, sp_ret_val = pcall(function()
            return syscall.sc_aio_return(spcb)
        end)
        if sp_ret_ok then
            log("  aio_return: " .. sp_ret_val:tonumber())
            if sp_ret_val:tonumber() > 0 then
                local b0 = memory.read_byte(spbuf):tonumber()
                log(string.format("  data: 0x%02x (expected 0x55)", b0))
            end
        end
    end

    pcall(function() syscall.sc_close(sp0) end)
    pcall(function() syscall.sc_close(sp1) end)
else
    log("  socketpair failed")
end

-- Cleanup
for _, p in ipairs(pipes) do
    pcall(function() syscall.sc_close(p.rfd) end)
    pcall(function() syscall.sc_close(p.wfd) end)
end

log("")
log("=== AIO STRESS DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
