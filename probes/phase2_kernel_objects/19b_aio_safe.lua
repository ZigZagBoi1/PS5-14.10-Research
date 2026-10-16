-- 14.10 Recon Probe 19b: Safe AIO exploration
-- Probe 19 crashed at aio_read — likely wrong struct aiocb layout
-- This probe: (1) checks which AIO syscalls resolve, (2) tries aio_read
-- with carefully built aiocb, (3) tests aio_cancel with fd-based API

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO SAFE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

-- ============================================================
-- PART 1: Check which AIO syscalls are available
-- ============================================================
log("")
log("--- PART 1: AIO syscall resolution ---")

syscall.resolve({
    sc_pipe = 42,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_socket = 97,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_mmap = 477,
})

-- AIO syscalls - FreeBSD numbers
local aio_nums = {
    {255, "aio_read"},
    {256, "aio_write"},
    {314, "aio_return"},
    {315, "aio_error"},     -- note: some sources say 317
    {316, "aio_cancel"},
    {317, "aio_error_alt"},
    {321, "aio_waitcomplete"},
    {341, "aio_suspend"},
    {359, "aio_waitcomplete2"},
    {587, "aio_multi_wait"},
    {588, "aio_multi_cancel"},
    {589, "aio_multi_delete"},
    {590, "aio_multi_poll"},
}

for _, spec in ipairs(aio_nums) do
    local num = spec[1]
    local name = spec[2]
    local tbl = {}
    tbl["aio_" .. num] = num
    local rok = pcall(function() syscall.resolve(tbl) end)
    log(string.format("  %d %-25s %s", num, name, rok and "OK" or "FAIL"))
end

-- Now resolve the ones we'll use
syscall.resolve({
    sc_aio_read = 255,
    sc_aio_write = 256,
    sc_aio_return = 314,
    sc_aio_error = 315,
    sc_aio_cancel = 316,
    sc_aio_multi_wait = 587,
    sc_aio_multi_cancel = 588,
})

-- ============================================================
-- PART 2: Create a pipe and test basic aio_read
-- Try different aiocb struct layouts
-- ============================================================
log("")
log("--- PART 2: pipe + aiocb layout test ---")

local fds = memory.alloc(8)
syscall.sc_pipe(fds)
local rfd = memory.read_dword(fds):tonumber()
local wfd = memory.read_dword(fds + 4):tonumber()
log("  pipe: rfd=" .. rfd .. " wfd=" .. wfd)

-- Write data so read won't block
local wbuf = memory.alloc(64)
for i = 0, 63 do memory.write_byte(wbuf + i, 0x41 + (i % 26)) end
local wok, wret = pcall(function() return syscall.sc_write(wfd, wbuf, 32) end)
log("  write: " .. (wok and wret:tonumber() or "FAIL"))

-- FreeBSD 13 struct aiocb (from sys/aio.h):
--   int      aio_fildes;     // +0  (4 bytes)
--   // padding to align off_t  // +4  (4 bytes on LP64)
--   off_t    aio_offset;     // +8  (8 bytes)
--   volatile void *aio_buf;  // +16 (8 bytes)
--   size_t   aio_nbytes;     // +24 (8 bytes)
--   int      aio_reqprio;    // +32 (4 bytes)
--   struct sigevent aio_sigevent; // +40 (varies)
--   int      aio_lio_opcode; // after sigevent
--   struct __aiocb_private _aiocb_private;
-- Total ~168 bytes on FreeBSD

-- BUT: on PS5, struct sigevent might be different size
-- Let's try the standard layout first, with large alloc

local AIOCB_SIZE = 256
local aiocb = memory.alloc(AIOCB_SIZE)
local rbuf = memory.alloc(256)

-- Zero everything
for i = 0, AIOCB_SIZE - 1, 8 do
    memory.write_qword(aiocb + i, 0)
end
-- Zero read buffer and fill with marker
for i = 0, 255, 8 do
    memory.write_qword(rbuf + i, 0xDEADDEADDEADDEAD)
end

-- Layout A: standard FreeBSD
log("  trying layout A (FreeBSD standard)...")
memory.write_dword(aiocb + 0, rfd)         -- aio_fildes
memory.write_qword(aiocb + 8, 0)           -- aio_offset
memory.write_qword(aiocb + 16, rbuf)       -- aio_buf
memory.write_qword(aiocb + 24, 32)         -- aio_nbytes

local aio_ok, aio_ret = pcall(function()
    return syscall.sc_aio_read(aiocb)
end)
if aio_ok then
    log("  aio_read rv=" .. aio_ret:tonumber())

    -- Check if data arrived
    local b0 = memory.read_byte(rbuf):tonumber()
    log(string.format("  rbuf[0]=0x%02x (expect 0x41 or 0xDE)", b0))

    -- Check aio_error
    local aerr_ok, aerr = pcall(function() return syscall.sc_aio_error(aiocb) end)
    if aerr_ok then log("  aio_error=" .. aerr:tonumber()) end

    -- Check aio_return
    local aret_ok, aret = pcall(function() return syscall.sc_aio_return(aiocb) end)
    if aret_ok then log("  aio_return=" .. aret:tonumber()) end
else
    log("  aio_read CRASHED: " .. tostring(aio_ret):sub(1, 60))
end

-- ============================================================
-- PART 3: If layout A failed, try aio_cancel (fd-only form)
-- aio_cancel(fd, NULL) cancels all AIOs on fd
-- This doesn't need an aiocb struct at all
-- ============================================================
log("")
log("--- PART 3: aio_cancel fd-only ---")

-- Create another pipe
local fds2 = memory.alloc(8)
syscall.sc_pipe(fds2)
local rfd2 = memory.read_dword(fds2):tonumber()
local wfd2 = memory.read_dword(fds2 + 4):tonumber()

-- aio_cancel(fd, NULL) — cancel all on this fd
-- Should return AIO_ALLDONE(1), AIO_CANCELED(2), AIO_NOTCANCELED(3), or -1
local ac_ok, ac_ret = pcall(function()
    return syscall.sc_aio_cancel(rfd2, 0)
end)
log("  aio_cancel(rfd, NULL): " ..
    (ac_ok and "rv=" .. ac_ret:tonumber() or "ERR: " .. tostring(ac_ret):sub(1, 40)))

-- ============================================================
-- PART 4: aio_multi_wait with NULL/empty — check prototype
-- ============================================================
log("")
log("--- PART 4: aio_multi_wait prototype test ---")

-- Try with a valid but empty array
local empty_arr = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(empty_arr + i, 0) end

-- Try: aio_multi_wait(array, 0, ...) with various arg patterns
local mw_tests = {
    {"(arr,0,0,0,0,0)", function() return syscall.sc_aio_multi_wait(empty_arr, 0, 0, 0, 0, 0) end},
    {"(arr,0,0)", function() return syscall.sc_aio_multi_wait(empty_arr, 0, 0) end},
    {"(0,0,0,0,0,0)", function() return syscall.sc_aio_multi_wait(0, 0, 0, 0, 0, 0) end},
}

for _, t in ipairs(mw_tests) do
    local label = t[1]
    local fn = t[2]
    local ok2, ret2 = pcall(fn)
    log("  aio_multi_wait" .. label .. ": " ..
        (ok2 and "rv=" .. ret2:tonumber() or "ERR: " .. tostring(ret2):sub(1, 40)))
end

-- ============================================================
-- PART 5: aio_multi_cancel prototype test
-- ============================================================
log("")
log("--- PART 5: aio_multi_cancel prototype test ---")

local mc_tests = {
    {"(arr,0,0,0,0,0)", function() return syscall.sc_aio_multi_cancel(empty_arr, 0, 0, 0, 0, 0) end},
    {"(0,0,0,0,0,0)", function() return syscall.sc_aio_multi_cancel(0, 0, 0, 0, 0, 0) end},
}

for _, t in ipairs(mc_tests) do
    local label = t[1]
    local fn = t[2]
    local ok3, ret3 = pcall(fn)
    log("  aio_multi_cancel" .. label .. ": " ..
        (ok3 and "rv=" .. ret3:tonumber() or "ERR: " .. tostring(ret3):sub(1, 40)))
end

-- ============================================================
-- PART 6: If aio_read worked, stress test it
-- ============================================================
log("")
log("--- PART 6: aio stress (if read works) ---")

if aio_ok then
    log("  aio_read worked, running stress...")

    -- Write more data
    for round = 1, 10 do
        pcall(function() syscall.sc_write(wfd, wbuf, 32) end)
    end

    local ok_count = 0
    local err_count = 0

    for round = 1, 50 do
        -- Fresh aiocb each round
        local cb = memory.alloc(AIOCB_SIZE)
        local buf = memory.alloc(64)
        for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb + i, 0) end

        memory.write_dword(cb + 0, rfd)
        memory.write_qword(cb + 16, buf)
        memory.write_qword(cb + 24, 16)

        local s_ok = pcall(function() syscall.sc_aio_read(cb) end)
        if s_ok then
            -- Try immediate cancel
            local c_ok = pcall(function() syscall.sc_aio_cancel(rfd, cb) end)
            -- Collect result regardless
            local r_ok, r_ret = pcall(function() return syscall.sc_aio_return(cb) end)
            if r_ok then
                ok_count = ok_count + 1
            else
                err_count = err_count + 1
            end

            -- Double-collect (UAF test)
            local d_ok, d_ret = pcall(function() return syscall.sc_aio_return(cb) end)
            if d_ok and d_ret:tonumber() >= 0 then
                log("  *** DOUBLE aio_return OK at round " .. round .. "! rv=" .. d_ret:tonumber())
            end
        end

        -- Refill pipe every 5 rounds
        if round % 5 == 0 then
            pcall(function() syscall.sc_write(wfd, wbuf, 32) end)
        end
    end

    log("  50 rounds: ok=" .. ok_count .. " err=" .. err_count)

    -- Now test: submit, wait, cancel-after-return
    log("")
    log("  cancel-after-return test (100 rounds)...")
    local cac = 0
    for round = 1, 100 do
        pcall(function() syscall.sc_write(wfd, wbuf, 16) end)

        local cb2 = memory.alloc(AIOCB_SIZE)
        local buf2 = memory.alloc(64)
        for i = 0, AIOCB_SIZE - 1, 8 do memory.write_qword(cb2 + i, 0) end
        memory.write_dword(cb2, rfd)
        memory.write_qword(cb2 + 16, buf2)
        memory.write_qword(cb2 + 24, 16)

        pcall(function() syscall.sc_aio_read(cb2) end)
        pcall(function() syscall.sc_aio_return(cb2) end)
        -- Cancel after already collected
        pcall(function() syscall.sc_aio_cancel(rfd, cb2) end)
        -- Double return
        local dd_ok, dd_ret = pcall(function() return syscall.sc_aio_return(cb2) end)
        if dd_ok and dd_ret:tonumber() >= 0 then
            cac = cac + 1
        end
    end
    log("  double-return after cancel: " .. cac)
    if cac > 0 then
        log("  *** POTENTIAL UAF ***")
    end
else
    log("  aio_read failed, skipping stress")
end

-- Cleanup
pcall(function() syscall.sc_close(rfd) end)
pcall(function() syscall.sc_close(wfd) end)
pcall(function() syscall.sc_close(rfd2) end)
pcall(function() syscall.sc_close(wfd2) end)

log("")
log("=== AIO SAFE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
