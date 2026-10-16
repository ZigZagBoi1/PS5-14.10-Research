-- 14.10 Recon Probe 19e: AIO without passing zeros
-- CRITICAL: Passing 0/NULL to syscalls crashes the Lua loader!
-- Must pass valid pointers for ALL arguments

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO NOCRASH ===")
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
    sc_aio_multi_delete = 589,
})

-- Create socketpair
local sp = memory.alloc(8)
syscall.sc_socketpair(1, 1, 0, sp)
local fd0 = memory.read_dword(sp):tonumber()
local fd1 = memory.read_dword(sp + 4):tonumber()
log("socketpair: " .. fd0 .. ", " .. fd1)

-- Write data
local wbuf = memory.alloc(64)
for i = 0, 63 do memory.write_byte(wbuf + i, 0x41) end
syscall.sc_write(fd1, wbuf, 32)
log("wrote 32 bytes")

-- ============================================================
-- PART 1: aio_error and aio_return with valid pointer
-- These take just (struct aiocb*) — single argument
-- ============================================================
log("")
log("--- PART 1: aio_error / aio_return (single ptr) ---")

local cb1 = memory.alloc(512)
for i = 0, 511, 8 do memory.write_qword(cb1 + i, 0) end

local ae_ok, ae_ret = pcall(function() return syscall.sc_aio_error(cb1) end)
log("  aio_error(zeroed_aiocb): " ..
    (ae_ok and "rv=" .. ae_ret:tonumber() or "ERR: " .. tostring(ae_ret):sub(1, 50)))

local ar_ok, ar_ret = pcall(function() return syscall.sc_aio_return(cb1) end)
log("  aio_return(zeroed_aiocb): " ..
    (ar_ok and "rv=" .. ar_ret:tonumber() or "ERR: " .. tostring(ar_ret):sub(1, 50)))

-- ============================================================
-- PART 2: aio_cancel with valid aiocb pointer (not NULL)
-- aio_cancel(int fd, struct aiocb *aiocbp)
-- Pass our zeroed aiocb as second arg instead of 0
-- ============================================================
log("")
log("--- PART 2: aio_cancel(fd, valid_ptr) ---")

local ac_ok, ac_ret = pcall(function()
    return syscall.sc_aio_cancel(fd0, cb1)
end)
log("  aio_cancel(fd0, cb1): " ..
    (ac_ok and "rv=" .. ac_ret:tonumber() or "ERR: " .. tostring(ac_ret):sub(1, 50)))

-- ============================================================
-- PART 3: aio_read with valid struct
-- Key: EVERY field must be valid, no zeros for pointers
-- ============================================================
log("")
log("--- PART 3: aio_read ---")

local aiocb = memory.alloc(512)
local rbuf = memory.alloc(256)
for i = 0, 511, 8 do memory.write_qword(aiocb + i, 0) end
for i = 0, 255 do memory.write_byte(rbuf + i, 0xDE) end

-- Fill struct aiocb — standard FreeBSD amd64 layout:
-- +0:  int aio_fildes (4)
-- +4:  padding (4)
-- +8:  off_t aio_offset (8)
-- +16: volatile void* aio_buf (8)
-- +24: size_t aio_nbytes (8)
-- +32: int __spare__[2] (8) [reserved, must be 0]
-- +40: struct sigevent aio_sigevent (80 bytes on FreeBSD)
--   +40: int sigev_notify = 0 (SIGEV_NONE)
--   +44: int sigev_signo = 0
--   +48: union sigval = 0
--   +56..+119: union (pad)
-- +120: int aio_lio_opcode = 0 (LIO_READ)
-- +124: int aio_reqprio = 0
-- +128: struct __aiocb_private _aiocb_private (40 bytes)
--   +128: long status = 0
--   +136: long error = 0
--   +144: void* kernelinfo = 0
-- Total: ~168 bytes

memory.write_dword(aiocb + 0, fd0)      -- aio_fildes
memory.write_qword(aiocb + 8, 0)        -- aio_offset = 0 (ignored for sockets)
memory.write_qword(aiocb + 16, rbuf)    -- aio_buf = valid buffer
memory.write_qword(aiocb + 24, 16)      -- aio_nbytes = 16
-- sigevent at +40: SIGEV_NONE=0, already zero

log("  aiocb at " .. string.format("0x%x", aiocb))
log("  rbuf at " .. string.format("0x%x", rbuf))
log("  fd=" .. fd0)

local ar2_ok, ar2_ret = pcall(function()
    return syscall.sc_aio_read(aiocb)
end)
log("  aio_read: " ..
    (ar2_ok and "rv=" .. ar2_ret:tonumber() or "CRASH: " .. tostring(ar2_ret):sub(1, 50)))

if ar2_ok then
    log("  *** AIO_READ WORKS! ***")

    -- Check error state
    local e_ok, e_ret = pcall(function() return syscall.sc_aio_error(aiocb) end)
    if e_ok then log("  aio_error=" .. e_ret:tonumber()) end

    -- Get return value
    local r_ok, r_ret = pcall(function() return syscall.sc_aio_return(aiocb) end)
    if r_ok then
        log("  aio_return=" .. r_ret:tonumber())
        if r_ret:tonumber() > 0 then
            local b0 = memory.read_byte(rbuf):tonumber()
            local b1 = memory.read_byte(rbuf + 1):tonumber()
            log(string.format("  data: 0x%02x 0x%02x", b0, b1))
        end
    end
end

-- ============================================================
-- PART 4: Check alive and dump aiocb after aio_read
-- ============================================================
log("")
log("--- PART 4: post-state ---")

local alive_ok = pcall(function() syscall.sc_getpid() end)
log("  still alive: " .. tostring(alive_ok))

-- Dump the aiocb to see what kernel wrote back
if alive_ok then
    log("  aiocb dump:")
    for i = 0, 168 - 1, 8 do
        local lo = memory.read_dword(aiocb + i):tonumber()
        local hi = memory.read_dword(aiocb + i + 4):tonumber()
        if lo ~= 0 or hi ~= 0 then
            log(string.format("    +%3d: 0x%08x%08x", i, hi, lo))
        end
    end
end

-- Cleanup
pcall(function() syscall.sc_close(fd0) end)
pcall(function() syscall.sc_close(fd1) end)

log("")
log("=== AIO NOCRASH DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
