-- 14.10 Recon Probe 19d: Minimal AIO test
-- aio_read crashes with standard aiocb layout
-- Hypotheses:
-- 1. PS5 aiocb is a different size/layout (Sony modifications)
-- 2. aio_read needs specific sigevent setup (SIGEV_NONE=0 should work)
-- 3. The _aiocb_private field needs initialization
-- Test: try different struct sizes and field offsets

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO MINIMAL ===")
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
-- PART 1: Test aio_cancel with fd-only (no aiocb needed)
-- aio_cancel(fd, NULL) — should be safe
-- ============================================================
log("")
log("--- PART 1: aio_cancel(fd, NULL) ---")

local ac_ok, ac_ret = pcall(function()
    return syscall.sc_aio_cancel(fd0, 0)
end)
log("  aio_cancel(fd0, 0): " ..
    (ac_ok and "rv=" .. ac_ret:tonumber() or "CRASH"))

-- ============================================================
-- PART 2: Try different aiocb sizes
-- The crash might be because aio_read does copyin() of a
-- specific struct size and our buffer alignment is wrong
-- ============================================================
log("")
log("--- PART 2: aiocb layout probing ---")

-- FreeBSD struct sigevent is 32 bytes on amd64:
--   int sigev_notify;        // +0 (4)
--   int sigev_signo;         // +4 (4)
--   union sigval sigev_value; // +8 (8, pointer-sized)
--   union {                  // +16
--     int _threadid;
--     struct { ... } _kevent_flags;
--     long __spare__[8];     // 64 bytes
--   }
-- So sigevent is actually 80 bytes on FreeBSD! Not 32.
--
-- struct aiocb layout on FreeBSD amd64:
--   +0:  int aio_fildes (4)
--   +4:  padding (4)
--   +8:  off_t aio_offset (8)
--   +16: volatile void* aio_buf (8)
--   +24: size_t aio_nbytes (8)
--   +32: int __spare__[2] (8)  -- or aio_reqprio + padding
--   +40: struct sigevent aio_sigevent (80)
--   +120: int aio_lio_opcode (4)
--   +124: int aio_reqprio (4)  -- might be here instead
--   +128: struct __aiocb_private (40?)
--   Total ~168 bytes

-- Let me try with a huge buffer and carefully set SIGEV_NONE
local SIZES = {168, 176, 192, 200, 208, 224, 256, 320, 512}

for _, sz in ipairs(SIZES) do
    local cb = memory.alloc(sz + 64) -- extra padding
    local rbuf = memory.alloc(256)

    -- Zero EVERYTHING including padding
    for i = 0, sz + 63, 8 do
        memory.write_qword(cb + i, 0)
    end

    -- Standard FreeBSD layout
    memory.write_dword(cb + 0, fd0)         -- aio_fildes
    -- +4: padding = 0
    memory.write_qword(cb + 8, 0)           -- aio_offset = 0
    memory.write_qword(cb + 16, rbuf)       -- aio_buf
    memory.write_qword(cb + 24, 16)         -- aio_nbytes
    -- +32: spare/reqprio = 0
    -- +40: sigevent.sigev_notify = SIGEV_NONE (0)
    memory.write_dword(cb + 40, 0)          -- SIGEV_NONE

    local ok, ret = pcall(function()
        return syscall.sc_aio_read(cb)
    end)

    if ok then
        log(string.format("  size=%d: OK rv=%d", sz, ret:tonumber()))
        -- Check if read completed
        local b0 = memory.read_byte(rbuf):tonumber()
        log(string.format("    data[0]=0x%02x", b0))
        pcall(function() syscall.sc_aio_return(cb) end)
        break
    else
        log(string.format("  size=%d: CRASH — %s", sz, tostring(ret):sub(1, 40)))
        -- If it crashed, the loader might be dead
        -- Try to detect if we're still alive
        local alive = pcall(function() syscall.sc_getpid() end)
        if not alive then
            log("  LOADER DEAD")
            break
        end
    end
end

-- ============================================================
-- PART 3: Alternative — try with aio_buf as offset in the
-- aiocb itself (self-referential) to avoid bad pointer
-- ============================================================
log("")
log("--- PART 3: self-referential aiocb ---")

local cb3 = memory.alloc(512)
for i = 0, 511, 8 do memory.write_qword(cb3 + i, 0) end

-- Put read buffer at end of same allocation
local rbuf3 = cb3 + 256
memory.write_dword(cb3, fd0)
memory.write_qword(cb3 + 8, 0)
memory.write_qword(cb3 + 16, rbuf3)
memory.write_qword(cb3 + 24, 16)

local ok3, ret3 = pcall(function() return syscall.sc_aio_read(cb3) end)
log("  aio_read: " .. (ok3 and "rv=" .. ret3:tonumber() or "CRASH"))

-- ============================================================
-- PART 4: Try aio_error/aio_return with NULL (just to see what happens)
-- These take a single aiocb pointer
-- ============================================================
log("")
log("--- PART 4: aio_error/return with dummy ---")

local dcb = memory.alloc(512)
for i = 0, 511, 8 do memory.write_qword(dcb + i, 0) end

local ae_ok, ae_ret = pcall(function() return syscall.sc_aio_error(dcb) end)
log("  aio_error(zeroed): " ..
    (ae_ok and "rv=" .. ae_ret:tonumber() or "ERR: " .. tostring(ae_ret):sub(1, 40)))

local ar_ok, ar_ret = pcall(function() return syscall.sc_aio_return(dcb) end)
log("  aio_return(zeroed): " ..
    (ar_ok and "rv=" .. ar_ret:tonumber() or "ERR: " .. tostring(ar_ret):sub(1, 40)))

-- Cleanup
pcall(function() syscall.sc_close(fd0) end)
pcall(function() syscall.sc_close(fd1) end)

log("")
log("=== AIO MINIMAL DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
