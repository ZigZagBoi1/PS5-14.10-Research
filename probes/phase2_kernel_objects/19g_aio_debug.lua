-- 14.10 Recon Probe 19g: Debug why aio_read crashes
-- Every attempt at aio_read kills the loader
-- This probe: test aio_write, test with /dev/null, test alternate syscall nums
-- Also check if the Lua wrapper is the issue vs the kernel

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: AIO DEBUG ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_close = 6,
    sc_write = 4,
    sc_open = 5,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_aio_error = 315,
})

-- ============================================================
-- PART 1: Verify aio_error still works
-- ============================================================
log("")
log("--- PART 1: aio_error baseline ---")

local dummy = memory.alloc(512)
for i = 0, 511, 8 do memory.write_qword(dummy + i, 0) end

local ae_ok, ae_ret = pcall(function() return syscall.sc_aio_error(dummy) end)
log("  aio_error: " .. (ae_ok and "rv=" .. ae_ret:tonumber() or "CRASH"))

-- ============================================================
-- PART 2: Test if the issue is the syscall number
-- Maybe PS5 uses different numbers for aio_read
-- Try raw syscall approach: resolve with different numbers
-- ============================================================
log("")
log("--- PART 2: alternate aio_read numbers ---")

-- Standard FreeBSD: aio_read=255
-- But PS5 might remap to a different number
-- Let's check what's near 255

local alt_nums = {255, 256, 319, 320, 386, 387, 500, 501}
for _, num in ipairs(alt_nums) do
    local name = "aio_alt_" .. num
    local tbl = {}
    tbl[name] = num

    local rok = pcall(function() syscall.resolve(tbl) end)
    if rok then
        -- Try calling it with our aiocb
        local cb = memory.alloc(512)
        local buf = memory.alloc(256)
        for i = 0, 511, 8 do memory.write_qword(cb + i, 0) end

        -- Open /dev/null for a safe fd
        local nok, nret = pcall(function() return syscall.sc_open("/dev/null", 2) end)
        local nfd = nok and nret:tonumber() or -1

        if nfd >= 0 then
            memory.write_dword(cb, nfd)
            memory.write_qword(cb + 16, buf)
            memory.write_qword(cb + 24, 16)

            local t_ok, t_ret = pcall(function() return syscall[name](cb) end)
            log(string.format("  syscall %d: %s", num,
                t_ok and "rv=" .. t_ret:tonumber() or "ERR: " .. tostring(t_ret):sub(1, 30)))

            pcall(function() syscall.sc_close(nfd) end)
        end
    else
        log(string.format("  syscall %d: resolve FAIL", num))
    end
end

-- ============================================================
-- PART 3: Test if the problem is the aiocb pointer value
-- Maybe the Lua API passes the wrong thing to the kernel
-- Use a huge allocation to ensure alignment
-- ============================================================
log("")
log("--- PART 3: alignment test ---")

syscall.resolve({ sc_aio_read = 255 })

-- Allocate a very large buffer and use aligned address
local big = memory.alloc(65536)
-- Align to 4096 boundary
local aligned = big
local mod = big % 4096
if mod ~= 0 then aligned = big + (4096 - mod) end

local rbuf3 = memory.alloc(4096)
for i = 0, 511, 8 do memory.write_qword(aligned + i, 0) end

-- /dev/null
local n3_ok, n3_ret = pcall(function() return syscall.sc_open("/dev/null", 0) end)
local nfd3 = n3_ok and n3_ret:tonumber() or -1
log("  /dev/null fd=" .. nfd3)

if nfd3 >= 0 then
    memory.write_dword(aligned, nfd3)
    memory.write_qword(aligned + 8, 0)
    memory.write_qword(aligned + 16, rbuf3)
    memory.write_qword(aligned + 24, 1)  -- just 1 byte

    log("  aiocb at " .. string.format("0x%x", aligned) .. " (4K aligned)")

    local r3_ok, r3_ret = pcall(function() return syscall.sc_aio_read(aligned) end)
    log("  aio_read: " .. (r3_ok and "rv=" .. r3_ret:tonumber() or "CRASH"))

    if r3_ok then
        log("  *** WORKS WITH ALIGNED AIOCB ***")
    end

    pcall(function() syscall.sc_close(nfd3) end)
end

-- ============================================================
-- PART 4: Test if it's a sandbox kill (SIGKILL from kernel)
-- vs a crash (SIGSEGV). If sandbox, no amount of fixing helps.
-- We can check by seeing if subsequent syscalls work after
-- the pcall catches the error
-- ============================================================
log("")
log("--- PART 4: post-crash liveness ---")

local alive = pcall(function() return syscall.sc_getpid() end)
log("  alive after all tests: " .. tostring(alive))

if alive then
    log("  PID: " .. syscall.getpid():tonumber())
end

log("")
log("=== AIO DEBUG DONE ===")
return table.concat(out, "\n")
