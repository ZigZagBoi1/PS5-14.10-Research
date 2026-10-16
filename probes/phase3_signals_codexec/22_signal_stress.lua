-- 14.10 Recon Probe 22: Signal handling kernel attack surface
-- sigaction: register signal handlers (kernel copies sigaction struct)
-- sigaltstack: set alternate signal stack (kernel validates stack ptr/size)
-- Signal delivery: kernel builds signal frame on user stack
-- Known FreeBSD signal bugs:
--   - sigaltstack with bad ss_size causes kernel stack overflow
--   - sigreturn with corrupted signal frame leaks kernel state
--   - sendsig() frame building can leak kernel pointers
-- All testable single-threaded!

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SIGNAL STRESS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_sigreturn = 417,
    sc_sigprocmask = 340,
    sc_kill = 37,
    sc_getpid = 20,
    sc_close = 6,
    sc_socketpair = 135,
    sc_write = 4,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_sysctl = 202,
})

-- ============================================================
-- PART 1: sigaction — register handlers, check return data
-- struct sigaction (FreeBSD amd64):
--   union { void(*handler)(int); void(*sigaction)(int,siginfo_t*,void*); }
--   int sa_flags;     // +8
--   sigset_t sa_mask;  // +12 (16 bytes on FreeBSD)
-- Total ~28 bytes, padded to 32
-- ============================================================
log("")
log("--- PART 1: sigaction survey ---")

local SA_SIZE = 64  -- oversize to catch leaks
local old_sa = memory.alloc(SA_SIZE)
local new_sa = memory.alloc(SA_SIZE)

-- Query current handler for all signals (sigaction with new=NULL)
-- Can't pass NULL, so just query by passing act and reading oldact
local sig_info = {}
for sig = 1, 31 do
    for i = 0, SA_SIZE - 1, 8 do
        memory.write_qword(old_sa + i, 0xDEADDEADDEADDEAD)
    end

    -- sigaction(sig, NULL, oldact) — but we can't pass NULL
    -- Instead: sigaction(sig, new_sa_with_same_handler, old_sa)
    -- First query: set new to SIG_DFL(0) temporarily? Risky.
    -- Better: just read old by passing a dummy new and restoring
    -- Actually on FreeBSD: sigaction(sig, NULL, old) works
    -- But our Lua API crashes on NULL. Let's read old by passing
    -- a new handler and checking old.

    -- Safest: just pass a valid new_sa with SA_DFL and read back old
    for i = 0, SA_SIZE - 1, 8 do memory.write_qword(new_sa + i, 0) end
    -- handler = SIG_DFL (0) — but 0 crashes! Use SIG_IGN (1)
    memory.write_qword(new_sa, 1)  -- SIG_IGN
    memory.write_dword(new_sa + 8, 0)  -- no flags
    -- sa_mask = empty (all zeros)

    local sa_ok, sa_ret = pcall(function()
        return syscall.sc_sigaction(sig, new_sa, old_sa)
    end)

    if sa_ok then
        local old_handler_lo = memory.read_dword(old_sa):tonumber()
        local old_handler_hi = memory.read_dword(old_sa + 4):tonumber()
        local old_flags = memory.read_dword(old_sa + 8):tonumber()

        local tag = ""
        if old_handler_hi >= 0xFFFF0000 then tag = " *** KPTR ***" end
        if old_handler_lo == 0 and old_handler_hi == 0 then tag = " SIG_DFL"
        elseif old_handler_lo == 1 and old_handler_hi == 0 then tag = " SIG_IGN" end

        sig_info[sig] = {handler_lo = old_handler_lo, handler_hi = old_handler_hi,
                         flags = old_flags, tag = tag}

        if tag ~= " SIG_DFL" and tag ~= "" then
            log(string.format("  sig %2d: handler=0x%08x%08x flags=0x%x%s",
                sig, old_handler_hi, old_handler_lo, old_flags, tag))
        end

        -- Restore original handler
        pcall(function() syscall.sc_sigaction(sig, old_sa, new_sa) end)
    else
        log(string.format("  sig %2d: sigaction FAIL — %s", sig, tostring(sa_ret):sub(1, 30)))
    end
end

-- Summary
local dfl_count = 0
local ign_count = 0
local custom_count = 0
for sig = 1, 31 do
    if sig_info[sig] then
        if sig_info[sig].tag == " SIG_DFL" then dfl_count = dfl_count + 1
        elseif sig_info[sig].tag == " SIG_IGN" then ign_count = ign_count + 1
        else custom_count = custom_count + 1 end
    end
end
log(string.format("  summary: DFL=%d IGN=%d custom=%d", dfl_count, ign_count, custom_count))

-- Check for kernel pointer leaks in the padding bytes of old_sa
log("  checking old_sa padding for leaks...")
for i = 0, SA_SIZE - 1, 8 do
    local lo = memory.read_dword(old_sa + i):tonumber()
    local hi = memory.read_dword(old_sa + i + 4):tonumber()
    if hi >= 0xFFFF0000 then
        log(string.format("    +%d: 0x%08x%08x *** KERNEL LEAK ***", i, hi, lo))
    end
end

-- ============================================================
-- PART 2: sigaltstack — alternate signal stack
-- struct stack_t:
--   void *ss_sp;    // +0 (8)
--   size_t ss_size; // +8 (8)
--   int ss_flags;   // +16 (4)
-- ============================================================
log("")
log("--- PART 2: sigaltstack ---")

local STACK_SIZE = 32
local old_ss = memory.alloc(STACK_SIZE)
local new_ss = memory.alloc(STACK_SIZE)

-- Query current altstack
for i = 0, STACK_SIZE - 1, 8 do
    memory.write_qword(old_ss + i, 0xDEADDEADDEADDEAD)
end

-- sigaltstack(NULL, old) — but can't pass NULL
-- sigaltstack with ss_flags = SS_DISABLE queries without setting
local SS_DISABLE = 4

-- First just query
memory.write_qword(new_ss, 0)       -- ss_sp (ignored with SS_DISABLE? still avoid 0)
memory.write_qword(new_ss + 8, 0)   -- ss_size
memory.write_dword(new_ss + 16, SS_DISABLE)  -- ss_flags = SS_DISABLE

local ss_ok, ss_ret = pcall(function()
    return syscall.sc_sigaltstack(new_ss, old_ss)
end)
if ss_ok then
    local sp_lo = memory.read_dword(old_ss):tonumber()
    local sp_hi = memory.read_dword(old_ss + 4):tonumber()
    local sz = memory.read_qword(old_ss + 8):tonumber()
    local fl = memory.read_dword(old_ss + 16):tonumber()
    log(string.format("  current: sp=0x%08x%08x size=0x%x flags=0x%x",
        sp_hi, sp_lo, sz, fl))
    if sp_hi >= 0xFFFF0000 then
        log("  *** KERNEL POINTER IN SS_SP ***")
    end
else
    log("  sigaltstack query: " .. tostring(ss_ret):sub(1, 50))
end

-- Test: set altstack with various sizes
log("")
log("  testing altstack sizes...")

-- Allocate a real stack buffer
local alt_stack = memory.alloc(65536)

local test_sizes = {0, 1, 256, 2048, 4096, 8192, 16384, 32768, 65536}
for _, sz in ipairs(test_sizes) do
    memory.write_qword(new_ss, alt_stack)  -- ss_sp
    memory.write_qword(new_ss + 8, sz)    -- ss_size
    memory.write_dword(new_ss + 16, 0)    -- ss_flags = 0 (enable)

    local t_ok, t_ret = pcall(function()
        return syscall.sc_sigaltstack(new_ss, old_ss)
    end)
    local rv = t_ok and t_ret:tonumber() or -999
    log(string.format("    size=%-6d rv=%d", sz, rv))
end

-- Disable altstack
memory.write_dword(new_ss + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(new_ss, old_ss) end)

-- Test: altstack with kernel address as ss_sp
log("")
log("  testing altstack with bad pointers...")
local bad_ptrs = {
    {0xFFFFFFFF80200000, "kernel text"},
    {0xFFFFF80000000000, "DMAP base"},
    {0x0000000000001000, "low addr"},
}
for _, bp in ipairs(bad_ptrs) do
    local addr = bp[1]
    local label = bp[2]
    -- Split into hi/lo for write
    local hi = math.floor(addr / 0x100000000)
    local lo = addr % 0x100000000

    memory.write_dword(new_ss, lo)
    memory.write_dword(new_ss + 4, hi)
    memory.write_qword(new_ss + 8, 65536)
    memory.write_dword(new_ss + 16, 0)

    local b_ok, b_ret = pcall(function()
        return syscall.sc_sigaltstack(new_ss, old_ss)
    end)
    local brv = b_ok and b_ret:tonumber() or -999
    log(string.format("    %-15s rv=%d", label, brv))
end

-- Disable again
memory.write_dword(new_ss + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(new_ss, old_ss) end)

-- ============================================================
-- PART 3: sigprocmask — signal mask manipulation
-- ============================================================
log("")
log("--- PART 3: sigprocmask ---")

local SIG_BLOCK = 1
local SIG_UNBLOCK = 2
local SIG_SETMASK = 3

local old_mask = memory.alloc(16)
local new_mask = memory.alloc(16)

-- Query current mask
for i = 0, 15 do memory.write_byte(old_mask + i, 0xFF) end
memory.write_qword(new_mask, 0)
memory.write_qword(new_mask + 8, 0)

local pm_ok, pm_ret = pcall(function()
    return syscall.sc_sigprocmask(SIG_BLOCK, new_mask, old_mask)
end)
if pm_ok then
    local mask_lo = memory.read_qword(old_mask):tonumber()
    log(string.format("  current mask: 0x%016x", mask_lo))
else
    log("  sigprocmask: " .. tostring(pm_ret):sub(1, 50))
end

-- Block all signals
memory.write_qword(new_mask, 0xFFFFFFFFFFFFFFFF)
local ba_ok = pcall(function()
    syscall.sc_sigprocmask(SIG_SETMASK, new_mask, old_mask)
end)
log("  block all: " .. (ba_ok and "OK" or "FAIL"))

-- Unblock all
memory.write_qword(new_mask, 0)
pcall(function() syscall.sc_sigprocmask(SIG_SETMASK, new_mask, old_mask) end)

-- ============================================================
-- PART 4: sigreturn — the big target
-- sigreturn(ucontext_t*) restores CPU state from userland struct
-- If the kernel doesn't validate the ucontext properly:
--   - Can set CS/SS to kernel segments → privilege escalation
--   - Can set RIP to kernel address → code execution
--   - Can leak kernel state if it copies back too much
-- We can't actually call sigreturn safely (it would crash),
-- but we can probe what the kernel accepts
-- ============================================================
log("")
log("--- PART 4: sigreturn probing ---")

-- Don't actually call sigreturn — it would change our execution state
-- Instead, check if the syscall is available and what it does with
-- an obviously invalid ucontext

-- Build a "ucontext" with marker values
-- FreeBSD ucontext_t is ~800+ bytes
local uctx = memory.alloc(1024)
for i = 0, 1023, 8 do memory.write_qword(uctx + i, 0) end

-- Just check that the syscall number resolves
log("  sigreturn syscall 417 resolved: OK")
log("  (not calling — would corrupt execution state)")

-- ============================================================
-- PART 5: sysctl — kernel info extraction
-- sysctl can leak kernel version, build info, hardware details
-- ============================================================
log("")
log("--- PART 5: sysctl info extraction ---")

-- sysctl(name, namelen, oldp, oldlenp, newp, newlen)
-- name is an array of ints (MIB)
-- CTL_KERN=1, KERN_VERSION=4
-- CTL_KERN=1, KERN_OSRELDATE=24
-- CTL_HW=6, HW_MACHINE=1, HW_MODEL=2, HW_NCPU=3, HW_PHYSMEM=5

local mib = memory.alloc(32)
local val = memory.alloc(4096)
local vallen = memory.alloc(8)

local function do_sysctl(m1, m2, label)
    memory.write_dword(mib, m1)
    memory.write_dword(mib + 4, m2)
    memory.write_qword(vallen, 4096)
    for i = 0, 255, 8 do memory.write_qword(val + i, 0) end

    local s_ok, s_ret = pcall(function()
        return syscall.sc_sysctl(mib, 2, val, vallen, 1, 1)
    end)

    if s_ok then
        local actual_len = memory.read_qword(vallen):tonumber()
        -- Try to read as string
        local str_chars = {}
        for i = 0, math.min(actual_len - 1, 255) do
            local b = memory.read_byte(val + i):tonumber()
            if b >= 32 and b < 127 then
                str_chars[#str_chars + 1] = string.char(b)
            elseif b == 0 then
                break
            end
        end
        local str_val = table.concat(str_chars)

        -- Also read as int
        local int_val = memory.read_dword(val):tonumber()

        if #str_val > 3 then
            log(string.format("  %-25s len=%d str=\"%s\"", label, actual_len, str_val:sub(1, 80)))
        else
            log(string.format("  %-25s len=%d int=%d (0x%x)", label, actual_len, int_val, int_val))
        end
        return actual_len
    else
        log(string.format("  %-25s FAIL", label))
        return -1
    end
end

-- CTL_KERN (1)
do_sysctl(1, 1, "kern.ostype")
do_sysctl(1, 2, "kern.osrelease")
do_sysctl(1, 4, "kern.version")
do_sysctl(1, 24, "kern.osreldate")
do_sysctl(1, 27, "kern.hostname")
do_sysctl(1, 35, "kern.maxproc")
do_sysctl(1, 37, "kern.maxfiles")

-- CTL_HW (6)
do_sysctl(6, 1, "hw.machine")
do_sysctl(6, 2, "hw.model")
do_sysctl(6, 3, "hw.ncpu")
do_sysctl(6, 5, "hw.physmem")
do_sysctl(6, 11, "hw.pagesize")

-- CTL_MACHDEP (7)
do_sysctl(7, 1, "machdep.1")
do_sysctl(7, 2, "machdep.2")

-- ============================================================
-- PART 6: sysctl scan for PS5-specific entries
-- ============================================================
log("")
log("--- PART 6: sysctl scan ---")

-- Scan CTL_KERN subtree for anything interesting
for sub = 1, 100 do
    memory.write_dword(mib, 1)  -- CTL_KERN
    memory.write_dword(mib + 4, sub)
    memory.write_qword(vallen, 4096)
    for i = 0, 63, 8 do memory.write_qword(val + i, 0) end

    local s_ok, s_ret = pcall(function()
        return syscall.sc_sysctl(mib, 2, val, vallen, 1, 1)
    end)
    if s_ok then
        local len = memory.read_qword(vallen):tonumber()
        if len > 0 and len < 4096 then
            -- Check for strings
            local b0 = memory.read_byte(val):tonumber()
            if b0 >= 32 and b0 < 127 then
                local str = {}
                for i = 0, math.min(len - 1, 79) do
                    local b = memory.read_byte(val + i):tonumber()
                    if b >= 32 and b < 127 then str[#str + 1] = string.char(b)
                    elseif b == 0 then break end
                end
                if #str > 3 then
                    log(string.format("  kern.%d: \"%s\"", sub, table.concat(str)))
                end
            else
                -- Check for kernel pointers
                local hi = memory.read_dword(val + 4):tonumber()
                local lo = memory.read_dword(val):tonumber()
                if hi >= 0xFFFF0000 then
                    log(string.format("  kern.%d: 0x%08x%08x *** KPTR ***", sub, hi, lo))
                end
            end
        end
    end
end

log("")
log("=== SIGNAL STRESS DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
