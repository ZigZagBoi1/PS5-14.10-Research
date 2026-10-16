-- 14.10 Recon Probe 25: Safe kernel altstack test
-- Probe 24 showed: signal delivery to user altstack WORKS
-- The handler ran and corrupted Lua state
-- New approach:
-- 1. Set altstack to kernel addr
-- 2. Block the signal with sigprocmask
-- 3. Send signal (it becomes pending, not delivered)
-- 4. Check if anything happened
-- 5. Also: set altstack to kernel addr, but handler = SIG_IGN
--    SIG_IGN should not build a frame at all
-- 6. Test: does the kernel even touch ss_sp during sigaltstack()?
--    Maybe it reads/writes the pointed memory during the syscall

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SIGALT SAFE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_sigprocmask = 340,
    sc_sigpending = 343,
    sc_kill = 37,
    sc_getpid = 20,
    sc_close = 6,
    sc_write = 4,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_sysctl = 202,
    sc_socketpair = 135,
})

local SA_SIZE = 64
local SS_SIZE = 32
local SA_ONSTACK = 0x0001
local SA_SIGINFO = 0x0040
local SS_DISABLE = 4
local SIG_BLOCK = 1
local SIG_UNBLOCK = 2
local SIG_SETMASK = 3

local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(SS_SIZE)
local ss_old = memory.alloc(SS_SIZE)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: Verify signal frame baseline on user altstack
-- Use a pattern we can check reliably (not 0xAA which has
-- precision issues in Lua doubles)
-- ============================================================
log("")
log("--- PART 1: signal frame baseline ---")

local STACK_SZ = 16384
local user_stack = memory.alloc(STACK_SZ)

-- Fill with simple pattern: offset value as 32-bit int
for i = 0, STACK_SZ - 1, 4 do
    memory.write_dword(user_stack + i, 0x11110000 + i)
end

-- Set altstack
memory.write_qword(ss_new, user_stack)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Set SIGUSR1 handler to crash handler with SA_ONSTACK
-- But first block SIGUSR1 so delivery is deferred
local mask = memory.alloc(16)
local old_mask = memory.alloc(16)

-- Block SIGUSR1 (bit 29, since SIGUSR1=30, 0-indexed = bit 29)
memory.write_qword(mask, 0)
memory.write_qword(mask + 8, 0)
-- Signal 30 = bit 29 in the mask
local sigusr1_bit = 2^29  -- SIGUSR1=30 is bit 29
memory.write_dword(mask, sigusr1_bit)  -- low 32 bits
-- Actually sigset_t on FreeBSD: signal N is in word (N-1)/32, bit (N-1)%32
-- SIGUSR1=30: word 0, bit 29
memory.write_dword(mask, 2^29)

pcall(function() syscall.sc_sigprocmask(SIG_BLOCK, mask, old_mask) end)
log("  blocked SIGUSR1")

-- Set handler with SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4)  -- crash handler
memory.write_dword(sa_new + 4, 0)
memory.write_dword(sa_new + 8, SA_ONSTACK + SA_SIGINFO)
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

-- Send SIGUSR1 (will be pending, not delivered)
pcall(function() syscall.sc_kill(pid, 30) end)
log("  sent SIGUSR1 (blocked, should be pending)")

-- Check pending
local pending = memory.alloc(16)
local sp_ok, sp_ret = pcall(function()
    return syscall.sc_sigpending(pending)
end)
if sp_ok then
    local pend_lo = memory.read_dword(pending):tonumber()
    log(string.format("  pending mask: 0x%08x (bit29=%s)",
        pend_lo, (pend_lo % (2^30) >= 2^29) and "SET" or "clear"))
end

-- Check altstack — NOT modified because signal not delivered
local modified = 0
for i = 0, STACK_SZ - 4, 4 do
    local v = memory.read_dword(user_stack + i):tonumber()
    if v ~= 0x11110000 + i then
        modified = modified + 1
    end
end
log("  altstack modified dwords (blocked): " .. modified)

-- Now UNBLOCK and let the signal deliver
-- This will run the crash handler — we need to survive
-- Actually... the crash handler will corrupt Lua. Don't do this yet.
-- Instead, change handler to SIG_IGN before unblocking
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
memory.write_dword(sa_new + 8, SA_ONSTACK)  -- still SA_ONSTACK
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  changed handler to SIG_IGN (still ONSTACK)")

-- Unblock
memory.write_qword(mask, 0)
pcall(function() syscall.sc_sigprocmask(SIG_SETMASK, mask, old_mask) end)
log("  unblocked — pending signal should deliver")

-- Check altstack modification (SIG_IGN should NOT build frame)
modified = 0
for i = 0, STACK_SZ - 4, 4 do
    local v = memory.read_dword(user_stack + i):tonumber()
    if v ~= 0x11110000 + i then
        modified = modified + 1
    end
end
log("  altstack modified dwords (after IGN delivery): " .. modified)

-- Disable altstack
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- ============================================================
-- PART 2: Kernel altstack with SIG_IGN
-- If SIG_IGN doesn't touch the altstack, then setting it to
-- kernel addr and sending an ignored signal is safe
-- ============================================================
log("")
log("--- PART 2: kernel altstack + SIG_IGN ---")

-- Set altstack to kernel DMAP
local KADDR_HI = 0xFFFFF800
local KADDR_LO = 0x10000000

memory.write_dword(ss_new, KADDR_LO)
memory.write_dword(ss_new + 4, KADDR_HI)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local kss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log(string.format("  set kernel altstack: %s", kss_ok and "OK" or "FAIL"))

-- SIGUSR2 with SIG_IGN + SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
memory.write_dword(sa_new + 8, SA_ONSTACK)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

-- Send SIGUSR2
local k_ok, k_ret = pcall(function()
    return syscall.sc_kill(pid, 31)
end)
log("  kill(SIGUSR2) with kernel altstack: " ..
    (k_ok and "rv=" .. k_ret:tonumber() or "CRASH"))

local alive1 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive1))

-- Check altstack state
local check_ss = memory.alloc(SS_SIZE)
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, check_ss) end)
local css_lo = memory.read_dword(check_ss):tonumber()
local css_hi = memory.read_dword(check_ss + 4):tonumber()
local css_fl = memory.read_dword(check_ss + 16):tonumber()
log(string.format("  altstack: sp=0x%08x%08x flags=0x%x", css_hi, css_lo, css_fl))

-- ============================================================
-- PART 3: Kernel altstack with REAL handler (blocked signal)
-- Set kernel altstack, set real handler with SA_ONSTACK,
-- send signal but keep it BLOCKED, then change to SIG_IGN
-- and unblock — if SIG_IGN path doesn't touch altstack, safe
-- ============================================================
log("")
log("--- PART 3: kernel altstack + blocked real handler ---")

-- Re-enable kernel altstack
memory.write_dword(ss_new, KADDR_LO)
memory.write_dword(ss_new + 4, KADDR_HI)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Block SIGUSR2 (signal 31 = bit 30)
memory.write_dword(mask, 2^30)
memory.write_dword(mask + 4, 0)
pcall(function() syscall.sc_sigprocmask(SIG_BLOCK, mask, old_mask) end)

-- Set real handler with SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4)
memory.write_dword(sa_new + 4, 0)
memory.write_dword(sa_new + 8, SA_ONSTACK + SA_SIGINFO)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

-- Send signal (stays pending)
pcall(function() syscall.sc_kill(pid, 31) end)
log("  sent SIGUSR2 (blocked, kernel altstack, real handler)")

-- Check pending
pcall(function() syscall.sc_sigpending(pending) end)
local pend_lo2 = memory.read_dword(pending):tonumber()
log(string.format("  pending: 0x%08x (bit30=%s)",
    pend_lo2, (pend_lo2 % (2^31) >= 2^30) and "SET" or "clear"))

-- Change handler to SIG_DFL before unblocking
-- SIG_DFL for SIGUSR2 = terminate. But we're ignoring it...
-- Better: change to SIG_IGN, then unblock
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
memory.write_dword(sa_new + 8, 0)  -- NO SA_ONSTACK this time
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)
log("  changed to SIG_IGN (no ONSTACK)")

-- Also disable altstack before unblocking
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  disabled altstack")

-- Unblock
memory.write_qword(mask, 0)
pcall(function() syscall.sc_sigprocmask(SIG_SETMASK, mask, old_mask) end)
log("  unblocked SIGUSR2")

local alive2 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive2))

-- ============================================================
-- PART 4: Test if sigaltstack validates ss_sp in kernel
-- by setting it to an unmapped userland address and triggering
-- signal delivery — if kernel crashes = no validation
-- ============================================================
log("")
log("--- PART 4: unmapped userland altstack ---")

-- Use a high userland address that's definitely unmapped
local UNMAPPED_HI = 0x00007FFF
local UNMAPPED_LO = 0xDEAD0000

memory.write_dword(ss_new, UNMAPPED_LO)
memory.write_dword(ss_new + 4, UNMAPPED_HI)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local uss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log(string.format("  set unmapped altstack 0x%08x%08x: %s",
    UNMAPPED_HI, UNMAPPED_LO, uss_ok and "OK" or "FAIL"))

-- Send IGN signal (safe, no frame built)
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)
memory.write_dword(sa_new + 8, SA_ONSTACK)
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

local u_ok, u_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill with unmapped altstack + IGN: " ..
    (u_ok and "rv=" .. u_ret:tonumber() or "CRASH"))

-- Disable
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Restore defaults
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

log("")
log("=== SIGALT SAFE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
