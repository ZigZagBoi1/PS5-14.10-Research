-- CRASH_CLASS: RISKY
-- PROBE 146a: thr_create(430) with CS=0x43/SS=0x3B fix
--
-- Context: thr_create(430) returns rv=0 with real TID but panics kernel.
-- Root cause (13.60 Ghidra PRs #30/#31): set_mcontext() copies CS from
-- user ucontext without OR-ing SEL_RPL_MASK (0x3). CS=0 from zeroed
-- context → ISPL(0)=0 → kernel-mode fault → pcb_onfault==NULL → panic.
--
-- FIX HYPOTHESIS: Set CS=0x43 (user code segment, RPL=3) and
-- SS=0x3B (user data segment, RPL=3) in the ucontext/mcontext.
-- This should make the child thread's trap frame indicate user-mode,
-- preventing the kernel panic.
--
-- WARNING: This WILL create a real kernel thread. If the hypothesis is
-- wrong, it panics the PS5. Only run when confident.

print("=== PROBE 146a: THR_CREATE CS=0x43 FIX ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 146a COMPLETE ===")
    return
end

-- ============================================================
-- SECTION A: Build proper ucontext with CS=0x43
-- ============================================================
print("")
print("--- SECTION A: BUILD UCONTEXT ---")

-- FreeBSD amd64 ucontext_t layout:
-- +0x00: uc_sigmask (16 bytes)
-- +0x10: uc_mcontext (mcontext_t)
--   mcontext_t on amd64:
--   +0x00: mc_onstack (8)
--   +0x08: mc_rdi (8)
--   +0x10: mc_rsi (8)
--   +0x18: mc_rdx (8)
--   +0x20: mc_rcx (8)
--   +0x28: mc_r8 (8)
--   +0x30: mc_r9 (8)
--   +0x38: mc_rax (8)
--   +0x40: mc_rbx (8)
--   +0x48: mc_rbp (8)
--   +0x50: mc_r10 (8)
--   +0x58: mc_r11 (8)
--   +0x60: mc_r12 (8)
--   +0x68: mc_r13 (8)
--   +0x70: mc_r14 (8)
--   +0x78: mc_r15 (8)
--   +0x80: mc_trapno (4)
--   +0x84: mc_fs (2), mc_gs (2)
--   +0x88: mc_addr (8)
--   +0x90: mc_flags (4)
--   +0x94: mc_es (2), mc_ds (2)
--   +0x98: mc_err (8)
--   +0xA0: mc_rip (8)
--   +0xA8: mc_cs (8)    *** THIS IS THE KEY FIELD ***
--   +0xB0: mc_rflags (8)
--   +0xB8: mc_rsp (8)
--   +0xC0: mc_ss (8)    *** AND THIS ***
--   +0xC8: mc_len (4)
--   +0xCC: mc_fpformat (4)
--   +0xD0: mc_ownedfp (4)
--   +0xD4: mc_fpstate[64] (512 bytes)
--   +0x2D4: mc_fsbase (8)
--   +0x2DC: mc_gsbase (8)
-- Total mcontext: ~0x340
-- uc_link at +0x350 (8)
-- uc_stack at +0x358 (ss_sp=8, ss_size=8, ss_flags=4)
-- uc_flags at +0x374 (4)

-- Offsets relative to mcontext start (uc + 0x10)
local MC_RDI = 0x08
local MC_RSI = 0x10
local MC_RDX = 0x18
local MC_RCX = 0x20
local MC_R8 = 0x28
local MC_RAX = 0x38
local MC_RBX = 0x40
local MC_RBP = 0x48
local MC_RSP_OFF = 0xB8 - 0x00  -- mc_rsp offset from mc start
local MC_RIP = 0xA0
local MC_CS = 0xA8
local MC_RFLAGS = 0xB0
local MC_RSP = 0xB8
local MC_SS = 0xC0
local MC_LEN = 0xC8
local MC_FSBASE = 0x2D4

-- We need a thread entry point. Use a simple gadget: ret (just returns)
-- Or better: use Thrd_exit to cleanly exit
local ret_gadget = gadgets["ret"]
local thrd_exit = libc_addrofs.Thrd_exit

print("ret gadget: " .. string.format("0x%X", ret_gadget or 0))
print("Thrd_exit: " .. string.format("0x%X", thrd_exit or 0))

-- Get current FS base for the new thread
local fsbase_buf = memory.alloc(8)
safe_wq(fsbase_buf, uint64(0))
-- sysarch(129=AMD64_GET_FSBASE, &fsbase) — wait, 129 is SET_FSBASE
-- sysarch(128=AMD64_GET_FSBASE, &fsbase)
local sa_ret = to_num(native.fcall_with_rax(stub, 165, 128, to_num(fsbase_buf)))
local fsbase = safe_rq(fsbase_buf)
print("sysarch(GET_FSBASE) ret=" .. sa_ret .. " fsbase=" .. fmt_addr(fsbase))

if sa_ret ~= 0 then
    -- Try alternative: read from TCB
    sa_ret = to_num(native.fcall_with_rax(stub, 165, 130, to_num(fsbase_buf)))
    fsbase = safe_rq(fsbase_buf)
    print("sysarch(GET_GSBASE=130) ret=" .. sa_ret .. " gsbase=" .. fmt_addr(fsbase))
end

-- Allocate thread stack (64KB)
local stack_size = 0x10000
local stack = to_num(native.fcall_with_rax(stub, 477, 0, stack_size, 3, 0x1002, 0xFFFFFFFF, 0))
print("thread stack: " .. string.format("0x%X", stack) .. " size=" .. stack_size)

if stack <= 0 then
    print("Stack alloc failed — aborting")
    print("=== PROBE 146a COMPLETE ===")
    return
end

-- Stack pointer: top of stack minus red zone
local stack_top = stack + stack_size - 128

-- Allocate ucontext (need ~0x400 bytes)
local uc = memory.alloc(0x400)
-- Zero it
for i = 0, 0x3F8, 8 do safe_wq(uc + i, uint64(0)) end

local mc = uc + 0x10  -- mcontext start

-- Set the critical registers
safe_wq(mc + MC_RIP, uint64(thrd_exit or ret_gadget))  -- entry point
safe_wq(mc + MC_RSP, uint64(stack_top))                 -- stack pointer
safe_wq(mc + MC_RDI, uint64(0))                          -- arg0 = exit code 0
safe_wq(mc + MC_CS, uint64(0x43))                        -- *** USER CODE SEGMENT RPL=3 ***
safe_wq(mc + MC_SS, uint64(0x3B))                        -- *** USER DATA SEGMENT RPL=3 ***
safe_wq(mc + MC_RFLAGS, uint64(0x202))                   -- IF=1, bit1=1 (standard)
safe_wd(mc + MC_LEN, 0x340)                              -- mcontext length

-- Set segment registers
safe_wd(mc + 0x94, 0x003B003B)   -- ES=0x3B, DS=0x3B

-- Set FS base if we got it
if fsbase and sa_ret == 0 then
    safe_wq(mc + MC_FSBASE, fsbase)
    print("Set fsbase in mcontext")
end

-- Set uc_stack
safe_wq(uc + 0x358, uint64(stack))       -- ss_sp
safe_wq(uc + 0x360, uint64(stack_size))  -- ss_size
safe_wd(uc + 0x368, 0)                    -- ss_flags

print("")
print("ucontext built:")
print("  RIP=" .. fmt_addr(safe_rq(mc + MC_RIP)))
print("  RSP=" .. fmt_addr(safe_rq(mc + MC_RSP)))
print("  CS=" .. fmt_addr(safe_rq(mc + MC_CS)))
print("  SS=" .. fmt_addr(safe_rq(mc + MC_SS)))
print("  RFLAGS=" .. fmt_addr(safe_rq(mc + MC_RFLAGS)))
print("  mc_len=" .. (safe_rd(mc + MC_LEN) or 0))

print("canary_pre_thr: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- SECTION B: thr_create with fixed ucontext
-- ============================================================
print("")
print("--- SECTION B: THR_CREATE ---")

-- thr_create(ucontext_t *ctx, long *id, int flags)
-- sys 430
local tid_buf = memory.alloc(8)
safe_wq(tid_buf, uint64(0))

print("Calling thr_create(430)...")
print("*** WARNING: If CS=0x43 hypothesis is wrong, this panics the kernel ***")

local thr_ret = to_num(native.fcall_with_rax(stub, 430,
    to_num(uc), to_num(tid_buf), 0))
local tid = safe_rq(tid_buf)

print("thr_create ret=" .. thr_ret)
print("tid=" .. fmt_addr(tid))

-- If we get here, the kernel didn't panic!
print("*** SURVIVED thr_create ***")

-- Wait a moment for thread to run
sleep(0.1, 's')

print("canary_post_thr: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Try thr_join if thread is alive
if thr_ret == 0 then
    print("Attempting thr_join...")
    -- _thr_exit is not the same as joining. Use Thrd_join pattern
    -- or just wait
    sleep(0.5, 's')
    print("Thread should have exited by now")
end

-- Cleanup
native.fcall_with_rax(stub, 73, stack, stack_size)

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 146a COMPLETE ===")
