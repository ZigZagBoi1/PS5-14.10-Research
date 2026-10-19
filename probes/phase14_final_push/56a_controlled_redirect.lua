-- CRASH_CLASS: MODERATE
-- PROBE 56a v2: Controlled CClosure redirect via DWORD writes
--
-- Context: 55g confirmed +0x20 IS the C function dispatch pointer.
-- CRITICAL: qword writes to +0x20 BLOCK (54q, 56a v1 both hung 15-30s).
-- DWORD writes to +0x20 are INSTANT (55g section G/H).
-- This version uses safe_wd for the low dword + safe_wd for the high dword.
--
-- Tests:
--   [C] Redirect type() -> tostring (should return "42" for type(42))
--   [D] Redirect type() -> rawequal (should return boolean)
--   [E] Redirect type() -> select (should return selected args)
--   [F] Cross-redirect: pcall() -> type's C function

print("=== PROBE 56a v2: CONTROLLED REDIRECT (DWORD WRITES) ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

-- Write a qword using two dword writes (avoids the qword write hang)
local function write_ptr(addr, new_val)
    local new_h, new_l = get_hi_lo(new_val)
    local ok1 = safe_wd(addr, new_l)
    local ok2 = safe_wd(addr + 4, new_h)
    return ok1 and ok2
end

-- Get addresses of all test functions
local funcs = {
    {name="type",     fn=type},
    {name="tostring", fn=tostring},
    {name="rawget",   fn=rawget},
    {name="select",   fn=select},
    {name="pcall",    fn=pcall},
    {name="rawequal", fn=rawequal},
}

print("[A] Function addresses and +0x20 targets")
for _, f in ipairs(funcs) do
    f.addr = parse_func_addr(f.fn)
    if f.addr then
        f.target = safe_rq(f.addr + 0x20)
        f.target_h, f.target_l = get_hi_lo(f.target)
        print(string.format("  %-10s obj=%s  +0x20=%s", f.name, hexval(f.addr), hexval(f.target)))
    else
        print(string.format("  %-10s FAILED to parse", f.name))
    end
end

local type_addr = funcs[1].addr
local type_orig = funcs[1].target
local type_orig_h, type_orig_l = funcs[1].target_h, funcs[1].target_l
if not type_addr or not type_orig then
    print("FAILED: can't get type address")
    print("=== PROBE 56a ABORTED ===")
    return
end

print("")
print("[B] Baseline")
print("  type(42) = " .. tostring(type(42)))
print("  type('hello') = " .. tostring(type("hello")))
print("  type(nil) = " .. tostring(type(nil)))
print("  type({}) = " .. tostring(type({})))

collectgarbage("stop")

-- ============================================================
-- [C] Redirect type() -> tostring's C function
-- tostring(42) returns "42", so type(42) should return "42"
-- ============================================================
print("")
print("[C] Redirect type() -> tostring (via dword writes)")
local tostring_entry = funcs[2]
if tostring_entry and tostring_entry.target then
    print("  old +0x20: " .. hexval(type_orig))
    print("  new +0x20: " .. hexval(tostring_entry.target))
    local wok = write_ptr(type_addr + 0x20, tostring_entry.target)
    print("  dword write ok=" .. tostring(wok))
    -- Verify the write landed
    local verify = safe_rq(type_addr + 0x20)
    print("  verify +0x20: " .. hexval(verify))
    print("  MARKER_BEFORE_CALL")
    local ok, result = pcall(type, 42)
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok) .. " result=" .. tostring(result))
    if ok then
        local ok2, result2 = pcall(type, "hello")
        print("  type('hello') ok=" .. tostring(ok2) .. " result=" .. tostring(result2))
        local ok3, result3 = pcall(type, nil)
        print("  type(nil) ok=" .. tostring(ok3) .. " result=" .. tostring(result3))
    end
    -- Restore via dword writes
    write_ptr(type_addr + 0x20, type_orig)
    local restored = safe_rq(type_addr + 0x20)
    print("  restored +0x20: " .. hexval(restored))
    print("  verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no tostring target")
end

-- ============================================================
-- [D] Redirect type() -> rawequal's C function
-- rawequal(a,b) returns boolean
-- ============================================================
print("")
print("[D] Redirect type() -> rawequal (via dword writes)")
local rawequal_entry = funcs[6]
if rawequal_entry and rawequal_entry.target then
    print("  new +0x20: " .. hexval(rawequal_entry.target))
    write_ptr(type_addr + 0x20, rawequal_entry.target)
    print("  MARKER_BEFORE_CALL")
    local ok, result = pcall(type, 42, 42)
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok) .. " result=" .. tostring(result))
    local ok2, result2 = pcall(type, 42, 99)
    print("  type(42,99) ok=" .. tostring(ok2) .. " result=" .. tostring(result2))
    write_ptr(type_addr + 0x20, type_orig)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no rawequal target")
end

-- ============================================================
-- [E] Redirect type() -> select's C function
-- select(n, ...) returns n-th through last args
-- ============================================================
print("")
print("[E] Redirect type() -> select (via dword writes)")
local select_entry = funcs[4]
if select_entry and select_entry.target then
    print("  new +0x20: " .. hexval(select_entry.target))
    write_ptr(type_addr + 0x20, select_entry.target)
    print("  MARKER_BEFORE_CALL")
    local ok, r1, r2, r3 = pcall(type, 1, "aaa", "bbb", "ccc")
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok))
    if ok then
        print("  r1=" .. tostring(r1) .. " r2=" .. tostring(r2) .. " r3=" .. tostring(r3))
    else
        print("  error: " .. tostring(r1))
    end
    write_ptr(type_addr + 0x20, type_orig)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no select target")
end

-- ============================================================
-- [F] Timing comparison: dword write vs read
-- ============================================================
print("")
print("[F] Timing: 10 dword write cycles to +0x20")
local tostring_h, tostring_l = tostring_entry.target_h, tostring_entry.target_l
local t0 = os.clock()
for i = 1, 10 do
    safe_wd(type_addr + 0x20, tostring_l)
    safe_wd(type_addr + 0x24, tostring_h)
    safe_wd(type_addr + 0x20, type_orig_l)
    safe_wd(type_addr + 0x24, type_orig_h)
end
local t1 = os.clock()
print(string.format("  10 swap+restore cycles: %.4fs (%.4fs each)", t1 - t0, (t1 - t0) / 10))
print("  verify type(42): " .. tostring(type(42)))

collectgarbage("restart")

print("")
print("=== PROBE 56a v2 COMPLETE ===")
