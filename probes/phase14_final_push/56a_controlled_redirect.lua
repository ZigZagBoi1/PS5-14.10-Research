-- CRASH_CLASS: MODERATE
-- PROBE 56a: Controlled CClosure function pointer redirect
--
-- Context: 55g confirmed +0x20 IS the C function dispatch pointer.
-- Writing +1 crashed (misaligned exec). 54q redirected type()->tonumber()
-- and it blocked/looped. This probe does a SAFE controlled redirect:
--   1. Redirect type() -> rawget's C function (takes 2 args, returns 1)
--   2. Redirect type() -> select's C function
--   3. Redirect type() -> tostring's C function
-- Each time: overwrite +0x20, call type(), capture result, restore +0x20.
-- We also test calling with pcall to catch crashes.
-- If this works, we have proven arbitrary C function dispatch.

print("=== PROBE 56a: CONTROLLED CCLOSURE REDIRECT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
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

-- Get addresses of all test functions
local funcs = {
    {name="type",     fn=type},
    {name="tostring", fn=tostring},
    {name="rawget",   fn=rawget},
    {name="select",   fn=select},
    {name="pcall",    fn=pcall},
    {name="rawlen",   fn=rawlen},
    {name="rawequal", fn=rawequal},
}

print("[A] Function addresses and +0x20 targets")
for _, f in ipairs(funcs) do
    f.addr = parse_func_addr(f.fn)
    if f.addr then
        f.target = safe_rq(f.addr + 0x20)
        print(string.format("  %-10s obj=%s  +0x20=%s", f.name, hexval(f.addr), hexval(f.target)))
    else
        print(string.format("  %-10s FAILED to parse", f.name))
    end
end

local type_addr = funcs[1].addr
local type_orig = funcs[1].target
if not type_addr or not type_orig then
    print("FAILED: can't get type address")
    print("=== PROBE 56a ABORTED ===")
    return
end

print("")
print("[B] Baseline: type(42) = " .. tostring(type(42)))
print("    Baseline: type('hello') = " .. tostring(type("hello")))
print("    Baseline: type(nil) = " .. tostring(type(nil)))
print("    Baseline: type({}) = " .. tostring(type({})))

collectgarbage("stop")

-- ============================================================
-- [C] Redirect type() -> tostring's C function
-- tostring(x) takes 1 arg, returns a string. type(42) should
-- now behave like tostring(42) and return "42"
-- ============================================================
print("")
print("[C] Redirect type() -> tostring")
local tostring_target = funcs[2].target
if tostring_target then
    print("  writing +0x20: " .. hexval(type_orig) .. " -> " .. hexval(tostring_target))
    safe_wq(type_addr + 0x20, tostring_target)
    print("  MARKER_BEFORE_CALL")
    local ok, result = pcall(type, 42)
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok) .. " result=" .. tostring(result))
    local ok2, result2 = pcall(type, "hello")
    print("  type('hello') ok=" .. tostring(ok2) .. " result=" .. tostring(result2))
    local ok3, result3 = pcall(type, {})
    print("  type({}) ok=" .. tostring(ok3) .. " result=" .. tostring(result3))
    -- Restore
    safe_wq(type_addr + 0x20, type_orig)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no tostring target")
end

-- ============================================================
-- [D] Redirect type() -> rawequal's C function
-- rawequal(a,b) takes 2 args, returns boolean.
-- type(42) called with 1 arg should call rawequal with the
-- lua_State, which will compare its args
-- ============================================================
print("")
print("[D] Redirect type() -> rawequal")
local rawequal_entry = nil
for _, f in ipairs(funcs) do
    if f.name == "rawequal" and f.target then rawequal_entry = f end
end
if rawequal_entry then
    print("  writing +0x20: " .. hexval(type_orig) .. " -> " .. hexval(rawequal_entry.target))
    safe_wq(type_addr + 0x20, rawequal_entry.target)
    print("  MARKER_BEFORE_CALL")
    local ok, result = pcall(type, 42, 42)
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok) .. " result=" .. tostring(result))
    local ok2, result2 = pcall(type, 42, 99)
    print("  type(42,99) ok=" .. tostring(ok2) .. " result=" .. tostring(result2))
    -- Restore
    safe_wq(type_addr + 0x20, type_orig)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no rawequal target")
end

-- ============================================================
-- [E] Redirect type() -> select's C function
-- select(n, ...) returns the n-th through last args
-- ============================================================
print("")
print("[E] Redirect type() -> select")
local select_entry = nil
for _, f in ipairs(funcs) do
    if f.name == "select" and f.target then select_entry = f end
end
if select_entry then
    print("  writing +0x20: " .. hexval(type_orig) .. " -> " .. hexval(select_entry.target))
    safe_wq(type_addr + 0x20, select_entry.target)
    print("  MARKER_BEFORE_CALL")
    local ok, r1, r2, r3 = pcall(type, 1, "aaa", "bbb", "ccc")
    print("  MARKER_AFTER_CALL ok=" .. tostring(ok))
    print("  r1=" .. tostring(r1) .. " r2=" .. tostring(r2) .. " r3=" .. tostring(r3))
    -- Restore
    safe_wq(type_addr + 0x20, type_orig)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  SKIP: no select target")
end

-- ============================================================
-- [F] Cross-redirect: redirect pcall() -> type's C function
-- This tests redirecting a DIFFERENT function, not just type()
-- ============================================================
print("")
print("[F] Redirect pcall() -> type's original C function")
local pcall_entry = nil
for _, f in ipairs(funcs) do
    if f.name == "pcall" and f.addr then pcall_entry = f end
end
if pcall_entry then
    local pcall_orig = safe_rq(pcall_entry.addr + 0x20)
    print("  pcall orig +0x20: " .. hexval(pcall_orig))
    print("  writing pcall +0x20 -> type's C func: " .. hexval(type_orig))
    safe_wq(pcall_entry.addr + 0x20, type_orig)
    print("  MARKER_BEFORE_CALL")
    -- Now pcall(42) should behave like type(42) and return "number"
    -- But we can't use pcall to protect this since pcall IS what we modified
    -- Use a different error handler
    local saved_type = type  -- type is now the Lua-level wrapper, still pointing at type's CClosure
    local result = pcall(42)
    print("  MARKER_AFTER_CALL result=" .. tostring(result))
    -- Restore
    safe_wq(pcall_entry.addr + 0x20, pcall_orig)
    print("  restored")
else
    print("  SKIP: no pcall entry")
end

collectgarbage("restart")

print("")
print("=== PROBE 56a COMPLETE ===")
