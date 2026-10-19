-- CRASH_CLASS: MODERATE
-- PROBE 56c: Redirect functions NOT used internally by the Lua VM
--
-- Context: All writes to type()+0x20 hang because memory.write_dword
-- internally calls type() for argument validation. After the write lands,
-- the internal type() call dispatches to the wrong function.
--
-- Solution: redirect functions the VM never calls internally:
--   rawequal, rawget, rawlen, select, pairs
-- These are only called explicitly from Lua code, never by the VM itself.

print("=== PROBE 56c: REDIRECT NON-VM FUNCTIONS ===")
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

-- Get addresses
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)
local select_addr = parse_func_addr(select)
local tostring_addr = parse_func_addr(tostring)
local type_addr = parse_func_addr(type)

print("[INFO] Addresses:")
print("  rawequal: " .. hexval(rawequal_addr))
print("  rawget:   " .. hexval(rawget_addr))
print("  select:   " .. hexval(select_addr))
print("  tostring: " .. hexval(tostring_addr))
print("  type:     " .. hexval(type_addr))

if not rawequal_addr or not rawget_addr then
    print("ABORT: missing addresses")
    return
end

-- Read +0x20 targets
local rawequal_20_lo = safe_rd(rawequal_addr + 0x20)
local rawequal_20_hi = safe_rd(rawequal_addr + 0x24)
local rawget_20_lo = safe_rd(rawget_addr + 0x20)
local rawget_20_hi = safe_rd(rawget_addr + 0x24)
local select_20_lo = safe_rd(select_addr + 0x20)
local select_20_hi = safe_rd(select_addr + 0x24)
local tostring_20_lo = safe_rd(tostring_addr + 0x20)
local tostring_20_hi = safe_rd(tostring_addr + 0x24)
local type_20_lo = safe_rd(type_addr + 0x20)
local type_20_hi = safe_rd(type_addr + 0x24)

print(string.format("  rawequal +0x20: lo=0x%08X hi=0x%08X", rawequal_20_lo or 0, rawequal_20_hi or 0))
print(string.format("  rawget   +0x20: lo=0x%08X hi=0x%08X", rawget_20_lo or 0, rawget_20_hi or 0))
print(string.format("  select   +0x20: lo=0x%08X hi=0x%08X", select_20_lo or 0, select_20_hi or 0))
print(string.format("  tostring +0x20: lo=0x%08X hi=0x%08X", tostring_20_lo or 0, tostring_20_hi or 0))
print(string.format("  type     +0x20: lo=0x%08X hi=0x%08X", type_20_lo or 0, type_20_hi or 0))

collectgarbage("stop")

-- ============================================================
-- [A] Redirect rawequal() -> rawget's C function
-- rawequal(a,b) takes 2 args, returns bool
-- rawget(t,k) takes 2 args, returns value
-- Both take 2 args — compatible signatures
-- ============================================================
print("")
print("[A] Redirect rawequal -> rawget (2 args each)")
print("  Baseline rawequal(1,1) = " .. tostring(rawequal(1,1)))
print("  Baseline rawequal(1,2) = " .. tostring(rawequal(1,2)))
local test_table = {foo = "bar", [1] = "one", [2] = "two"}
print("  Baseline rawget(t,'foo') = " .. tostring(rawget(test_table, "foo")))
print("")
print("  MARKER_A_BEFORE_WRITE")
memory.write_dword(rawequal_addr + 0x20, rawget_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawget_20_hi)
print("  MARKER_A_AFTER_WRITE")
-- Now rawequal(t, k) should behave like rawget(t, k)
local a_result = rawequal(test_table, "foo")
print("  MARKER_A_AFTER_CALL")
print("  rawequal(t,'foo') = " .. tostring(a_result))
print("  expected: 'bar' (if redirected to rawget)")
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  MARKER_A_RESTORED")
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [B] Redirect rawget() -> type's C function
-- rawget(t,k) -> type(x): type takes 1 arg, rawget takes 2
-- But the C code just reads from the Lua stack, so it may work
-- ============================================================
print("")
print("[B] Redirect rawget -> type")
print("  MARKER_B_BEFORE_WRITE")
memory.write_dword(rawget_addr + 0x20, type_20_lo)
memory.write_dword(rawget_addr + 0x24, type_20_hi)
print("  MARKER_B_AFTER_WRITE")
-- rawget(42, "x") should behave like type(42) = "number"
local b_result = rawget(42, "x")
print("  MARKER_B_AFTER_CALL")
print("  rawget(42,'x') = " .. tostring(b_result))
print("  expected: 'number' (if redirected to type)")
-- Restore
memory.write_dword(rawget_addr + 0x20, rawget_20_lo)
memory.write_dword(rawget_addr + 0x24, rawget_20_hi)
print("  MARKER_B_RESTORED")
print("  verify rawget(t,'foo') = " .. tostring(rawget(test_table, "foo")))

-- ============================================================
-- [C] Redirect select() -> tostring's C function
-- select(1, ...) -> tostring(x)
-- ============================================================
print("")
print("[C] Redirect select -> tostring")
print("  Baseline select(1,'a','b') = " .. tostring(select(1, "a", "b")))
print("  MARKER_C_BEFORE_WRITE")
memory.write_dword(select_addr + 0x20, tostring_20_lo)
memory.write_dword(select_addr + 0x24, tostring_20_hi)
print("  MARKER_C_AFTER_WRITE")
-- select(42) should behave like tostring(42) = "42"
local c_result = select(42)
print("  MARKER_C_AFTER_CALL")
print("  select(42) = " .. tostring(c_result))
print("  expected: '42' (if redirected to tostring)")
-- Restore
memory.write_dword(select_addr + 0x20, select_20_lo)
memory.write_dword(select_addr + 0x24, select_20_hi)
print("  MARKER_C_RESTORED")
print("  verify select(1,'a','b') = " .. tostring(select(1, "a", "b")))

-- ============================================================
-- [D] Redirect rawequal() -> tostring's C function
-- Test cross-function redirect with different arg count
-- ============================================================
print("")
print("[D] Redirect rawequal -> tostring")
print("  MARKER_D_BEFORE_WRITE")
memory.write_dword(rawequal_addr + 0x20, tostring_20_lo)
memory.write_dword(rawequal_addr + 0x24, tostring_20_hi)
print("  MARKER_D_AFTER_WRITE")
-- rawequal(42) should behave like tostring(42) = "42"
local d_result = rawequal(42)
print("  MARKER_D_AFTER_CALL")
print("  rawequal(42) = " .. tostring(d_result))
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  MARKER_D_RESTORED")
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [E] Write+restore rawequal+0x20 with NO call (timing test)
-- ============================================================
print("")
print("[E] 10 write+restore cycles on rawequal+0x20 (no calls)")
local t0 = os.clock()
for i = 1, 10 do
    memory.write_dword(rawequal_addr + 0x20, rawget_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawget_20_hi)
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
end
local t1 = os.clock()
print(string.format("  10 cycles: %.4fs (%.4fs each)", t1 - t0, (t1 - t0) / 10))
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

collectgarbage("restart")

print("")
print("=== PROBE 56c COMPLETE ===")
