-- CRASH_CLASS: LOW
-- Check the output position of syscall 601 cmd 0x00 without changing state.
-- The retained 13.60 handler copies eight bytes to syscall arg2, not arg3.

print("=== PROBE 83c: sys601 cmd0 output position ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u64(v)
    if type(v) == "number" then
        if v < 0 then v = v + 0x100000000 end
        return uint64(string.format("0x%08X", v))
    end
    return v or uint64("0x00000000")
end
local function call(n, a, b, c)
    local ok, rv = pcall(function()
        return make_syscall(n)(u64(a), u64(b), u64(c), u64(0), u64(0), u64(0))
    end)
    if not ok then print("call_error=" .. tostring(rv)); return nil end
    return to_num(rv)
end
local function fill(p)
    memory.write_dword(p, 0xA5A5A5A5)
    memory.write_dword(p + 4, 0xA5A5A5A5)
end
local function show(label, p)
    local v = memory.read_qword(p)
    local h = (type(v) == "table" and v.h) or 0
    local l = (type(v) == "table" and v.l) or to_num(v)
    print(string.format("%s=0x%08X_%08X", label, h, l))
end

local arg2 = memory.alloc(16)
local arg3 = memory.alloc(16)
fill(arg2); fill(arg3)
print("pid=" .. tostring(call(20)))
print("cmd0_rv=" .. tostring(call(601, 0, arg2, arg3)))
show("arg2_after", arg2)
show("arg3_after", arg3)

-- Discriminating control: if the output really goes to arg2, a null arg2
-- should fail even when arg3 is a valid writable buffer.
fill(arg3)
print("cmd0_null_arg2_rv=" .. tostring(call(601, 0, 0, arg3)))
show("arg3_after_null_arg2", arg3)
print("canary_pid=" .. tostring(call(20)))
print("=== PROBE 83c COMPLETE ===")
