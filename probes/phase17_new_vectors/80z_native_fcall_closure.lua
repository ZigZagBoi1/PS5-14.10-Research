-- CRASH_CLASS: LOW
-- Inspect a candidate real CClosure in the loader's native syscall path.
-- Earlier captures establish that syscall.pipe.__call is Lua bytecode.
print("=== PROBE 80z: NATIVE FCALL CLOSURE ===")

if type(native) ~= "table" then
    print("native_table=" .. type(native))
    print("=== PROBE 80z COMPLETE ===")
    return
end
local f = native.fcall_with_rax
print("fcall_with_rax_type=" .. type(f))
if type(f) ~= "function" then
    print("=== PROBE 80z COMPLETE ===")
    return
end

local can_dump = pcall(string.dump, f)
print("lua_closure=" .. tostring(can_dump))
if can_dump then
    print("native.fcall_with_rax is Lua bytecode")
    print("=== PROBE 80z COMPLETE ===")
    return
end

local descriptor = tostring(f)
print("descriptor=" .. descriptor)
local address = descriptor:match("function:%s*(0x%x+)")
    or descriptor:match("function:%s*(%x+)")
if not address then
    print("ADDRESS PARSE FAILED")
    print("=== PROBE 80z COMPLETE ===")
    return
end
if not address:match("^0x") then address = "0x" .. address end
local closure = uint64(address)
print("closure=" .. address)
for _, offset in ipairs({0, 8, 16, 24, 32, 40, 48}) do
    local ok, value = pcall(function()
        return memory.read_qword(closure + offset)
    end)
    if ok then
        print(string.format("+0x%02X=%s", offset, tostring(value)))
    else
        print(string.format("+0x%02X=READ_FAILED", offset))
    end
end
print("=== PROBE 80z COMPLETE ===")
