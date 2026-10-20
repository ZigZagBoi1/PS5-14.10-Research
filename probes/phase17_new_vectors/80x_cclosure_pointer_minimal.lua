-- CRASH_CLASS: LOW
-- Read-only classification of the syscall pipe __call closure layout.
-- Kept separate from 80u's broad memory scan so a failed or slow scan
-- cannot obscure the first address observation after loader recovery.
print("=== PROBE 80x: CCLOSURE POINTER MINIMAL ===")

if type(syscall) ~= "table" or type(syscall.pipe) ~= "table" then
    print("NO SYSCALL PIPE")
    print("=== PROBE 80x COMPLETE ===")
    return
end
local mt = getmetatable(syscall.pipe)
if type(mt) ~= "table" or type(mt.__call) ~= "function" then
    print("NO CALL CLOSURE")
    print("=== PROBE 80x COMPLETE ===")
    return
end

local descriptor = tostring(mt.__call)
print("descriptor=" .. descriptor)
local is_lua = pcall(string.dump, mt.__call)
print("lua_closure=" .. tostring(is_lua))
if is_lua then
    print("__call is Lua bytecode; +0x20 is not a C function pointer")
    print("=== PROBE 80x COMPLETE ===")
    return
end
local address = descriptor:match("function:%s*(0x%x+)")
    or descriptor:match("function:%s*(%x+)")
if not address then
    print("ADDRESS PARSE FAILED")
    print("=== PROBE 80x COMPLETE ===")
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
print("=== PROBE 80x COMPLETE ===")
