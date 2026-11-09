-- CRASH_CLASS: LOW
-- PROBE 86e: Safely enumerate upvalues of kernel.read_qword

print("=== PROBE 86e ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. to_num(syscall.getpid()))

-- Safe upvalue enumeration
print("--- kernel.read_qword upvalues ---")
for i = 1, 20 do
    local ok, name, val = pcall(function()
        return debug.getupvalue(kernel.read_qword, i)
    end)
    if not ok then
        print("up" .. i .. " pcall_fail")
        break
    end
    if not name then break end
    print("up" .. i .. ": " .. tostring(name) .. "=" .. type(val))
end

print("")
print("--- native.read_buffer upvalues ---")
for i = 1, 20 do
    local ok, name, val = pcall(function()
        return debug.getupvalue(native.read_buffer, i)
    end)
    if not ok then
        print("up" .. i .. " pcall_fail=" .. tostring(name))
        break
    end
    if not name then break end
    print("up" .. i .. ": " .. tostring(name) .. "=" .. type(val))
end

-- Check if native.read_buffer is C or Lua
print("")
print("--- NATIVE.READ_BUFFER TYPE ---")
local ok2, info = pcall(debug.getinfo, native.read_buffer, "S")
if ok2 and info then
    print("what=" .. tostring(info.what))
    print("source=" .. tostring(info.source))
end

-- Try reading kernel.lua source info
print("")
print("--- KERNEL.READ_QWORD SOURCE ---")
local ok3, info3 = pcall(debug.getinfo, kernel.read_qword, "SL")
if ok3 and info3 then
    print("source=" .. tostring(info3.source))
    print("what=" .. tostring(info3.what))
    print("line=" .. tostring(info3.linedefined))
    print("lastline=" .. tostring(info3.lastlinedefined))
end

-- Bytecode strings from kernel.read_qword
print("")
print("--- KERNEL.READ_QWORD BYTECODES ---")
local ok4, bc = pcall(string.dump, kernel.read_qword)
if ok4 then
    print("len=" .. #bc)
    local strs = {}
    for s in bc:gmatch("[%a_][%w_%.]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            print("  " .. s)
        end
    end
else
    print("not dumpable: " .. tostring(bc))
end

print("=== PROBE 86e COMPLETE ===")
