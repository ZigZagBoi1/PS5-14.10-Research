-- CRASH_CLASS: LOW
-- PROBE 86d: Find how kernel.lua references read_buffer via upvalues
-- Then patch it to use native.read_buffer

print("=== PROBE 86d ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

print("pid=" .. to_num(syscall.getpid()))

-- Inspect upvalues of kernel.read_qword
print("--- UPVALUES of kernel.read_qword ---")
local i = 1
while true do
    local name, val = debug.getupvalue(kernel.read_qword, i)
    if not name then break end
    print(string.format("up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
    if type(val) == "table" then
        local c = 0
        for k, v in pairs(val) do
            c = c + 1
            if c <= 10 then
                print(string.format("  .%s = %s", tostring(k), tostring(v)))
            end
        end
        if c > 10 then print("  ... " .. c .. " total") end
    end
    i = i + 1
end

-- Also check kernel.write_qword
print("")
print("--- UPVALUES of kernel.write_qword ---")
i = 1
while true do
    local name, val = debug.getupvalue(kernel.write_qword, i)
    if not name then break end
    print(string.format("up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
    i = i + 1
end

-- Check kernel.read_byte
print("")
print("--- UPVALUES of kernel.read_byte ---")
i = 1
while true do
    local name, val = debug.getupvalue(kernel.read_byte, i)
    if not name then break end
    print(string.format("up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
    i = i + 1
end

-- Now try patching the upvalue
print("")
print("--- PATCHING ---")
i = 1
while true do
    local name, val = debug.getupvalue(kernel.read_qword, i)
    if not name then break end
    if name == "read_buffer" then
        print("found read_buffer at upvalue " .. i)
        debug.setupvalue(kernel.read_qword, i, native.read_buffer)
        print("patched!")
        -- Verify
        local name2, val2 = debug.getupvalue(kernel.read_qword, i)
        print("verify: " .. tostring(name2) .. " = " .. tostring(val2))
        break
    end
    i = i + 1
end

-- Also patch write_buffer for kernel.write_qword
i = 1
while true do
    local name, val = debug.getupvalue(kernel.write_qword, i)
    if not name then break end
    if name == "write_buffer" then
        print("found write_buffer at upvalue " .. i)
        debug.setupvalue(kernel.write_qword, i, native.write_buffer)
        print("patched write!")
        break
    end
    i = i + 1
end

-- Test kernel.read_qword after patching
print("")
print("--- TEST AFTER PATCH ---")
local test = memory.alloc(8)
memory.write_qword(test, uint64(0x0BADCAFE))
local ok, r = pcall(kernel.read_qword, test)
print("read_qword ok=" .. tostring(ok))
if ok then
    print("val=" .. tostring(r))
    local h, l = get_hi_lo(r)
    print(string.format("h=0x%08X l=0x%08X", h, l))
else
    print("err=" .. tostring(r):sub(1, 200))
end

-- Test write
local ok2, r2 = pcall(kernel.write_qword, test, uint64(0xCAFEBABE))
print("write_qword ok=" .. tostring(ok2))
if ok2 then
    local rb = memory.read_qword(test)
    print("readback=" .. tostring(rb))
else
    print("err=" .. tostring(r2):sub(1, 200))
end

print("=== PROBE 86d COMPLETE ===")
