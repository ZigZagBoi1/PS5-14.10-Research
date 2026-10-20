-- CRASH_CLASS: LOW
-- PROBE 86g: Minimal native.read/write_buffer test

print("=== PROBE 86g ===")
print("S1")

local buf = memory.alloc(16)
memory.write_dword(buf, 0xDEADBEEF)
memory.write_dword(buf + 4, 0xCAFEBABE)
print("S2")

-- Test read
local ok, r = pcall(native.read_buffer, buf, 8)
print("read ok=" .. tostring(ok))
if ok and type(r) == "string" then
    print("len=" .. #r)
    for i = 1, #r do
        io.write(string.format("%02X ", r:byte(i)))
    end
    print("")
end
print("S3")

-- Test write
local wdata = string.char(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
local ok2, r2 = pcall(native.write_buffer, buf, wdata)
print("write ok=" .. tostring(ok2) .. " r=" .. tostring(r2))
print("S4")

-- Verify write
local v1 = memory.read_dword(buf)
local v2 = memory.read_dword(buf + 4)
print("v1=" .. tostring(v1))
print("v2=" .. tostring(v2))
print("S5")

-- Replace kernel.read_qword
kernel.read_qword = function(addr)
    local data = native.read_buffer(addr, 8)
    if not data or #data < 8 then return uint64(0) end
    local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(1, 8)
    local lo = b1 + b2*256 + b3*65536 + b4*16777216
    local hi = b5 + b6*256 + b7*65536 + b8*16777216
    return uint64(string.format("0x%X%08X", hi, lo))
end
print("S6 replaced")

-- Test
memory.write_qword(buf, uint64(0x0BADCAFE))
local ok3, r3 = pcall(kernel.read_qword, buf)
print("test ok=" .. tostring(ok3) .. " r=" .. tostring(r3))

print("=== PROBE 86g COMPLETE ===")
