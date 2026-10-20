-- CRASH_CLASS: LOW
-- PROBE 86f: Replace kernel.read/write functions with native versions
-- Since we can't patch upvalues, replace the whole function

print("=== PROBE 86f ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

print("pid=" .. to_num(syscall.getpid()))

-- Step 1: Test native.read_buffer signature more carefully
print("--- NATIVE.READ_BUFFER ---")
local buf = memory.alloc(16)
memory.write_dword(buf, 0xDEADBEEF)
memory.write_dword(buf + 4, 0xCAFEBABE)
memory.write_dword(buf + 8, 0x12345678)
memory.write_dword(buf + 12, 0xABCD0000)

-- Test: native.read_buffer(addr, size) -> string
local ok1, r1 = pcall(native.read_buffer, buf, 8)
print("(buf,8) ok=" .. tostring(ok1) .. " type=" .. type(r1))
if ok1 and type(r1) == "string" then
    print("len=" .. #r1)
    -- Parse as qword: little-endian
    local b = {r1:byte(1, 8)}
    local lo = b[1] + b[2]*256 + b[3]*65536 + b[4]*16777216
    local hi = b[5] + b[6]*256 + b[7]*65536 + b[8]*16777216
    print(string.format("parsed: h=0x%08X l=0x%08X", hi, lo))
end

-- Test with uint64 addr
local ok2, r2 = pcall(native.read_buffer, uint64(to_num(buf)), 8)
print("(u64,8) ok=" .. tostring(ok2) .. " type=" .. type(r2))

-- Step 2: Test native.write_buffer signature
print("")
print("--- NATIVE.WRITE_BUFFER ---")
local wbuf = memory.alloc(8)
local data = string.char(0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48)
local ok3, r3 = pcall(native.write_buffer, wbuf, data)
print("write ok=" .. tostring(ok3) .. " r=" .. tostring(r3))
if ok3 then
    local readback = to_num(memory.read_dword(wbuf))
    print(string.format("readback=0x%08X", readback))
end

-- Step 3: Replace kernel functions
print("")
print("--- REPLACING KERNEL FUNCTIONS ---")

-- New kernel.read_qword using native.read_buffer
kernel.read_qword = function(addr)
    local data = native.read_buffer(addr, 8)
    if not data or #data < 8 then return uint64(0) end
    local b = {data:byte(1, 8)}
    local lo = b[1] + b[2]*256 + b[3]*65536 + b[4]*16777216
    local hi = b[5] + b[6]*256 + b[7]*65536 + b[8]*16777216
    return uint64(string.format("0x%X%08X", hi, lo))
end

kernel.read_dword = function(addr)
    local data = native.read_buffer(addr, 4)
    if not data or #data < 4 then return 0 end
    local b = {data:byte(1, 4)}
    return b[1] + b[2]*256 + b[3]*65536 + b[4]*16777216
end

kernel.read_byte = function(addr)
    local data = native.read_buffer(addr, 1)
    if not data or #data < 1 then return 0 end
    return data:byte(1)
end

kernel.write_qword = function(addr, val)
    local h, l = get_hi_lo(val)
    local data = string.char(
        l % 256, math.floor(l/256) % 256, math.floor(l/65536) % 256, math.floor(l/16777216) % 256,
        h % 256, math.floor(h/256) % 256, math.floor(h/65536) % 256, math.floor(h/16777216) % 256
    )
    native.write_buffer(addr, data)
end

kernel.write_dword = function(addr, val)
    local v = to_num(val)
    local data = string.char(
        v % 256, math.floor(v/256) % 256, math.floor(v/65536) % 256, math.floor(v/16777216) % 256
    )
    native.write_buffer(addr, data)
end

print("replaced all kernel R/W functions")

-- Step 4: Test the replaced functions on heap memory
print("")
print("--- TEST REPLACED FUNCTIONS ---")
memory.write_qword(buf, uint64(0x0BADCAFE))
local ok4, r4 = pcall(kernel.read_qword, buf)
print("read_qword ok=" .. tostring(ok4) .. " val=" .. tostring(r4))
if ok4 then
    local h, l = get_hi_lo(r4)
    print(string.format("h=0x%08X l=0x%08X", h, l))
end

local ok5, r5 = pcall(kernel.read_dword, buf)
print("read_dword ok=" .. tostring(ok5) .. " val=" .. tostring(r5))

local ok6 = pcall(kernel.write_qword, buf, uint64(0x1234ABCD))
print("write_qword ok=" .. tostring(ok6))
if ok6 then
    local rb = memory.read_qword(buf)
    print("readback=" .. tostring(rb))
end

-- Step 5: Now try reading from a known module base (userland test)
print("")
print("--- MODULE BASE READ ---")
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(1), uint64(info))
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=" .. tostring(eboot_base))

-- Read first bytes from eboot via kernel.read_qword (should work since it's userland RX)
local ok7, r7 = pcall(kernel.read_qword, eboot_base)
print("eboot_read ok=" .. tostring(ok7) .. " val=" .. tostring(r7))

print("=== PROBE 86f COMPLETE ===")
