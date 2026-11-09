-- CRASH_CLASS: LOW
-- PROBE 88g: Detail dump of kernel pointers found in libkernel data

print("=== PROBE 88g ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

print("pid=" .. to_num(syscall.getpid()))

-- Get libkernel data section
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local data_lo = to_num(memory.read_dword(info + 0x118))
local data_hi = to_num(memory.read_dword(info + 0x11C))
local data_size = to_num(memory.read_dword(info + 0x120))
print(string.format("data=0x%X%08X size=0x%X", data_hi, data_lo, data_size))

-- Read the region around +0x3E00 to +0x4000 in detail
print("")
print("--- DETAIL DUMP +0x3E00 to +0x4000 ---")
for off = 0x3E00, 0x3FFC, 4 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 4)
    if not ok or not data or #data < 4 then break end
    local b1,b2,b3,b4 = data:byte(1,4)
    local val = b1+b2*256+b3*65536+b4*16777216
    if val ~= 0 then
        print(string.format("+0x%04X: 0x%08X", off, val))
    end
end

-- Also dump as qwords to see the pairing
print("")
print("--- QWORD VIEW +0x3E00 to +0x4000 ---")
for off = 0x3E00, 0x3FF8, 8 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 8)
    if not ok or not data or #data < 8 then break end
    local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(1,8)
    local lo = b1+b2*256+b3*65536+b4*16777216
    local hi = b5+b6*256+b7*65536+b8*16777216
    if hi ~= 0 or lo ~= 0 then
        local tag = ""
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = " <-- KPTR" end
        print(string.format("+0x%04X: hi=0x%08X lo=0x%08X%s", off, hi, lo, tag))
    end
end

-- Also scan +0x4000 to +0x5000 for more
print("")
print("--- SCAN +0x4000 to +0x5000 ---")
local kcount = 0
for off = 0x4000, 0x4FF8, 8 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 8)
    if not ok or not data or #data < 8 then
        print(string.format("BREAK +0x%X", off))
        break
    end
    local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(1,8)
    local lo = b1+b2*256+b3*65536+b4*16777216
    local hi = b5+b6*256+b7*65536+b8*16777216
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
        kcount = kcount + 1
        if kcount <= 20 then
            print(string.format("KPTR +0x%04X: hi=0x%08X lo=0x%08X", off, hi, lo))
        end
    end
end
print("kptr_4k_5k=" .. kcount)

print("=== PROBE 88g COMPLETE ===")
