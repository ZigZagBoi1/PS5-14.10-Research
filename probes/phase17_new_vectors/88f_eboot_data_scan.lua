-- CRASH_CLASS: LOW
-- PROBE 88f: Scan eboot data section for kernel pointers

print("=== PROBE 88f ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

print("pid=" .. to_num(syscall.getpid()))

-- Get eboot data section
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0), uint64(info))
local edata_lo = to_num(memory.read_dword(info + 0x118))
local edata_hi = to_num(memory.read_dword(info + 0x11C))
local edata_size = to_num(memory.read_dword(info + 0x120))
print(string.format("edata=0x%X%08X size=0x%X", edata_hi, edata_lo, edata_size))

-- Scan in 64-byte chunks, print progress every 1KB
local kcount = 0
local scan = math.min(edata_size, 0x4000) -- 16KB max
print("scanning " .. scan .. " bytes")

for off = 0, scan - 1, 64 do
    local addr = uint64(string.format("0x%X%08X", edata_hi, edata_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 64)
    if not ok or not data then
        print(string.format("BREAK +0x%X", off))
        break
    end
    for i = 1, #data - 7, 8 do
        local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
        local lo = b1+b2*256+b3*65536+b4*16777216
        local hi = b5+b6*256+b7*65536+b8*16777216
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            kcount = kcount + 1
            if kcount <= 20 then
                print(string.format("KPTR +0x%04X: 0x%08X%08X", off+i-1, hi, lo))
            end
        end
    end
    if off % 0x400 == 0 and off > 0 then
        print(string.format("progress: +0x%X kptr=%d", off, kcount))
    end
end
print("total_kptr=" .. kcount)

-- Also scan deeper into libkernel data (8KB-16KB)
print("")
print("--- LIBKERNEL 8K-16K ---")
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local ldata_lo = to_num(memory.read_dword(info + 0x118))
local ldata_hi = to_num(memory.read_dword(info + 0x11C))
local ldata_size = to_num(memory.read_dword(info + 0x120))
print(string.format("lkdata=0x%X%08X size=0x%X", ldata_hi, ldata_lo, ldata_size))

local lkcount = 0
local lscan_start = 0x2000
local lscan_end = math.min(ldata_size, 0x4000)
for off = lscan_start, lscan_end - 1, 64 do
    local addr = uint64(string.format("0x%X%08X", ldata_hi, ldata_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 64)
    if not ok or not data then
        print(string.format("LK BREAK +0x%X", off))
        break
    end
    for i = 1, #data - 7, 8 do
        local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
        local lo = b1+b2*256+b3*65536+b4*16777216
        local hi = b5+b6*256+b7*65536+b8*16777216
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            lkcount = lkcount + 1
            if lkcount <= 10 then
                print(string.format("LK_KPTR +0x%04X: 0x%08X%08X", off+i-1, hi, lo))
            end
        end
    end
end
print("lk_kptr=" .. lkcount)

print("=== PROBE 88f COMPLETE ===")
