-- CRASH_CLASS: LOW
-- PROBE 87f: Deep scan libkernel data section for kernel pointers
-- Use native.read_buffer to scan entire data segment

print("=== PROBE 87f ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Get libkernel info (handle 0x2001)
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local text_size = to_num(memory.read_dword(info + 0x110))
local data_lo = to_num(memory.read_dword(info + 0x118))
local data_hi = to_num(memory.read_dword(info + 0x11C))
local data_size = to_num(memory.read_dword(info + 0x120))

print(string.format("text=0x%X%08X size=0x%X", text_hi, text_lo, text_size))
print(string.format("data=0x%X%08X size=0x%X", data_hi, data_lo, data_size))

-- Scan data section for kernel pointers
local data_addr = uint64(string.format("0x%X%08X", data_hi, data_lo))
local scan_size = math.min(data_size, 0x4000) -- 16KB max
print("scanning " .. scan_size .. " bytes of data section")

local kptrs = {}
local chunk_size = 256
for chunk_off = 0, scan_size - 1, chunk_size do
    local remaining = math.min(chunk_size, scan_size - chunk_off)
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + chunk_off))
    local ok, data = pcall(native.read_buffer, addr, remaining)
    if ok and data and #data >= 8 then
        for i = 1, #data - 7, 8 do
            local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i, i+7)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                kptrs[#kptrs+1] = {off=chunk_off+i-1, hi=hi, lo=lo}
            end
        end
    elseif not ok then
        print(string.format("chunk 0x%X fail", chunk_off))
        break
    end
end

print("kptr_count=" .. #kptrs)
for i, p in ipairs(kptrs) do
    if i <= 20 then
        print(string.format("  data+0x%04X: 0x%08X%08X", p.off, p.hi, p.lo))
    end
end

-- Also scan eboot data section
print("")
print("--- EBOOT DATA ---")
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0), uint64(info))
local edata_lo = to_num(memory.read_dword(info + 0x118))
local edata_hi = to_num(memory.read_dword(info + 0x11C))
local edata_size = to_num(memory.read_dword(info + 0x120))
print(string.format("eboot_data=0x%X%08X size=0x%X", edata_hi, edata_lo, edata_size))

local ekptrs = {}
local escan = math.min(edata_size, 0x4000)
for chunk_off = 0, escan - 1, chunk_size do
    local remaining = math.min(chunk_size, escan - chunk_off)
    local addr = uint64(string.format("0x%X%08X", edata_hi, edata_lo + chunk_off))
    local ok, data = pcall(native.read_buffer, addr, remaining)
    if ok and data and #data >= 8 then
        for i = 1, #data - 7, 8 do
            local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i, i+7)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                ekptrs[#ekptrs+1] = {off=chunk_off+i-1, hi=hi, lo=lo}
            end
        end
    elseif not ok then
        break
    end
end
print("eboot_kptr_count=" .. #ekptrs)
for i, p in ipairs(ekptrs) do
    if i <= 10 then
        print(string.format("  edata+0x%04X: 0x%08X%08X", p.off, p.hi, p.lo))
    end
end

print("=== PROBE 87f COMPLETE ===")
