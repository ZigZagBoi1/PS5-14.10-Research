-- CRASH_CLASS: LOW
-- PROBE 88a: Check storage for saved kernel_rw + deep data scan

print("=== PROBE 88a ===")

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

-- PART A: Check storage for saved kernel_rw
print("--- STORAGE CHECK ---")
local has_storage = type(storage) == "table"
print("storage exists: " .. tostring(has_storage))
if has_storage then
    local ok1, krw = pcall(storage.get, "kernel_rw")
    print("storage.get ok=" .. tostring(ok1))
    if ok1 and krw then
        print("kernel_rw type=" .. type(krw))
        if type(krw) == "table" then
            for k, v in pairs(krw) do
                print("  " .. tostring(k) .. "=" .. tostring(v))
            end
        else
            print("  value=" .. tostring(krw))
        end
    else
        print("kernel_rw=nil (no saved state)")
    end
    -- List all storage keys
    local ok2, keys = pcall(storage.list)
    if ok2 and keys then
        print("storage keys:")
        if type(keys) == "table" then
            for k, v in pairs(keys) do
                print("  " .. tostring(k) .. "=" .. tostring(v))
            end
        end
    end
    -- Try other possible keys
    for _, key in ipairs({"exploit", "kbase", "kernel_base", "allproc", "pipe_addr"}) do
        local ok3, val = pcall(storage.get, key)
        if ok3 and val ~= nil then
            print("storage[" .. key .. "]=" .. tostring(val))
        end
    end
end

-- PART B: Scan deeper into libkernel data (skip first 2KB already scanned)
print("")
print("--- LIBKERNEL DEEP ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local data_lo = to_num(memory.read_dword(info + 0x118))
local data_hi = to_num(memory.read_dword(info + 0x11C))
local data_size = to_num(memory.read_dword(info + 0x120))
print(string.format("data=0x%X%08X size=0x%X", data_hi, data_lo, data_size))

-- Scan 2KB-8KB range
local kcount = 0
for off = 0x800, math.min(data_size, 0x2000) - 1, 64 do
    local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
    local ok, data2 = pcall(native.read_buffer, addr, 64)
    if not ok or not data2 then
        print(string.format("BREAK at +0x%X", off))
        break
    end
    for i = 1, #data2 - 7, 8 do
        local b1,b2,b3,b4,b5,b6,b7,b8 = data2:byte(i,i+7)
        local lo2 = b1+b2*256+b3*65536+b4*16777216
        local hi2 = b5+b6*256+b7*65536+b8*16777216
        if hi2 >= 0xFFFF8000 and hi2 < 0xFFFFFFFF then
            kcount = kcount + 1
            if kcount <= 10 then
                print(string.format("KPTR +0x%04X: 0x%08X%08X", off+i-1, hi2, lo2))
            end
        end
    end
end
print("kptr_2k_8k=" .. kcount)

-- PART C: Scan eboot data section
print("")
print("--- EBOOT DATA ---")
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0), uint64(info))
local edata_lo = to_num(memory.read_dword(info + 0x118))
local edata_hi = to_num(memory.read_dword(info + 0x11C))
local edata_size = to_num(memory.read_dword(info + 0x120))
print(string.format("edata=0x%X%08X size=0x%X", edata_hi, edata_lo, edata_size))

local ekcount = 0
for off = 0, math.min(edata_size, 0x4000) - 1, 64 do
    local addr = uint64(string.format("0x%X%08X", edata_hi, edata_lo + off))
    local ok, data2 = pcall(native.read_buffer, addr, 64)
    if not ok or not data2 then
        print(string.format("EBREAK at +0x%X", off))
        break
    end
    for i = 1, #data2 - 7, 8 do
        local b1,b2,b3,b4,b5,b6,b7,b8 = data2:byte(i,i+7)
        local lo2 = b1+b2*256+b3*65536+b4*16777216
        local hi2 = b5+b6*256+b7*65536+b8*16777216
        if hi2 >= 0xFFFF8000 and hi2 < 0xFFFFFFFF then
            ekcount = ekcount + 1
            if ekcount <= 10 then
                print(string.format("EKPTR +0x%04X: 0x%08X%08X", off+i-1, hi2, lo2))
            end
        end
    end
end
print("eboot_kptr=" .. ekcount)

-- PART D: Check ipv6_kernel_rw table contents
print("")
print("--- IPV6_KERNEL_RW ---")
if type(ipv6_kernel_rw) == "table" then
    for k, v in pairs(ipv6_kernel_rw) do
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
    if type(ipv6_kernel_rw.data) == "table" then
        print("ipv6_kernel_rw.data:")
        for k, v in pairs(ipv6_kernel_rw.data) do
            print("  " .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

-- PART E: Check kernel.addr
print("")
print("--- KERNEL.ADDR ---")
if type(kernel) == "table" and type(kernel.addr) == "table" then
    local cnt = 0
    for k, v in pairs(kernel.addr) do
        cnt = cnt + 1
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
    print("addr_count=" .. cnt)
end

print("=== PROBE 88a COMPLETE ===")
