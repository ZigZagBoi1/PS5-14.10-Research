-- CRASH_CLASS: LOW
-- PROBE 87g: Quick data section scan, small chunks, safe

print("=== PROBE 87g ===")

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

-- Get libkernel (handle 0x2001)
print("--- LIBKERNEL ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local ok, ret = pcall(function()
    return make_syscall(593)(uint64(0x2001), uint64(info))
end)
print("593 ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

local data_lo = to_num(memory.read_dword(info + 0x118))
local data_hi = to_num(memory.read_dword(info + 0x11C))
local data_size = to_num(memory.read_dword(info + 0x120))
print(string.format("data=0x%X%08X size=0x%X", data_hi, data_lo, data_size))

-- Only scan first 2KB in 64-byte chunks
if data_size > 0 and (data_hi ~= 0 or data_lo ~= 0) then
    local scan = math.min(data_size, 0x800)
    local kcount = 0
    for off = 0, scan - 1, 64 do
        local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
        local ok2, data2 = pcall(native.read_buffer, addr, 64)
        if not ok2 or not data2 then break end
        for i = 1, #data2 - 7, 8 do
            local b1,b2,b3,b4,b5,b6,b7,b8 = data2:byte(i,i+7)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                kcount = kcount + 1
                if kcount <= 10 then
                    print(string.format("KPTR +0x%04X: 0x%08X%08X", off+i-1, hi, lo))
                end
            end
        end
    end
    print("kptr_total=" .. kcount)
else
    print("no data section")
    -- Maybe handle is wrong, try handle 1
    print("trying handle 1")
    memory.write_dword(info, 0x160)
    make_syscall(593)(uint64(1), uint64(info))
    data_lo = to_num(memory.read_dword(info + 0x118))
    data_hi = to_num(memory.read_dword(info + 0x11C))
    data_size = to_num(memory.read_dword(info + 0x120))
    print(string.format("h1 data=0x%X%08X size=0x%X", data_hi, data_lo, data_size))
end

print("=== PROBE 87g COMPLETE ===")
