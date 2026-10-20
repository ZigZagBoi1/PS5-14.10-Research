-- CRASH_CLASS: LOW
-- PROBE 87e: Get FS base safely, read only small chunks with pcall

print("=== PROBE 87e ===")

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

-- Get FS base
local fsbase_buf = memory.alloc(8)
memory.write_qword(fsbase_buf, uint64(0))
local ok, ret = pcall(function()
    return make_syscall(165)(uint64(130), uint64(fsbase_buf))
end)
local fsbase = memory.read_qword(fsbase_buf)
print("fsbase=" .. tostring(fsbase))
print("ret=" .. tostring(ret))

-- Try to read just 8 bytes at FS base
local fh, fl = get_hi_lo(fsbase)
print(string.format("h=0x%X l=0x%X", fh, fl))

if fh ~= 0 or fl ~= 0 then
    -- Read 8 bytes at a time, pcall each
    for off = 0, 64, 8 do
        local addr = uint64(string.format("0x%X%08X", fh, fl + off))
        local ok2, data = pcall(native.read_buffer, addr, 8)
        if ok2 and data and #data >= 8 then
            local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(1,8)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            local tag = ""
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = " KPTR!" end
            print(string.format("+0x%02X: 0x%08X%08X%s", off, hi, lo, tag))
        else
            print(string.format("+0x%02X: FAIL", off))
            break
        end
    end
end

print("=== PROBE 87e COMPLETE ===")
