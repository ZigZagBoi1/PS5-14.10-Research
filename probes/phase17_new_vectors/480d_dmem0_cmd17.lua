-- CRASH_CLASS: HIGH
-- PROBE 480d: does /dev/dmem0 answer 0x80108017 the way dmem1 does?
--
-- dmem0 refused the readable half (0x4008800A returned -1) while dmem1 and
-- dmem2 answered it, so the three nodes are not one cdev. This probe issues the
-- fatal write-group command on dmem0 to see whether the panic is a property of
-- the driver family or of dmem1/dmem2 alone.

print("=== PROBE 480d: dmem0 0x80108017 ===")
for i = 1, 200 do
    print(string.rep("pad ", 10) .. tostring(i))
end

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local page = memory.alloc(0x100)
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local fd = sgn(make_syscall(5)(uint64(put_str("/dev/dmem0")), uint64(2), uint64(0)))
print("[1] open(/dev/dmem0, O_RDWR)=" .. fd)
if fd < 0 then print("=== PROBE 480d COMPLETE (open refused) ==="); return end
print("[2] calling 0x80108017")
local ok, r = pcall(function() return make_syscall(54)(uint64(fd), uint64(0x80108017), uint64(page)) end)
print(string.format("[3] RETURNED ret=%d", ok and sgn(r) or -999))
print("=== PROBE 480d COMPLETE ===")
