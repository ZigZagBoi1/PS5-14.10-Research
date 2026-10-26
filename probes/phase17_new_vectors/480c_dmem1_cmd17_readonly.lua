-- CRASH_CLASS: HIGH
-- PROBE 480c: does 0x80108017 fire on an O_RDONLY handle?
--
-- Every measured panic used an O_RDWR handle. 480b showed /dev/dmem2 opens
-- O_RDONLY as fd 23, so the mode is available to test. If the command still
-- panics here, the driver does not gate on write mode; if it returns -1, the
-- write-mode open is part of the trigger. Padding forces a flush so the capture
-- keeps the markers if the call panics.

print("=== PROBE 480c: dmem1 0x80108017 on O_RDONLY ===")
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
local fd = sgn(make_syscall(5)(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0)))
print("[1] open(/dev/dmem1, O_RDONLY)=" .. fd)
if fd < 0 then print("=== PROBE 480c COMPLETE (open refused) ==="); return end
print("[2] calling 0x80108017 on the read-only handle")
local ok, r = pcall(function() return make_syscall(54)(uint64(fd), uint64(0x80108017), uint64(page)) end)
print(string.format("[3] RETURNED ret=%d", ok and sgn(r) or -999))
print("=== PROBE 480c COMPLETE ===")
