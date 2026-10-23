-- CRASH_CLASS: MODERATE
-- PROBE 480a: is the dmem2 stop the open or the ioctl?
--
-- 479a's sweep issued 0x80108017 on /dev/dmem2 and received zero bytes before
-- the connection stopped answering. A blocked open and a blocked ioctl look
-- identical there, and the loader buffers its output, so nothing was flushed.
-- This probe sets stdout unbuffered and prints on both sides of the open and
-- both sides of the ioctl, so the last line names the blocked call.

io.stdout:setvbuf("no")
print("=== PROBE 480a: dmem2 0x80108017, where does it block ===")
print("")

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

print("[1] opening /dev/dmem2")
local fd = sgn(make_syscall(5)(uint64(put_str("/dev/dmem2")), uint64(2), uint64(0)))
print("[2] fd=" .. fd)
if fd < 0 then print("=== PROBE 480a COMPLETE (open refused) ==="); return end

print("[3] calling 0x80108017")
local ok, r = pcall(function() return make_syscall(54)(uint64(fd), uint64(0x80108017), uint64(page)) end)
print(string.format("[4] RETURNED ret=%d", ok and sgn(r) or -999))
pcall(function() make_syscall(6)(uint64(fd)) end)
print("=== PROBE 480a COMPLETE ===")
