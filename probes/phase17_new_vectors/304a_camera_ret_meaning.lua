-- CRASH_CLASS: LOW
-- PROBE 304a: what does 22 mean for the camera commands?
--
-- 300a: every 0x40040000..0x40040013 on /dev/camera returned 22 with a valid
-- page, -1 with null and -1 with an unmapped address, and wrote nothing. 22 is
-- EINVAL on FreeBSD, which a successful ioctl should not return, so this probe
-- puts the same call beside controls that are known:
--
--   FIOCLEX on camera        known to return 0 (267a)
--   a command in the same group the node does not own
--   the same camera command twice in a row
--   the camera command against /dev/zero, which has no such handler

print("=== PROBE 304a: CAMERA RETURN VALUE ===")

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
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_ioctl = make_syscall(54)
local page = memory.alloc(0x1000)

local function open_node(path, mode)
    return sgn(sc_open(uint64(put_str(path)), uint64(mode), uint64(0)))
end
local function io(fd, cmd, arg)
    return sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
end

local cam = open_node("/dev/camera", 2)
print(string.format("[open] /dev/camera O_RDWR fd=%d", cam))
if cam < 0 then print("=== DONE ===") return end

print(string.format("[FIOCLEX camera] ret=%d", io(cam, 0x20006601, uint64(0))))
print(string.format("[unowned 0x4004FFFF] ret=%d", io(cam, 0x4004FFFF, uint64(page))))
print(string.format("[0x40040000 #1] ret=%d", io(cam, 0x40040000, uint64(page))))
print(string.format("[0x40040000 #2] ret=%d", io(cam, 0x40040000, uint64(page))))
print(string.format("[0x40040013] ret=%d", io(cam, 0x40040013, uint64(page))))
print(string.format("[0x40040000 null] ret=%d", io(cam, 0x40040000, uint64(0))))
print(string.format("[0x40040000 page+4] ret=%d", io(cam, 0x40040000, uint64(page + 4))))

local zero = open_node("/dev/zero", 2)
print(string.format("[open] /dev/zero fd=%d", zero))
if zero >= 0 then
    print(string.format("[0x40040000 on zero] ret=%d", io(zero, 0x40040000, uint64(page))))
    print(string.format("[FIOCLEX zero] ret=%d", io(zero, 0x20006601, uint64(0))))
end

print("=== DONE ===")
