-- CRASH_CLASS: LOW
-- PROBE 300a: the camera driver's own commands
--
-- Context: 288a found /dev/camera answering 0x40040000 through 0x40040013,
-- which is the out direction, a 4-byte argument, group 0 and commands 0..0x13.
-- Group 0 is not one of the file layer's groups, so these are the camera
-- driver's own numbers.
--
-- 299a swept every group of the other open nodes and found nothing but
-- FIODTYPE; the camera node was still being swept when the run timed out, so
-- this probe goes straight at the twenty numbers 288a already identified.
--
-- Each is called with a zeroed page, then with a null argument, then with an
-- unmapped address, and the page is dumped after the first call to see what,
-- if anything, the driver writes back.

print("=== PROBE 300a: camera commands ===")
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
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local fd = sgn(sc_open(uint64(put_str("/dev/camera")), uint64(2), uint64(0)))
print(string.format("/dev/camera O_RDWR fd=%d", fd))
if fd < 0 then
    fd = sgn(sc_open(uint64(put_str("/dev/camera")), uint64(0), uint64(0)))
    print(string.format("/dev/camera O_RDONLY fd=%d", fd))
end
if fd < 0 then
    print("cannot open")
    print("=== PROBE 300a COMPLETE ===")
    return
end

local page = memory.alloc(0x1000)
local unmapped = uint64(string.format("0x%X%08X", 0x00000040, 0x00000000))

local function zero()
    for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end
end

for num = 0x00, 0x13 do
    local cmd = 0x40040000 + num
    zero()
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    local d0 = sgn(memory.read_dword(page))
    local d4 = sgn(memory.read_dword(page + 4))
    local rn = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(0)))
    local ru = sgn(sc_ioctl(uint64(fd), uint64(cmd), unmapped))
    print(string.format("0x%08X ret=%d page[0]=0x%08X page[4]=0x%08X null=%d unmapped=%d",
        cmd, r, d0, d4, rn, ru))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 300a COMPLETE ===")
