-- CRASH_CLASS: MODERATE
-- PROBE 288a: which ioctl groups the USB and input nodes answer
--
-- Context: the 278a sweep called 0x0000..0xFFFF on every node, which only
-- covers group 0 with length 0. The /dev/gc table was found at group 0x81 with
-- lengths up to 0x888, so a node whose driver declares its commands with a
-- length or a group the sweep never set would look dead.
--
-- The USB stack matters because it is the one kernel path that parses
-- attacker-supplied bytes without a code-execution prerequisite: a device
-- descriptor, a SCSI reply and a filesystem image all reach kernel parsers
-- because the device was plugged in. FreeBSD's usb ioctls live in group 'U'
-- (0x55), which the 16-bit sweep could only have hit with a zero length.
--
-- This probe walks every group 0x00..0xFF at five lengths and four
-- directions, on the nodes that would carry a USB or input stack:
--
--   usb, usbctl, ugen0.2, camera, hid, bt, hmd_cmd, notification0

print("=== PROBE 288a: node ioctl groups ===")
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

local page = memory.alloc(0x4000)
for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(page + off, 0xAAAAAAAA) end) end
local arg = uint64(page)

local nodes = { "usb", "usbctl", "ugen0.2", "camera", "hid", "bt", "hmd_cmd", "notification0" }
local dirs = { 0x40000000, 0x80000000, 0xC0000000, 0x20000000 }
local lens = { 0, 4, 8, 0x10, 0x30, 0x100 }

for _, node in ipairs(nodes) do
    local path = "/dev/" .. node
    local fd = sgn(sc_open(uint64(put_str(path)), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(put_str(path)), uint64(0), uint64(0))) end
    print(string.format("[%s] open=%d", node, fd))
    if fd >= 0 then
        local hits = 0
        for _, d in ipairs(dirs) do
            for _, len in ipairs(lens) do
                local base = d + len * 0x10000
                for group = 0, 0xFF do
                    local gbase = base + group * 0x100
                    for num = 0, 0xFF do
                        local cmd = gbase + num
                        local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
                        if r ~= -1 then
                            hits = hits + 1
                            if hits <= 20 then
                                print(string.format("    HIT 0x%08X -> %d", cmd, r))
                            end
                        end
                    end
                end
                print(string.format("    dir=0x%08X len=0x%03X done hits=%d", d, len, hits))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 288a COMPLETE ===")
