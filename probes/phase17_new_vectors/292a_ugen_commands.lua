-- CRASH_CLASS: MODERATE
-- PROBE 292a: what the USB generic device answers
--
-- Context: 288a swept every ioctl group on eight nodes. The USB nodes were the
-- only ones that answered driver commands at all:
--
--   /dev/usb     generic file commands only
--   /dev/usbctl  0x40045594, 0x200055C9, 0x200055CA
--   /dev/ugen0.2 twenty group-0x55 commands, among them 0x80045506,
--                0x80045565, 0x80045571..0x8004557D, 0x80045580,
--                0x80045588, 0x80045589, and 0x40045564 / 0x40045575 /
--                0x40045587 / 0x4004558B / 0x40045592
--
-- Group 0x55 is 'U' in FreeBSD's ioctl numbering, which is the USB stack
-- itself (USB_GET_DEVICEINFO, USB_GET_DEVICE_DESC, USB_SET_ALT_IFACE and the
-- bus-control entry points). 0x40045564 decodes as _IOW('U', 0x64, 4), and
-- USB_DO_ATTACH is _IOW('U', 100, struct usb_attach_arg) in FreeBSD's usb.h -
-- the entry point that takes bus and device pointers from its argument.
--
-- Every one of these returned 0 to a page filled with 0xAA, which is either a
-- handler that ignored the argument or something that is not what its number
-- says. This probe calls each one with a zeroed page and dumps what came back.
--
-- Nothing here is known to be reachable for a game process; the point is to
-- find out what the USB stack lets us read or set.

print("=== PROBE 292a: ugen commands ===")
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
local function hexdump(addr, n)
    local out = {}
    for row = 0, math.floor((n - 1) / 16) do
        local line = string.format("    %04X  ", row * 16)
        local ascii = ""
        for col = 0, 15 do
            local b = 0
            pcall(function() b = to_num(memory.read_byte(addr + row * 16 + col)) end)
            line = line .. string.format("%02X ", b)
            ascii = ascii .. (b >= 32 and b < 127 and string.char(b) or ".")
        end
        out[#out + 1] = line .. " " .. ascii
    end
    return table.concat(out, "\n")
end
local function nonzero(addr, n)
    for i = 0, n - 1 do
        local b = 0
        pcall(function() b = to_num(memory.read_byte(addr + i)) end)
        if b ~= 0 then return true end
    end
    return false
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x4000)

local nodes = { "ugen0.2", "usbctl", "usb" }
local cmds = {
    0x80045506, 0x80045565, 0x80045571, 0x80045572, 0x80045576,
    0x80045577, 0x80045578, 0x8004557A, 0x8004557B, 0x8004557C,
    0x8004557D, 0x80045580, 0x80045588, 0x80045589,
    0x40045564, 0x40045575, 0x40045587, 0x4004558B, 0x40045592,
    0x40045594, 0x200055C9, 0x200055CA,
    0x80045501, 0x80045502, 0x80045503, 0x80045504, 0x80045505,
    0x80045507, 0x80045508, 0xC0045506,
}

for _, node in ipairs(nodes) do
    local path = "/dev/" .. node
    local fd = sgn(sc_open(uint64(put_str(path)), uint64(2), uint64(0)))
    print(string.format("[%s] open=%d", node, fd))
    if fd >= 0 then
        for _, cmd in ipairs(cmds) do
            for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
            local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
            local note = ""
            if r == 0 then
                if nonzero(page, 0x100) then
                    note = " wrote"
                else
                    note = " empty"
                end
            end
            print(string.format("    0x%08X -> %d%s", cmd, r, note))
            if r == 0 and nonzero(page, 0x100) then
                print(hexdump(page, 64))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 292a COMPLETE ===")
