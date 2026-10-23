-- CRASH_CLASS: MODERATE
-- PROBE 471b: the full 32-bit ioctl encoding space on /dev/gic
--
-- Context: 274a swept 0x0000..0xFFFF - groups 0x00..0xFF, eight-bit number, no
-- direction or length bits - with three argument shapes, and every one of the
-- 196 608 calls returned -1. A BSD ioctl number carries the direction in bits
-- 30-31 and the size in bits 16-28, so a driver that checks full 32-bit
-- constants (the encrypt service uses 0xC0104401) is invisible to that sweep.
--
-- This probe crosses the five direction values with nine lengths and the whole
-- 0x0000..0xFFFF group/number space, with a zeroed 0x1000 page as the argument
-- so a copyin of any tested length can succeed.
--
--   directions {0x00000000, 0x20000000, 0x40000000, 0x80000000, 0xC0000000}
--   lengths    {0, 4, 8, 0x10, 0x18, 0x20, 0x40, 0x100, 0x1000}
--   group/num  0x0000..0xFFFF
--
-- 2 949 120 calls, about a minute at the rate 274a measured. Anything that is
-- not -1 is printed immediately; a crash leaves the last progress line naming
-- the direction and length that was being swept.

print("=== PROBE 471b: gic full encoding space ===")
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

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("[0] open(/dev/gic, O_RDWR)=" .. fd)
if fd < 0 then
    print("[0] refused; nothing to sweep")
    return
end

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local dirs = { 0x00000000, 0x20000000, 0x40000000, 0x80000000, 0xC0000000 }
local lens = { 0, 4, 8, 0x10, 0x18, 0x20, 0x40, 0x100, 0x1000 }

local interesting = 0
local total = 0
local TOP = 0x10000

for _, d in ipairs(dirs) do
    for _, len in ipairs(lens) do
        local base = d + (len * 0x10000)
        print(string.format("[A] dir=0x%08X len=0x%X base=0x%08X", d, len, base))
        for g = 0, TOP - 1 do
            local cmd = base + g
            local r = sc_ioctl(uint64(fd), uint64(cmd), arg)
            local n = sgn(r)
            total = total + 1
            if n ~= -1 then
                interesting = interesting + 1
                if interesting <= 200 then
                    print(string.format("    HIT cmd=0x%08X ret=%d", cmd, n))
                end
            end
            if g % 0x4000 == 0x3FFF then
                print(string.format("    progress dir=0x%08X len=0x%X 0x%04X  %d calls", d, len, g, total))
            end
        end
    end
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print(string.format("[B] total=%d interesting=%d", total, interesting))
if interesting == 0 then
    print("[B] the whole encoding space was refused with -1")
end
print("=== PROBE 471b COMPLETE ===")
