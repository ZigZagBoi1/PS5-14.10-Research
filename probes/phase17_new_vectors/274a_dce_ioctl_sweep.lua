-- CRASH_CLASS: MODERATE
-- PROBE 274a: sweep the /dev/dce ioctl command space with three argument shapes
--
-- Context: /dev/dce is the one node proven to have its own d_ioctl - FIONBIO
-- returns 0 on zero/null/random and -1 on dce (268a), so the refusal is the
-- driver's, not VFS's. Every command tried so far (0x00-0xFF, two shapes) was
-- refused, which says the encoding is wrong, not that the driver is empty.
--
-- A BSD ioctl number is (inout << 30) | (group << 8) | number, so a sweep of
-- 0x0000..0xFFFF covers groups 0x00..0xFF with an 8-bit number and no length
-- bits. Three shapes are tried per command: a null argument, a zeroed page,
-- and a page whose first qword is the buffer length - the size-first request
-- struct shape Sony drivers use.
--
-- Anything that is not -1 is printed the moment it happens. If the driver
-- panics on a command the last progress line names the range, because the
-- process dies with the probe.

print("=== PROBE 274a: dce ioctl sweep ===")
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

local fd = sgn(sc_open(uint64(put_str("/dev/dce")), uint64(2), uint64(0)))
print("[0] open(/dev/dce, O_RDWR)=" .. fd)
if fd < 0 then
    print("[0] refused; nothing to sweep")
    return
end

local zero_page = memory.alloc(0x1000)
local size_page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do
    pcall(function() memory.write_dword(zero_page + off, 0) end)
    pcall(function() memory.write_dword(size_page + off, 0) end)
end
pcall(function() memory.write_qword(size_page, uint64(0x1000)) end)

local shapes = {
    { name = "null", arg = uint64(0) },
    { name = "zeropage", arg = uint64(zero_page) },
    { name = "sizefirst", arg = uint64(size_page) },
}

local interesting = 0
local total = 0
local TOP = 0x10000

for _, shape in ipairs(shapes) do
    print("")
    print("[A] shape=" .. shape.name .. " commands 0x0000..0xFFFF")
    for cmd = 0, TOP - 1 do
        local r = sc_ioctl(uint64(fd), uint64(cmd), shape.arg)
        local n = sgn(r)
        total = total + 1
        if n ~= -1 then
            interesting = interesting + 1
            if interesting <= 200 then
                print(string.format("    HIT shape=%-9s cmd=0x%04X ret=%d", shape.name, cmd, n))
            end
        end
        if cmd % 0x2000 == 0x1FFF then
            print(string.format("    progress %-9s 0x%04X  %d calls", shape.name, cmd, total))
        end
    end
    print(string.format("    shape=%-9s done, interesting so far %d", shape.name, interesting))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print(string.format("[B] total=%d interesting=%d", total, interesting))
if interesting == 0 then
    print("[B] every command in the space was refused with -1")
end
print("=== PROBE 274a COMPLETE ===")
