-- CRASH_CLASS: HIGH
-- PROBE 284a: complete the /dev/gc table over the whole length field
--
-- Context: every sweep so far fixed the length field to a short list
-- (0, 4, 8, 0x10, 0x20, 0x40, 0x100). The ioctl encoding carries fourteen
-- bits of length, so a driver command declared with any other size - a struct
-- of 0x18, 0x30, 0x200 bytes - was never called. The table found so far has
-- twenty commands in group 0x81, and they all copy a small struct and ignore
-- its contents as pointers.
--
-- This probe calls group 0x81 over length 0..0x7FF in all four directions,
-- 2,097,152 calls, and prints a line for each length block only when a
-- command answers. Any command outside that set would be new.
--
-- 0xC0048125 is inside the swept space and hung twice; if the run stops, the
-- last printed length block bounds where.

print("=== PROBE 284a: gc full length field ===")
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

local fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(0), uint64(0))) end
print("[0] open(/dev/gc)=" .. fd)
if fd < 0 then return end

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0xAAAAAAAA) end) end
local arg = uint64(page)

local dirs = { 0x20000000, 0x40000000, 0x80000000, 0xC0000000 }
local hits = 0

print("")
print("[A] length 0x000..0x7FF, group 0x81")
for _, d in ipairs(dirs) do
    for len = 0, 0x7FF do
        local base = d + len * 0x10000 + 0x8100
        print(string.format("    LEN 0x%08X..0x%08X", base, base + 0xFF))
        for num = 0, 0xFF do
            local cmd = base + num
            local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
            if r ~= -1 then
                hits = hits + 1
                print(string.format("    HIT 0x%08X -> %d", cmd, r))
            end
        end
    end
end

print("")
print("[B] total hits " .. hits)
pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 284a COMPLETE ===")
