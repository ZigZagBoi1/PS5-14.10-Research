-- CRASH_CLASS: HIGH
-- PROBE 286a: finish the gc table over the space the sweeps skipped
--
-- Context: 284a covered group 0x81 for lengths 0..0x7FF in all four
-- directions, found 0x80888123 and 0xC004811D, and then hung at 0xC0048125.
-- That leaves two holes:
--
--   dir 0xC0000000, the in/out direction, only length 4 was reached
--   every direction above length 0x7FF was never called
--
-- The second hole is the one that matters, because the only large command
-- found so far (0x80888123, 0x888 bytes) lives just inside the boundary the
-- first sweep covered. A command with a 0x2000-byte struct would have been
-- invisible to both earlier sweeps.
--
-- Length 4 in the 0xC0000000 direction is skipped: 0xC0048125 lives there and
-- hangs. Everything else is swept, and a length block prints only when a
-- command answers.

print("=== PROBE 286a: gc sweep remainder ===")
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

local page = memory.alloc(0x4000)
for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(page + off, 0xAAAAAAAA) end) end
local arg = uint64(page)
local hits = 0

local function sweep(d, from, to)
    for len = from, to do
        local base = d + len * 0x10000 + 0x8100
        for num = 0, 0xFF do
            local cmd = base + num
            local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
            if r ~= -1 then
                hits = hits + 1
                print(string.format("    HIT 0x%08X -> %d", cmd, r))
            end
        end
        if len % 0x200 == 0 then
            print(string.format("    AT dir=0x%08X len=0x%03X hits=%d", d, len, hits))
        end
    end
end

print("")
print("[A] dir 0xC0000000, lengths 5..0x7FF")
sweep(0xC0000000, 5, 0x7FF)

print("")
print("[B] dir 0x80000000, lengths 0x800..0x3FFF")
sweep(0x80000000, 0x800, 0x3FFF)

print("")
print("[C] dir 0x40000000, lengths 0x800..0x3FFF")
sweep(0x40000000, 0x800, 0x3FFF)

print("")
print("[D] dir 0x20000000, lengths 0x800..0x3FFF")
sweep(0x20000000, 0x800, 0x3FFF)

print("")
print("[E] total hits " .. hits)
pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 286a COMPLETE ===")
