-- CRASH_CLASS: HIGH
-- PROBE 285a: the one large-struct command in the gc table
--
-- Context: 284a swept group 0x81 over length 0..0x7FF instead of the seven
-- lengths the earlier sweeps used, and found two numbers the short sweep could
-- not see:
--
--   0x80888123   direction in, length 0x888, group 0x81, num 0x23
--   0xC004811D   direction in/out, length 4
--
-- 0x80888123 takes 2184 bytes from user space, which is two orders of
-- magnitude more than any other command in this table. A command with a
-- fixed-size input struct of that size is worth measuring before anything
-- else: it is where a driver would accept a buffer description, a pointer
-- list or a descriptor table.
--
-- The sweep then hung at 0xC0048125, the same command that hung in 281a and
-- 282a after 283a had run, so that block is avoided here.

print("=== PROBE 285a: gc big command ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(0), uint64(0))) end
print("[0] open(/dev/gc)=" .. fd)
if fd < 0 then return end

local page = memory.alloc(0x2000)
local function fill(p, v, n)
    for off = 0, n - 4, 4 do pcall(function() memory.write_dword(p + off, v) end) end
end
local function scan(p, want, n)
    local changed, shown, line = 0, 0, ""
    for off = 0, n - 4, 4 do
        local v = rd(p + off)
        if v ~= want then
            changed = changed + 1
            if shown < 10 then
                line = line .. string.format(" [%03X]=0x%08X", off, v)
                shown = shown + 1
            end
        end
    end
    return changed, line
end

local BIG = 0x80888123

print("")
print("[A] 0x80888123 with a 0xAA page (0x888 bytes of input)")
fill(page, 0xAAAAAAAA, 0x888)
print("    calling")
local r = sgn(sc_ioctl(uint64(fd), uint64(BIG), uint64(page)))
local c, l = scan(page, 0xAAAAAAAA, 0x888)
print(string.format("    ret=%d changed=%d%s", r, c, l))

print("")
print("[B] 0x80888123 with a zero page")
fill(page, 0, 0x888)
print("    calling")
r = sgn(sc_ioctl(uint64(fd), uint64(BIG), uint64(page)))
c, l = scan(page, 0, 0x888)
print(string.format("    ret=%d changed=%d%s", r, c, l))

print("")
print("[C] 0x80888123 with a null argument")
r = sgn(sc_ioctl(uint64(fd), uint64(BIG), uint64(0)))
print(string.format("    ret=%d", r))

print("")
print("[D] 0xC004811D, the other number the short sweep could not see")
for _, cmd in ipairs({ 0xC004811D }) do
    fill(page, 0xAAAAAAAA, 0x1000)
    r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    c, l = scan(page, 0xAAAAAAAA, 0x100)
    print(string.format("    cmd=0x%08X ret=%d changed=%d%s", cmd, r, c, l))
    r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(0)))
    print(string.format("    cmd=0x%08X null -> %d", cmd, r))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 285a COMPLETE ===")
