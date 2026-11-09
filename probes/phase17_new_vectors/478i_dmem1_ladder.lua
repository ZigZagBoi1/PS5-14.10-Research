-- CRASH_CLASS: HIGH
-- PROBE 478i: how short can the fatal prefix get?
--
-- 477b dies 3/3 with byte-identical 1504-byte captures at 0x80108013, after
-- calling 0x80108000..0x80108012 with a print between each call.
-- 478b: 0x80108013 alone, four shapes, survives.
-- 478d: every prefix call followed immediately by 0x13, 19 pairs, survives —
--       but it writes 64 dwords into the page between a call and the 0x13.
-- 478h: tight prefix, no prints, a busy loop before 0x13, survives 5/5.
-- 478f: 200 tight 0x13 calls, survives.
-- 478g: full page dump after every prefix call, all zeros, 0x13 refused.
--
-- So the death needs 0x13 to follow the prefix almost immediately, and the
-- prefix matters. This probe shortens the prefix from the end: 0x12 then 0x13,
-- then 0x11..0x12 then 0x13, and so on. Every rung prints before and after.
-- The first rung that dies names the shortest fatal sequence.

print("=== PROBE 478i: dmem1 fatal prefix ladder ===")
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

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x100)
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print("[0] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("[0] refused"); return end

for start = 0x12, 0x00, -1 do
    for nr = start, 0x12 do
        local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108000 + nr), uint64(page)) end)
        print(string.format("[L] start=%02X call %02X ret=%d", start, nr, ok and sgn(r) or -999))
    end
    print(string.format("[L] start=%02X -> 0x80108013", start))
    local ok2, r2 = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
    print(string.format("[L] start=%02X survived, ret=%d", start, ok2 and sgn(r2) or -999))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478i COMPLETE (every rung survived) ===")
