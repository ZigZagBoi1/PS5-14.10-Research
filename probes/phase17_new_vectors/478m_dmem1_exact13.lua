-- CRASH_CLASS: HIGH
-- PROBE 478m: 477b's exact [13] line, then stop
--
-- Context: 476a's sweep died inside /dev/dmem1, in the IOC_IN size-0x10 block,
-- somewhere in [0x80108000, 0x8010BFFF). 477a then showed that group 0x80
-- nr 0x0A is a readable command at size 8 (returns the constant
-- 0x0000000150000000), so the write half of the same family is the first
-- suspect.
--
-- This probe walks group 0x80 only, nr 0x00..0xFF, printing the command number
-- BEFORE each call so the last line of a truncated capture names the killer.
-- The argument is a zeroed 0x100 page. If the console survives, the loop's
-- returns and any bytes written back are recorded.
--
-- A console power-off here is the expected outcome for exactly one command.

print("=== PROBE 478m: exact [13] line ===")
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
local function rd32(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x100)
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print("[0] open(/dev/dmem1)=" .. fd)
if fd < 0 then
    print("[0] refused")
    return
end

for nr = 0x00, 0x12 do
    local cmd = 0x80108000 + nr
    print(string.format("[%02X] cmd=0x%08X", nr, cmd))
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), uint64(page)) end)
    local ret = ok and sgn(r) or -999
    print(string.format("[%02X] ret=%d  page=%08X %08X %08X %08X", nr, ret,
        rd32(page), rd32(page + 4), rd32(page + 8), rd32(page + 12)))
end

print("[13] cmd=0x80108013")
local ok3, r3 = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
local ret3 = ok3 and sgn(r3) or -999
print(string.format("[13] ret=%d  page=%08X %08X %08X %08X", ret3,
    rd32(page), rd32(page + 4), rd32(page + 8), rd32(page + 12)))
print("[13] stopped here")

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 477b COMPLETE ===")
