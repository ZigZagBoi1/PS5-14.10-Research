-- CRASH_CLASS: HIGH
-- PROBE 478d: which prefix command enables 0x80108013
--
-- 478b: 0x80108013 alone returns -1, four times, no damage.
-- 478c: 0x80108000..0x80108012 alone return -1 and the read canary still
--       answers 0x150000000 afterwards. The prefix is harmless by itself.
-- 477b: prefix then 0x80108013 kills the console.
--
-- So one command in the prefix puts the driver into a state where 0x80108013
-- proceeds instead of returning EINVAL.
--
-- This probe walks the prefix and calls 0x80108013 after each command,
-- printing both results. The first predecessor that enables it takes the
-- console down and the last printed line names it. If every pair returns -1,
-- the enablement needs more than one predecessor.

print("=== PROBE 478d: dmem1 0x80108013 enabler ===")
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

local arg = memory.alloc(0x100)
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print("[0] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("[0] refused"); return end

for nr = 0x00, 0x12 do
    for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108000 + nr), uint64(arg)) end)
    print(string.format("[%02X] ret=%d base=%08X", nr, ok and sgn(r) or -999, rd32(arg)))

    for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end
    print(string.format("[%02X] -> now 0x80108013", nr))
    local ok2, r2 = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(arg)) end)
    print(string.format("[%02X] 13 ret=%d base=%08X", nr, ok2 and sgn(r2) or -999, rd32(arg)))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478d COMPLETE (no predecessor enabled it) ===")
