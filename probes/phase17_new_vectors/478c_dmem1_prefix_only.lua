-- CRASH_CLASS: HIGH
-- PROBE 478c: the 477b prefix without its last call
--
-- 477b called 0x80108000..0x80108012 (all -1) and then 0x80108013, printed
-- "[13] ret=-" and the console died mid-line. 478b called 0x80108013 alone,
-- including the identical all-zero struct, and got -1 four times with no
-- damage.
--
-- So the death needs the prefix. Either one of 0x00..0x12 has a deferred
-- effect that fires microseconds later, or one of them leaves state that makes
-- 0x13 proceed instead of returning EINVAL.
--
-- This probe replays the prefix and STOPS. If the console survives past the
-- end of the run, the sequence is not lethal by itself and 0x13 in that state
-- is the suspect. If it dies afterwards, a deferred effect in the prefix owns
-- the death.
--
-- A read command at the end acts as a canary for driver state.

print("=== PROBE 478c: dmem1 prefix 0x00..0x12 only ===")
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

local okc, rc = pcall(function() return sc_ioctl(uint64(fd), uint64(0x4008800A), uint64(arg)) end)
print(string.format("[C0] read ret=%s base=%08X %08X", tostring(okc and sgn(rc) or -999), rd32(arg), rd32(arg + 4)))

for nr = 0x00, 0x12 do
    local cmd = 0x80108000 + nr
    print(string.format("[%02X] cmd=0x%08X", nr, cmd))
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), uint64(arg)) end)
    print(string.format("[%02X] ret=%d", nr, ok and sgn(r) or -999))
end

local ok2, r2 = pcall(function() return sc_ioctl(uint64(fd), uint64(0x4008800A), uint64(arg)) end)
print(string.format("[C1] read ret=%s base=%08X %08X", tostring(ok2 and sgn(r2) or -999), rd32(arg), rd32(arg + 4)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478c COMPLETE (prefix only, 0x13 not called) ===")
