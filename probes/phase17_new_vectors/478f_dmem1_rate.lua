-- CRASH_CLASS: HIGH
-- PROBE 478f: rate or command?
--
-- 477b died twice on the identical file, both times printing "[13] ret=-" and
-- nothing more: 0x80108000..0x80108012 then 0x80108013, one burst, zeroed page.
-- Every reconstruction survives: 0x80108013 alone (-1 four times), the prefix
-- alone (canary reads fine), interleaved prefix+0x13 (19 refusals).
--
-- The difference left is spacing. So either the burst rate trips something in
-- the driver, or 0x13 is lethal only immediately after the prefix.
--
-- This probe separates rate from command with a control: first 200 calls of the
-- known-benign read command 0x4008800A, then 200 calls of 0x80108013, both as
-- tight loops over a zeroed page. A death in the control blames the rate for
-- the whole driver; a death only in the second loop blames the command.

print("=== PROBE 478f: dmem1 rate vs command ===")
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

local last = 0
for i = 1, 200 do
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x4008800A), uint64(page)) end)
    last = ok and sgn(r) or -999
    if i % 50 == 0 then print(string.format("[C] read %d/200 ret=%d", i, last)) end
end
print(string.format("[C] control done, last=%d", last))

for i = 1, 200 do
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
    last = ok and sgn(r) or -999
    if i % 10 == 0 then print(string.format("[T] 0x80108013 %d/200 ret=%d", i, last)) end
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478f COMPLETE (both loops survived) ===")
