-- CRASH_CLASS: HIGH
-- PROBE 478h: the same fatal sequence with time inserted
--
-- 477b's fatal order is prefix 0x00..0x12 then 0x80108013, in one burst, twice
-- byte-identical. Every reconstruction that interleaves work survives.
--
-- If the death needs the calls to follow each other with nothing in between, a
-- busy-wait before 0x80108013 should make it survive; if it dies anyway, the
-- order alone is enough and the delay is irrelevant.
--
-- Five rounds, each prefix then a busy loop of 2,000,000 iterations (roughly a
-- tenth of a second) then 0x80108013. Survival of several rounds is evidence;
-- a death names the round.

print("=== PROBE 478h: dmem1 prefix + delay + 0x80108013 ===")
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

local function busy(n)
    local x = 0
    for i = 1, n do x = x + i end
    return x
end

for round = 1, 5 do
    for nr = 0x00, 0x12 do
        pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108000 + nr), uint64(page)) end)
    end
    print(string.format("[R%d] prefix done, waiting", round))
    busy(2000000)
    print(string.format("[R%d] call 0x80108013", round))
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
    print(string.format("[R%d] ret=%s", round, tostring(ok and sgn(r) or -999)))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478h COMPLETE (all five rounds survived) ===")
