-- CRASH_CLASS: MODERATE
-- PROBE 282a: finish the /dev/gc table, with the hanging command last
--
-- Context: 281a measured the write length of ten group-0x81 commands and then
-- stopped at 0xC0048125, which did not return: the loader answered a later
-- connection with zero bytes, so the calling thread is parked inside the
-- ioctl. That is a hang in the graphics driver, not a refusal.
--
-- 280a had called 0xC0048125 successfully with the same 0xAA page, so the hang
-- depends on state, not on the argument bytes. This probe finishes the eight
-- commands 281a never reached and calls 0xC0048125 last, so a repeated hang
-- costs nothing after it.
--
--   0xC004812E  0xC0088101  0xC0088111  0xC008811B
--   0xC0088133  0xC010810B  0xC0108120  0xC0108139

print("=== PROBE 282a: gc table, tail ===")
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

local page = memory.alloc(0x1000)
local function fill(v)
    for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end

local tail = {
    0xC004812E, 0xC0088101, 0xC0088111, 0xC008811B,
    0xC0088133, 0xC010810B, 0xC0108120, 0xC0108139,
}

print("")
print("[A] tail commands with a 0xAA page")
for _, cmd in ipairs(tail) do
    fill(0xAAAAAAAA)
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    local changed = 0
    local shown = 0
    local line = string.format("  cmd=0x%08X ret=%-3d", cmd, r)
    for off = 0, 0xFFC, 4 do
        local v = rd(page + off)
        if v ~= 0xAAAAAAAA then
            changed = changed + 1
            if shown < 8 then
                line = line .. string.format(" [%03X]=0x%08X", off, v)
                shown = shown + 1
            end
        end
    end
    print(line .. "  changed=" .. changed)
end

print("")
print("[B] tail commands with a null argument")
for _, cmd in ipairs(tail) do
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(0)))
    print(string.format("  cmd=0x%08X null -> %d", cmd, r))
end

print("")
print("[C] 0xC0048125 again, last, because it hung once")
fill(0xAAAAAAAA)
local r = sgn(sc_ioctl(uint64(fd), uint64(0xC0048125), uint64(page)))
print(string.format("  0xC0048125 -> %d  [0]=0x%08X", r, rd(page)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 282a COMPLETE ===")
