-- CRASH_CLASS: MODERATE
-- PROBE 287a: dump the four struct commands the length sweep uncovered
--
-- Context: 286a swept the lengths the earlier probes skipped and found four
-- in/out commands with real struct sizes:
--
--   0xC0188132   _IOWR(0x81, 0x32, 0x18)
--   0xC0288130   _IOWR(0x81, 0x30, 0x28)
--   0xC030811E   _IOWR(0x81, 0x1E, 0x30)
--   0xC0488131   _IOWR(0x81, 0x31, 0x48)
--
-- Every other command in this table takes 4, 8 or 16 bytes. These take 24, 40,
-- 48 and 72, which is the size of a descriptor, not a scalar, and an in/out
-- command is where a driver both reads fields and writes results.
--
-- The probe fills a page with 0xAA, calls each command and prints every
-- changed dword with its offset, then calls it a second time to see whether
-- the values are stable. A pointer in the output would be the first kernel or
-- GPU address this console has handed back.

print("=== PROBE 287a: gc struct commands ===")
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
local function fill(v, n)
    for off = 0, n - 4, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end
local function dump(want, n, label)
    local out, count = {}, 0
    for off = 0, n - 4, 4 do
        local v = rd(page + off)
        if v ~= want then
            count = count + 1
            if count <= 10 then
                out[#out + 1] = string.format("[%02X]=0x%08X", off, v)
            end
        end
    end
    print(string.format("    %s changed=%d %s", label, count, table.concat(out, " ")))
end

local structs = {
    { 0xC0188132, 0x18 },
    { 0xC0288130, 0x28 },
    { 0xC030811E, 0x30 },
    { 0xC0488131, 0x48 },
}

print("")
print("[A] each struct command twice with a 0xAA buffer")
for _, s in ipairs(structs) do
    local cmd, len = s[1], s[2]
    fill(0xAAAAAAAA, len)
    local r1 = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    print(string.format("  cmd=0x%08X ret=%d", cmd, r1))
    dump(0xAAAAAAAA, len, "pass1")
    local r2 = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    print(string.format("  cmd=0x%08X ret=%d", cmd, r2))
    dump(0xAAAAAAAA, len, "pass2")
end

print("")
print("[B] the same commands with a zero buffer, for comparison")
for _, s in ipairs(structs) do
    local cmd, len = s[1], s[2]
    fill(0, len)
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    print(string.format("  cmd=0x%08X ret=%d", cmd, r))
    dump(0, len, "zero")
end

print("")
print("[C] null argument")
for _, s in ipairs(structs) do
    local r = sgn(sc_ioctl(uint64(fd), uint64(s[1]), uint64(0)))
    print(string.format("  cmd=0x%08X null -> %d", s[1], r))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 287a COMPLETE ===")
