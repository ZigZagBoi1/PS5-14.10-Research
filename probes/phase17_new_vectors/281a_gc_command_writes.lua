-- CRASH_CLASS: LOW
-- PROBE 281a: what each accepted /dev/gc command writes back
--
-- Context: 280a walked group 0x81 with a page filled 0xAAAAAAAA and twenty
-- commands returned 0. Several of them overwrote the buffer, which is the
-- shape an information leak has:
--
--   0x40048135 -> [0]=0x00000101     0x4004813A -> [0]=0x00000000
--   0x40088137 -> [0]=0, [4]=0       0xC0048113 -> [0]=0x00000003
--   0xC008811B -> [0]=0x80000000, [4]=0x0000000C
--   0xC0088133 -> [4]=0x0000005C     0xC010810B -> [0]=0x10, [4]=0x10
--
-- This probe dumps every changed dword across the whole page for each command,
-- so the length of the write is measured rather than assumed, and it calls each
-- command with a null argument to see whether the pointer is required.

print("=== PROBE 281a: gc command writes ===")
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

local cmds = {
    0x40048135, 0x4004813A, 0x40088137, 0x8004813C,
    0xC0048113, 0xC0048114, 0xC0048115, 0xC0048116, 0xC0048117,
    0xC004811F, 0xC0048125, 0xC004812E,
    0xC0088101, 0xC0088111, 0xC008811B, 0xC0088133,
    0xC010810B, 0xC0108120, 0xC0108139,
}

print("")
print("[A] call with a 0xAA page, list every changed dword")
for _, cmd in ipairs(cmds) do
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
print("[B] the same commands with a null argument")
for _, cmd in ipairs(cmds) do
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(0)))
    print(string.format("  cmd=0x%08X null -> %d", cmd, r))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 281a COMPLETE ===")
