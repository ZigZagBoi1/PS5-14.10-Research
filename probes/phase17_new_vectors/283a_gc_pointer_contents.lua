-- CRASH_CLASS: MODERATE
-- PROBE 283a: does any /dev/gc command treat buffer contents as an address
--
-- Context: 282a finished the group-0x81 table. Seventeen of the twenty
-- commands take a user pointer and every one of them returns -1 for NULL,
-- which proves the pointer itself is copied in. Some then write values back
-- into that same page, so the write goes to the pointer we passed.
--
-- The open question is whether a command reads a second address out of the
-- bytes we give it and uses that one. That is the difference between "the
-- driver fills a struct" and "the driver dereferences an attacker-chosen
-- address".
--
-- The test is safe: the buffer's first qword is set to the address of a
-- second user page, and that page is watched for changes. If it changes, the
-- command followed our pointer, and the next step is to point it at kernel
-- memory.
--
-- 0xC0048125 hung in both 281a and 282a, so it is excluded.

print("=== PROBE 283a: gc pointer contents ===")
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
local function u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(0), uint64(0))) end
print("[0] open(/dev/gc)=" .. fd)
if fd < 0 then return end

local page = memory.alloc(0x1000)
local page2 = memory.alloc(0x1000)

local function fill(p, v)
    for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(p + off, v) end) end
end
local function scan(p, want)
    local changed, shown, line = 0, 0, ""
    for off = 0, 0xFFC, 4 do
        local v = rd(p + off)
        if v ~= want then
            changed = changed + 1
            if shown < 6 then
                line = line .. string.format(" [%03X]=0x%08X", off, v)
                shown = shown + 1
            end
        end
    end
    return changed, line
end

local cmds = {
    0x40048135, 0x4004813A, 0x40088137, 0x8004813C,
    0xC0048113, 0xC0048114, 0xC0048115, 0xC0048116, 0xC0048117,
    0xC004811F, 0xC004812E,
    0xC0088101, 0xC0088111, 0xC008811B, 0xC0088133,
    0xC010810B, 0xC0108120, 0xC0108139,
}

-- the second page's address, split into two dwords so the first qword of the
-- argument page holds a real pointer
local p2lo = rd(page2)
local p2hi = rd(page2 + 4)
print(string.format("[1] page2=0x%08X%08X", p2hi, p2lo))
print("[2] page2=0x%08X page=0x%08X", rd(page2), rd(page))
local p2v_hi, p2v_lo = 0, p2lo

print("")
print("[A] buffer[0] = &page2, page2 filled 0x55")
for _, cmd in ipairs(cmds) do
    fill(page, 0xAAAAAAAA)
    fill(page2, 0x55555555)
    pcall(function() memory.write_dword(page, p2lo) end)
    pcall(function() memory.write_dword(page + 4, p2hi) end)
    local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page)))
    local c2, l2 = scan(page2, 0x55555555)
    local c1, l1 = scan(page, 0xAAAAAAAA)
    print(string.format("  cmd=0x%08X ret=%-3d arg_changed=%d%s  page2_changed=%d%s",
        cmd, r, c1, l1, c2, l2))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 283a COMPLETE ===")
