-- CRASH_CLASS: LOW
-- PROBE 293a: are the ugen commands stubs or handlers
--
-- Context: 292a called every group-0x55 command that answered on /dev/ugen0.2
-- with a zeroed page. Three of them copied a value back:
--
--   0x40045587 -> 0x00000064
--   0x4004558B -> 0x00008000
--   0x40045592 -> 0x00000001
--
-- and the other seventeen returned 0 without writing anything.
--
-- A handler that reads its argument answers differently for a null pointer, an
-- unmapped pointer, a zero page and a 0xAA page. A stub returns 0 for all four.
-- That distinction is the whole point of this probe: it decides whether the
-- USB ioctl surface is real before any effort goes into the structures behind
-- it.

print("=== PROBE 293a: ugen argument shapes ===")
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
local function word_at(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local zero = memory.alloc(0x1000)
local aa = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do
    pcall(function() memory.write_dword(zero + off, 0) end)
    pcall(function() memory.write_dword(aa + off, 0xAAAAAAAA) end)
end

local fd = sgn(sc_open(uint64(put_str("/dev/ugen0.2")), uint64(2), uint64(0)))
print(string.format("open=%d", fd))

local cmds = {
    0x80045506, 0x80045565, 0x80045571, 0x80045572, 0x80045576,
    0x80045577, 0x80045578, 0x8004557A, 0x8004557B, 0x8004557C,
    0x8004557D, 0x80045580, 0x80045588, 0x80045589,
    0x40045564, 0x40045575, 0x40045587, 0x4004558B, 0x40045592,
}

local shapes = {
    { "null", uint64(0) },
    { "bad", uint64(0x1000) },
    { "zero", uint64(zero) },
    { "aa", uint64(aa) },
}

if fd >= 0 then
    print(string.format("%-12s %-6s %-6s %-6s %-6s", "cmd", "null", "bad", "zero", "aa"))
    for _, cmd in ipairs(cmds) do
        local row = {}
        local out = {}
        for _, s in ipairs(shapes) do
            local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), s[2]))
            row[#row + 1] = string.format("%d", r)
            local w = word_at(s[2] == uint64(0) and zero or (s[1] == "zero" and zero or aa))
            out[#out + 1] = (s[1] == "null" or s[1] == "bad") and "-" or string.format("0x%X", w)
        end
        print(string.format("0x%08X %-6s %-6s %-6s %-6s   out %s %s",
            cmd, row[1], row[2], row[3], row[4], out[3], out[4]))
    end
    pcall(function() sc_close(uint64(fd)) end)
end

print("")
print("=== PROBE 293a COMPLETE ===")
