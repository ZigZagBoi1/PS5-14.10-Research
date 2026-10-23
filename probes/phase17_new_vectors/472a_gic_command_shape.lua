-- CRASH_CLASS: MODERATE
-- PROBE 472a: what does _IOWR('G', 1, 0x10) do on /dev/gic
--
-- Context: 471b swept the full encoding space on /dev/gic and found one
-- driver command beyond the three framework returns: 0xC0104701, direction
-- IN|OUT with 16 bytes. Unlike dce's write-only stub this one has an output
-- buffer, so every call below dumps all 16 returned bytes in hex: something
-- to read back, and a possible leak channel.
--
--   [A] does the handler copyin 16 bytes (null / short / kernel pointers)
--   [B] does the length have to be exactly 0x10, and which directions answer
--   [C] does the content matter, and what comes back in the 16 bytes
--   [D] repeatability: same call twice, and FIODTYPE afterwards

print("=== PROBE 472a: the gic command ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_mmap = make_syscall(477)

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(0), uint64(0))) end
print("[0] open(/dev/gic)=" .. fd)
if fd < 0 then
    print("=== PROBE 472a ABORTED ===")
    return
end

local CMD = 0xC0104701
local page = memory.alloc(0x1000)
local function zero_page()
    for off = 0, 0xFFC, 4 do wd(page + off, 0) end
end
local function hex16(tag)
    print(string.format("    %-16s %08X %08X %08X %08X",
        tag, rd(page) % 0x100000000, rd(page + 4) % 0x100000000,
        rd(page + 8) % 0x100000000, rd(page + 12) % 0x100000000))
end

zero_page()

print("")
print("[A] does the handler copyin sixteen bytes")
local unmapped = page + 0x1000 - 8  -- only 8 bytes of room before the edge
local cases = {
    { "zeroed page", uint64(page) },
    { "null", uint64(0) },
    { "short (8B)", uint64(unmapped) },
    { "kernel VA", uint64(string.format("0x%X%08X", 0xFFFF8000, 0x1000)) },
}
for _, c in ipairs(cases) do
    zero_page()
    local r = sc_ioctl(uint64(fd), uint64(CMD), c[2])
    print(string.format("    %-12s ret=%d", c[1], sgn(r)))
    if c[1] == "zeroed page" then hex16("returned") end
end

print("")
print("[B] does the length have to be 0x10, and which directions answer")
local lens = { 0, 4, 8, 0x10, 0x18, 0x20 }
for _, len in ipairs(lens) do
    for _, dir in ipairs({ 0xC0000000, 0x80000000, 0x40000000, 0x00000000 }) do
        zero_page()
        local cmd = dir + (len * 0x10000) + 0x4701
        local r = sc_ioctl(uint64(fd), uint64(cmd), uint64(page))
        print(string.format("    dir=0x%08X len=0x%02X ret=%d", dir, len, sgn(r)))
        if sgn(r) ~= -1 and cmd ~= CMD then hex16("returned") end
    end
end

print("")
print("[C] does the content matter, and what comes back")
local values = {
    { "q0=0 q1=0", 0, 0 },
    { "q0=1", 1, 0 },
    { "q0=-1", 0xFFFFFFFF, 0 },
    { "q0=self", -2, 0 },
    { "q0=0x100000001", 1, 1 },
    { "q0=q1=-1", 0xFFFFFFFF, 0xFFFFFFFF },
}
for _, v in ipairs(values) do
    zero_page()
    local q0 = v[2]
    if q0 == -2 then q0 = to_num(page) end
    wq(page, uint64(q0))
    wq(page + 8, uint64(v[3]))
    local r = sc_ioctl(uint64(fd), uint64(CMD), uint64(page))
    print(string.format("    %-14s ret=%d", v[1], sgn(r)))
    hex16("returned")
end

print("")
print("[D] same call twice, then FIODTYPE")
for i = 1, 3 do
    zero_page()
    local r = sc_ioctl(uint64(fd), uint64(CMD), uint64(page))
    print(string.format("    call %d ret=%d", i, sgn(r)))
    hex16("returned")
end
zero_page()
local rt = sc_ioctl(uint64(fd), uint64(0x4004667A), uint64(page))
print("    FIODTYPE after = " .. sgn(rt))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 472a COMPLETE ===")
