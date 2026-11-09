-- CRASH_CLASS: MODERATE
-- PROBE 277a: what does _IOW(0x82, 9, 8) do on /dev/dce
--
-- Context: 276a showed 0x80088209 is the only command in the whole encoding
-- space that answers on /dev/dce and not on zero, null, random, gic, dmem0 or
-- a socket. It returns 0 and writes nothing back, with an eight-byte input.
--
-- This probe pins down the handler's shape:
--   [A] does it copyin? a null pointer, a pointer with only four bytes of room,
--       and a kernel-shaped pointer must all fail if eight bytes are read
--   [B] does the length in the command have to be exactly eight
--   [C] does the content matter? zero, one, an address, a size-and-address pair
--   [D] does a successful call change anything observable - the same command
--       again, and a generic ioctl afterwards

print("=== PROBE 277a: the dce command ===")
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

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_mmap = make_syscall(477)

local fd = sgn(sc_open(uint64(put_str("/dev/dce")), uint64(2), uint64(0)))
print("[0] open(/dev/dce)=" .. fd)
if fd < 0 then return end

local CMD = 0x80088209
local page = memory.alloc(0x1000)
local function zero_page()
    for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

zero_page()

print("")
print("[A] does the handler copyin eight bytes")
local cases = {
    { "null",        uint64(0) },
    { "room 4",      uint64(page + 0xFFC) },
    { "room 8",      uint64(page + 0xFF8) },
    { "kernel addr", uint64(0xFFFF900000000000) },
    { "unmapped",    uint64(0x0000004000000000) },
}
for _, c in ipairs(cases) do
    local r = sc_ioctl(uint64(fd), uint64(CMD), c[2])
    print(string.format("    %-12s ret=%d", c[1], sgn(r)))
end

print("")
print("[B] does the length in the command have to be eight")
local lens = { 0, 4, 0x8, 0x10, 0x18, 0x20 }
for _, len in ipairs(lens) do
    for _, dir in ipairs({ 0x80000000, 0x40000000, 0xC0000000, 0x00000000 }) do
        local cmd = dir + len * 0x10000 + 0x8209
        local r = sc_ioctl(uint64(fd), uint64(cmd), uint64(page))
        print(string.format("    cmd=0x%08X ret=%d", cmd, sgn(r)))
    end
end

print("")
print("[C] does the content matter")
local values = {
    { "0",            0x0 },
    { "1",            0x1 },
    { "2",            0x2 },
    { "0x1000",       0x1000 },
    { "0xFFFFFFFF",   0xFFFFFFFF },
}
for _, v in ipairs(values) do
    zero_page()
    wq(page, uint64(v[2]))
    local r = sc_ioctl(uint64(fd), uint64(CMD), uint64(page))
    print(string.format("    q0=%-12s q1=0 ret=%d", v[1], sgn(r)))
end

zero_page()
wq(page, uint64(page))
wq(page + 8, uint64(0x1000))
local r2 = sc_ioctl(uint64(fd), uint64(CMD), uint64(page))
print(string.format("    q0=self q1=0x1000 ret=%d", sgn(r2)))

print("")
print("[D] repeatability and a generic ioctl afterwards")
for i = 1, 3 do
    zero_page()
    local r = sc_ioctl(uint64(fd), uint64(CMD), uint64(page))
    print(string.format("    call %d ret=%d", i, sgn(r)))
end
local rt = sc_ioctl(uint64(fd), uint64(0x4004667A), uint64(page))
print("    FIODTYPE after = " .. sgn(rt))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 277a COMPLETE ===")
