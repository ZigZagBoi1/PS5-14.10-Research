-- CRASH_CLASS: HIGH
-- PROBE 478a: give 0x80108013 a non-zero 16-byte argument
--
-- Context: 477b showed that 0x80108013 on /dev/dmem1 never returns and takes
-- the console with it, with a zeroed argument page. Every other 16-byte
-- command in the group reads {qword, dword, dword}: 0x80108017 passes
-- ([r14], [r14+8], [r14+0xc]) to 0x3f4c60 in the 13.60 dispatch.
--
-- This probe gives the command that same shape with real values, smallest
-- first, printing the shape before each call. q0 is a page this process owns,
-- so if the field is a user pointer the kernel copies from memory it can read.
-- If the field is physical, 0x310000000-ish is inside the 16 GB range and the
-- risk is real; that is accepted for this run.
--
-- S1 {page, 0x10, 0}   S2 {page, 0x1000, 0}   S3 {0x150000000, 0x10, 0}
-- S4 {page+0x40, 0x10, 1}
--
-- A power-off names the shape that did it (the line before the missing one).

print("=== PROBE 478a: dmem1 0x80108013 argument layout ===")
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
local function peek(base, n)
    local out = {}
    for i = 0, n - 1, 4 do out[#out + 1] = string.format("%08X", rd32(base + i)) end
    return table.concat(out, " ")
end
local function zero(base, n)
    for off = 0, n - 4, 4 do pcall(function() memory.write_dword(base + off, 0) end) end
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x200)
zero(page, 0x200)
for off = 0, 0x1FC, 4 do pcall(function() memory.write_dword(page + off, 0xDEADBEEF) end) end

local arg = memory.alloc(0x40)
zero(arg, 0x40)

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print(string.format("[0] open(/dev/dmem1)=%d  page=0x%08X", fd, to_num(page)))
if fd < 0 then print("[0] refused"); return end

-- control: the readable command still answers before we touch the risky one
local okc, rc = pcall(function() return sc_ioctl(uint64(fd), uint64(0x4008800A), uint64(arg)) end)
print(string.format("[C] 0x4008800A ret=%s arg=%s", tostring(okc and sgn(rc) or -999), peek(arg, 16)))

local shapes = {
    { tag = "S1", q0 = to_num(page),        q1 = 0x10,       q2 = 0 },
    { tag = "S2", q0 = to_num(page),        q1 = 0x1000,     q2 = 0 },
    { tag = "S3", q0 = 0x150000000,         q1 = 0x10,       q2 = 0 },
    { tag = "S4", q0 = to_num(page) + 0x40, q1 = 0x10,       q2 = 1 },
}

for _, s in ipairs(shapes) do
    zero(arg, 0x40)
    pcall(function() memory.write_qword(arg, uint64(s.q0)) end)
    pcall(function() memory.write_dword(arg + 8, s.q1) end)
    pcall(function() memory.write_dword(arg + 12, s.q2) end)
    print(string.format("[%s] call q0=0x%08X q1=0x%X q2=0x%X", s.tag, s.q0, s.q1, s.q2))
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(arg)) end)
    local ret = ok and sgn(r) or -999
    print(string.format("[%s] ret=%d arg=%s", s.tag, ret, peek(arg, 16)))
    print(string.format("[%s] page=%s", s.tag, peek(page, 32)))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478a COMPLETE ===")
