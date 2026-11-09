-- CRASH_CLASS: HIGH
-- PROBE 478b: which field makes 0x80108013 fatal
--
-- 478a: four non-zero shapes all returned -1 on /dev/dmem1, no damage.
-- 477b: the zeroed 16-byte page printed "[13] ret=-" and the console died, so
-- the ioctl had returned and the machine went down right after it.
--
-- This probe separates q0 from q1 as the fatal field, cheapest first, then
-- repeats the known-fatal all-zero call LAST so the run ends with the
-- confirmation and every earlier line is attributable.
--
-- [1] {1,      0x10, 0}   expect refused
-- [2] {page,   0,    0}   q1 = 0 with a valid q0
-- [3] {0,      0x10, 0}   q0 = 0 with q1 set
-- [4] {0,      0,    0}   the 477b shape, expected to kill

print("=== PROBE 478b: dmem1 0x80108013 zero field ===")
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

local page = memory.alloc(0x100)
zero(page, 0x100)
local arg = memory.alloc(0x40)
zero(arg, 0x40)

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print(string.format("[0] open(/dev/dmem1)=%d page=0x%08X", fd, to_num(page)))
if fd < 0 then print("[0] refused"); return end

local cases = {
    { tag = "1", q0 = 1,              q1 = 0x10 },
    { tag = "2", q0 = to_num(page),   q1 = 0    },
    { tag = "3", q0 = 0,              q1 = 0x10 },
    { tag = "4", q0 = 0,              q1 = 0    },
}

for _, c in ipairs(cases) do
    zero(arg, 0x40)
    pcall(function() memory.write_qword(arg, uint64(c.q0)) end)
    pcall(function() memory.write_dword(arg + 8, c.q1) end)
    print(string.format("[%s] call q0=0x%X q1=0x%X", c.tag, c.q0, c.q1))
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(arg)) end)
    local ret = ok and sgn(r) or -999
    print(string.format("[%s] ret=%d arg=%s", c.tag, ret, peek(arg, 16)))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478b COMPLETE ===")
