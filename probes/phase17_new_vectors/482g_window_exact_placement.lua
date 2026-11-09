-- CRASH_CLASS: HIGH
-- PROBE 482g: pin down what makes 0x80108002 return 0 or die
--
-- 482d: mmap placed the region at 0x2500140000, then insert {0x2500000000,0x4000}
--       returned 0.
-- 482e: insert {0x2520000000,0x4000}, nothing mmap'd in the probe -> died.
-- 482f: mmap 0x2500000000 (placement not printed), insert {0x2500000000,0x4000}
--       -> died before the [1] marker passed the pad.
-- So the same call has returned 0 once and died twice. This probe prints the
-- exact mmap placement and calls the command at exactly that address first,
-- then at an address never hinted, with pads so each step survives the log.
print("=== PROBE 482g: exact placement ===")

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
local function parts(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return h, l
end
local function put_str(str)
    local buf = memory.alloc(#str + 1)
    for i = 1, #str do pcall(function() memory.write_byte(buf + i - 1, string.byte(str, i)) end) end
    pcall(function() memory.write_byte(buf + #str, 0) end)
    return buf
end
local function cast64(n)
    return uint64(string.format("0x%08X%08X", math.floor(n / 4294967296) % 4294967296, n % 4294967296))
end
local function pad(tag)
    for i = 1, 200 do print(string.format("pad %-10s %03d %s", tag, i, string.rep("-", 24))) end
end

local arg = memory.alloc(0x100)
local sc_open = make_syscall(5)
local sc_ioctl = make_syscall(54)
local sc_mmap = make_syscall(477)

local function call(fd, q0, q1)
    pcall(function() memory.write_qword(arg, cast64(q0)) end)
    pcall(function() memory.write_qword(arg + 8, cast64(q1)) end)
    pcall(function() memory.write_qword(arg + 0x10, uint64(0)) end)
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108002), uint64(arg)) end)
    if not ok then return "pcall-fail" end
    return tostring(sgn(r))
end

local okm, rm = pcall(function()
    return sc_mmap(cast64(0x2500000000), uint64(0x40000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local mh, ml = 0, 0
if okm and rm ~= nil then mh, ml = parts(rm) end
local placed = mh * 4294967296 + ml
print(string.format("[setup] mmap hint 0x2500000000 ok=%s placed=%08X%08X", tostring(okm), mh, ml))
pad("setup")

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
print(string.format("[open] fd=%d", fd))
pad("open")

print("[1] insert at the exact placement")
print("    ret=" .. call(fd, placed, 0x4000))
pad("exact")

print("[2] insert at an address never hinted (0x2540000000)")
print("    ret=" .. call(fd, 0x2540000000, 0x4000))
pad("far")

print("[3] insert at the mapping start again")
print("    ret=" .. call(fd, placed, 0x4000))
pad("again")

print("=== PROBE 482g DONE ===")
