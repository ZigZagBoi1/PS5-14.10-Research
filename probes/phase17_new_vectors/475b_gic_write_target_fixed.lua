-- CRASH_CLASS: LOW
-- PROBE 475b: does the gic command write to the address q0 names? (corrected)
--
-- 475a was invalid: it passed memory.read_qword(target), the *contents* of the
-- target page, as q0 instead of the address. Every case therefore queried an
-- unmapped junk address and (correctly) got 0x816800FF. 475a's section [D] was
-- invalid for a second reason - its call() helper zeroed the whole argument
-- page, so the "tail changed" observation was the probe writing to itself.
--
-- This version passes the page address itself (the numeric handle memory.alloc
-- returns, the same idiom 472a used for q0=self), never clears the argument
-- page after the caller has filled it, and reads the argument page back in full
-- so a write past the four reported dwords is visible.

print("=== PROBE 475b: does the address get written? ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local CMD = 0xC0104701

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 then
    print("=== PROBE 475b ABORTED ===")
    return
end

local ARG_TAIL = 0x30
local arg = memory.alloc(0x40 + ARG_TAIL)
local target = memory.alloc(0x1000)

local function fill_target(v)
    for off = 0, 0xFFC, 4 do wd(target + off, v) end
end
local function dump_target(tag)
    print(string.format("    %-10s %08X %08X %08X %08X", tag,
        rd(target) % 0x100000000, rd(target + 4) % 0x100000000,
        rd(target + 8) % 0x100000000, rd(target + 12) % 0x100000000))
end
local function dump_arg(tag)
    local parts = {}
    for off = 0, 0x3C, 4 do
        parts[#parts + 1] = string.format("%08X", rd(arg + off) % 0x100000000)
    end
    print(string.format("    %-10s %s", tag, table.concat(parts, " ")))
end

-- The address itself, as the uint64 the call needs. memory.alloc hands back a
-- numeric handle; uint64(handle) is the idiom 472a used successfully.
local function set_q0(addr)
    local ok = pcall(function() memory.write_qword(arg, uint64(addr)) end)
    if ok then return true end
    local hi = math.floor(addr / 4294967296)
    local lo = addr % 4294967296
    return pcall(function() memory.write_qword(arg, uint64(string.format("0x%X%08X", hi, lo))) end)
end

local function call(q0, q1)
    set_q0(q0)
    wd(arg + 8, (q1 or 0) % 0x100000000)
    wd(arg + 12, 0)
    return sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
end

print(string.format("[0] arg=0x%X target=0x%X", to_num(arg), to_num(target)))

print("")
print("[A] target page as q0, pattern before and after")
for off = 0, 0x3C, 4 do wd(arg + off, 0) end
fill_target(0xC0FFEE00)
dump_target("before")
dump_arg("arg")
local r = call(target, 0)
print("    ret=" .. r)
dump_target("after")
dump_arg("arg-after")

print("")
print("[B] same q0, q1 = target: does the second dword change anything")
for off = 0, 0x3C, 4 do wd(arg + off, 0) end
fill_target(0xC0FFEE00)
r = call(target, target)
print("    ret=" .. r)
dump_target("after")
dump_arg("arg-after")

print("")
print("[C] content-dependence: fresh pattern, q1 = 0x1234")
for off = 0, 0x3C, 4 do wd(arg + off, 0) end
fill_target(0xDEADBEEF)
r = call(target, 0x1234)
print("    ret=" .. r)
dump_target("after")

print("")
print("[D] argument page tail left at a pattern before the call")
for off = 0, 0x3C, 4 do wd(arg + off, 0xA5A5A500) end
wd(arg, 0)
wd(arg + 8, 0)
-- deliberately do NOT clear: call_q0_only writes only the q0 dword
local ok_w = pcall(function() memory.write_qword(arg, uint64(0)) end)
dump_arg("before")
r = sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
print("    ret=" .. r)
dump_arg("after")

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 475b COMPLETE ===")
