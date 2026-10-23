-- CRASH_CLASS: LOW
-- PROBE 475a: does the gic command write to the address q0 names?
--
-- Context: 474a walked every high alias below eboot and all of them survived
-- with the error status, so the kill at 0xf0000000 is that mapping rather than
-- the address range. The classification table now reads:
--
--   writable mapping (prot 0x3):  status 0,        class 0 (file) or 3 (anon)
--   read-only / executable:       status 816800FF, class 0 or 1
--   unmapped:                     status 816800FF, class 0
--
-- The handler's argument is 16 bytes in and 16 bytes out, and the first dword
-- comes back as a truncated echo of q0. If "writable" is a precondition it is
-- probably about to write *through* q0. This probe allocates a second page
-- filled with a recognisable pattern, passes its address as q0, and compares
-- the page afterwards. It also varies q1 so a second address-shaped argument
-- shows up if one exists, and checks whether the argument page itself is
-- modified beyond the four reported dwords.

print("=== PROBE 475a: does the address get written? ===")
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
local sc_mmap = make_syscall(477)
local CMD = 0xC0104701

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 then
    print("=== PROBE 475a ABORTED ===")
    return
end

local arg = memory.alloc(0x40)
local target = memory.alloc(0x1000)
local function fill_target(v)
    for off = 0, 0xFFC, 4 do wd(target + off, v) end
end
local function dump_target(tag)
    print(string.format("    %-18s %08X %08X %08X %08X", tag,
        rd(target) % 0x100000000, rd(target + 4) % 0x100000000,
        rd(target + 8) % 0x100000000, rd(target + 12) % 0x100000000))
end
local function qword_addr(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    return ok and v or nil
end

local tq = qword_addr(target)
local ok_t, th, tl = pcall(function() return tq.h, tq.l end)

local function call(q0, q1)
    for off = 0, 0x3C, 4 do wd(arg + off, 0) end
    if type(q0) == "table" and q0.h then
        pcall(function() memory.write_qword(arg, uint64(string.format("0x%X%08X",
            q0.h % 0x100000000, q0.l % 0x100000000))) end)
    else
        wd(arg, q0 % 0x100000000)
    end
    wd(arg + 8, (q1 or 0) % 0x100000000)
    return sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
end

print("")
print("[A] target page as q0: pattern before, content after")
fill_target(0xC0FFEE00)
dump_target("before")
local r = call(tq, 0)
print("    ret=" .. r)
dump_target("after")
print(string.format("    argument: %08X %08X %08X %08X",
    rd(arg), rd(arg + 4), rd(arg + 8), rd(arg + 12)))

print("")
print("[B] does q1 matter: same q0, q1 = the target page")
fill_target(0xC0FFEE00)
dump_target("before")
r = call(tq, tq)
print("    ret=" .. r)
dump_target("after")

print("")
print("[C] does a second call with a different q1 move q0's page again")
fill_target(0xDEADBEEF)
dump_target("before")
r = call(tq, 0x1234)
print("    ret=" .. r)
dump_target("after")

print("")
print("[D] the argument page beyond the four reported dwords")
for off = 0, 0x3C, 4 do wd(arg + off, 0xA5A5A500) end
wd(arg, 0)
wd(arg + 8, 0)
r = call(0, 0)
local tail_changed = false
for off = 0x10, 0x3C, 4 do
    if rd(arg + off) % 0x100000000 ~= 0xA5A5A500 then tail_changed = true end
end
print(string.format("    ret=%d  arg[0x00..0x0C]=%08X %08X %08X %08X  tail changed=%s",
    r, rd(arg), rd(arg + 4), rd(arg + 8), rd(arg + 12), tostring(tail_changed)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 475a COMPLETE ===")
