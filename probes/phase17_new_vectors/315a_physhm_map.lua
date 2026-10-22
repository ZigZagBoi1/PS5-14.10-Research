-- CRASH_CLASS: HIGH (maps a physical shared memory object and reads it)
-- PROBE 315a: what is the descriptor physhm_open hands out, and can it be mapped?
--
-- 314a: 629(1, 2, arg2, arg3) returns a descriptor for any arg2 and for arg3 in
-- 0..3; every other arg1 and a page-sized arg3 are refused. So arg1 is a small
-- enum, not a length.
--
-- This identifies the object with the ioctl the other nodes answer (FIODTYPE =
-- 0x4004667A), then tries to map it with MAP_SHARED and with the syscall the
-- sysent names mmap_dmem (628). If the mapping succeeds the first bytes are
-- read - that is the point of a physical memory handle.

print("=== PROBE 315a: physhm descriptor and mapping ===")

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
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok then return v end
    return 0
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -1
end
local function U32(v) return uint64(v) end

local sc629 = make_syscall(629)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_628 = make_syscall(628)

-- [A] the descriptor and its ioctl identity
print("")
local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(0)))
print(string.format("[A] physhm_open(1,2,0,0) -> fd %d", fd))
if fd < 0 then print("no descriptor; stopping") print("=== COMPLETE ===") return end

local out = memory.alloc(0x40)
for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out + i, 0xcccccccc) end) end
local rv = sgn(sc_ioctl(U32(fd), U32(0x4004667A), uint64(out)))
print(string.format("  FIODTYPE -> ret=%d out=0x%X", rv, rd(out)))
rv = sgn(sc_ioctl(U32(fd), U32(0x4004667B), uint64(out)))
print(string.format("  0x4004667B -> ret=%d out=0x%X", rv, rd(out)))

-- [B] mmap the descriptor, MAP_SHARED
print("")
print("[B] mmap(MAP_SHARED) on the descriptor")
local MAP_SHARED, PROT_RW = 1, 3
for _, len in ipairs({0x1000, 0x200000}) do
    local p = sgn(sc_mmap(uint64(0), U32(len), U32(PROT_RW), U32(MAP_SHARED), U32(fd), uint64(0)))
    print(string.format("  mmap(len=0x%X, shared) -> %d", len, p))
    if p > 0 then
        print(string.format("    first 32 bytes: %s %s %s %s",
            tostring(rq(p)), tostring(rq(p + 8)), tostring(rq(p + 16)), tostring(rq(p + 24))))
        sc_munmap(uint64(string.format("0x%X", p)), U32(len))
    end
end

-- [C] 628 mmap_dmem, the mapper the sysent names for this family
print("")
print("[C] 628 mmap_dmem shapes")
for _, shape in ipairs({"addr,len,prot,flags,fd,off", "len,prot,flags,fd,off,0"}) do
    local ok, r = pcall(function()
        if shape == "addr,len,prot,flags,fd,off" then
            return sc_628(uint64(0), U32(0x200000), U32(PROT_RW), U32(MAP_SHARED), U32(fd), uint64(0))
        else
            return sc_628(U32(0x200000), U32(PROT_RW), U32(MAP_SHARED), U32(fd), uint64(0), uint64(0))
        end
    end)
    print(string.format("  628(%s) -> %s", shape, ok and tostring(sgn(r)) or ("DIED: " .. tostring(r))))
end

-- [D] read/write on the descriptor itself
print("")
print("[D] direct read/write on the descriptor")
local rbuf = memory.alloc(0x100)
for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(rbuf + i, 0xdddddddd) end) end
local r = sgn(make_syscall(3)(U32(fd), uint64(rbuf), U32(0x40)))
print(string.format("  read(0x40) -> %d first=%s", r, tostring(rq(rbuf))))
r = sgn(make_syscall(4)(U32(fd), uint64(rbuf), U32(0x10)))
print(string.format("  write(0x10) -> %d", r))

sc_close(U32(fd))
print("")
print("=== PROBE 315a COMPLETE ===")
