-- CRASH_CLASS: LOW (no mapping is created; every access goes through the descriptor)
-- PROBE 319a: what does the physhm descriptor do when used as a file?
--
-- 318a proved that touching a physhm mapping kills the process even inside
-- pcall - the page is mapped but its first access faults. So the mapping is not
-- the safe way in. A read or write on the descriptor itself goes through the
-- driver and never touches those page tables.
--
-- This asks the object what it is with FIODTYPE, tries read and write on it,
-- and then hands the descriptor to 628 (mmap_dmem), which the sysent names for
-- this family, in every argument position it could occupy.

print("=== PROBE 319a: physhm descriptor as a file ===")

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
local function U32(v) return uint64(v) end

local sc629 = make_syscall(629)
local sc_close = make_syscall(6)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_ioctl = make_syscall(54)
local sc_628 = make_syscall(628)

local buf = memory.alloc(0x200)
for i = 0, 0x1FF, 8 do pcall(function() memory.write_qword(buf + i, uint64(0xA1A2A3A4A5A6A7A8)) end) end

local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(0)))
print(string.format("M1 fd=%d", fd))
if fd < 0 then print("no descriptor") return end

-- [A] identity
local out = memory.alloc(0x40)
pcall(function() memory.write_dword(out, 0xcccccccc) end)
print(string.format("M2 FIODTYPE ret=%d out=0x%X",
    sgn(sc_ioctl(U32(fd), U32(0x4004667A), uint64(out))), to_num(memory.read_dword(out))))
print(string.format("M3 FIONBIO ret=%d", sgn(sc_ioctl(U32(fd), U32(0x8004667E), uint64(out)))))

-- [B] read and write through the descriptor
local r = sgn(sc_read(U32(fd), uint64(buf), U32(0x40)))
print(string.format("M4 read(0x40) ret=%d buf0=0x%X", r, to_num(memory.read_dword(buf))))
r = sgn(sc_write(U32(fd), uint64(buf), U32(0x10)))
print(string.format("M5 write(0x10) ret=%d", r))

-- [C] 628 mmap_dmem with the descriptor in each slot
local shapes = {
    {"addr,len,prot,flags,fd,off", function() return sc_628(uint64(0), U32(0x200000), U32(3), U32(1), U32(fd), uint64(0)) end},
    {"fd,addr,len", function() return sc_628(U32(fd), uint64(0), U32(0x200000), uint64(0), uint64(0), uint64(0)) end},
    {"addr,len,fd", function() return sc_628(uint64(0), U32(0x200000), U32(fd), uint64(0), uint64(0), uint64(0)) end},
    {"len,prot,fd", function() return sc_628(U32(0x200000), U32(3), U32(fd), uint64(0), uint64(0), uint64(0)) end},
}
for _, s in ipairs(shapes) do
    local ok, rv = pcall(s[2])
    print(string.format("M6 628(%s) -> %s", s[1], ok and tostring(sgn(rv)) or ("DIED: " .. tostring(rv))))
end

sc_close(U32(fd))
print("M7 closed")
print("=== PROBE 319a COMPLETE ===")
