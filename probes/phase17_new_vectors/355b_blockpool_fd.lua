-- CRASH_CLASS: LOW
-- PROBE 355b: what the blockpool descriptor actually is
--
-- 653 blockpool_open returns a descriptor (84a/190a: 22, and close/23 frees the
-- slot). Nobody has ever read, seeked, stat'ed or ioctl'ed that descriptor. If
-- it behaves like a file, it has a read routine; if it is a bare handle, every
-- operation should refuse. Either answer is new, and both are cheap.

print("=== PROBE 355b: THE BLOCKPOOL DESCRIPTOR ===")
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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local Z = uint64(0)
local function rd(addr) local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end return -1 end
local function wq(addr, v) pcall(function() memory.write_qword(addr, v) end) end
local function wd(addr, v) pcall(function() memory.write_dword(addr, v) end) end

local page = memory.alloc(0x400)
for i = 0, 0x3F8, 8 do wq(page + i, 0) end

print("[A] open and close the descriptor the way 190a established")
local fd = sgn(make_syscall(653)(Z, Z, Z, Z, Z, Z))
print(string.format("  653(0,0,0,0,0,0) = %d", fd))
if fd < 3 then
    print("  no descriptor; stopping")
    print("=== 355b DONE ===")
    return
end

print("[B] read(3)")
local r1 = sgn(make_syscall(3)(U(0, fd), U(0, to_num(page)), U(0, 0x100), Z, Z, Z))
print(string.format("  read = %d  first qword = 0x%X", r1, rd(page)))

print("[C] pread(475)")
local r2 = sgn(make_syscall(475)(U(0, fd), U(0, to_num(page) + 0x200), U(0, 0x40), U(0, 0), Z, Z))
print(string.format("  pread = %d  first qword at +0x200 = 0x%X", r2, rd(page + 0x200)))

print("[D] lseek(478)")
local r3 = sgn(make_syscall(478)(U(0, fd), U(0, 0), U(0, 0), Z, Z, Z))
print(string.format("  lseek(0,SEEK_SET) = %d", r3))

print("[E] fstat(189) - now known to be present")
local r4 = sgn(make_syscall(189)(U(0, fd), U(0, to_num(page) + 0x300), Z, Z, Z, Z))
print(string.format("  fstat = %d  mode=0x%X size=0x%X", r4, rd(page + 0x300 + 4), rd(page + 0x300 + 0x10)))

print("[F] ioctl FIODTYPE (0x4004667A) via 54")
local r5 = sgn(make_syscall(54)(U(0, fd), U(0, 0x4004667A), U(0, to_num(page) + 0x380), Z, Z, Z))
print(string.format("  ioctl = %d  value = 0x%X", r5, rd(page + 0x380)))

print("[G] write(4) of 16 bytes")
local r6 = sgn(make_syscall(4)(U(0, fd), U(0, to_num(page) + 0x100), U(0, 0x10), Z, Z, Z))
print(string.format("  write = %d", r6))

print("[H] close, then open again")
local r7 = sgn(make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z))
local fd2 = sgn(make_syscall(653)(Z, Z, Z, Z, Z, Z))
print(string.format("  close = %d  reopen = %d", r7, fd2))

print("")
print("=== 355b DONE ===")
