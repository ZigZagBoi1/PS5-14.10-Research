-- CRASH_CLASS: LOW
-- PROBE 358a: what /dev/gc and /dev/gic hand back when read
--
-- 268a read /dev/zero, /dev/random, /dev/null and /dev/dce: only dce refused.
-- The three nodes every other round only ever ioctl'ed - gc, gic, and the
-- camera - were never read at all. A driver's d_read is a different entry point
-- from its d_ioctl, and a graphics node that returns a descriptor, a version
-- block or a device id on read would be the context 622's 0x400 group wants.

print("=== PROBE 358a: READING THE GRAPHICS NODES ===")
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
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return -1 end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local page = memory.alloc(0x1000)
local path = memory.alloc(0x40)

local function dump(tag, n)
    local parts = {}
    for i = 0, math.min(n, 0x40) - 1, 4 do
        parts[#parts + 1] = string.format("%08X", rd(page + i))
    end
    if #parts > 0 then print(string.format("    %s: %s", tag, table.concat(parts, " "))) end
end

for _, name in ipairs({"/dev/gc", "/dev/gic", "/dev/dce", "/dev/camera", "/dev/ajm", "/dev/rng"}) do
    for i = 0, 0x3F, 8 do wq(path + i, 0) end
    str_at(path, name)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 2), Z, Z, Z, Z))
    print(string.format("[%s] open O_RDWR = %d", name, fd))
    if fd >= 3 then
        for i = 0, 0xFF8, 8 do wq(page + i, 0) end
        local n = sgn(make_syscall(3)(U(0, fd), U(0, to_num(page)), U(0, 0x100), Z, Z, Z))
        print(string.format("    read(0x100) = %d", n))
        if n ~= 0 then dump("bytes", n) end
        local st = memory.alloc(0x80)
        for i = 0, 0x78, 8 do wq(st + i, 0) end
        local fs = sgn(make_syscall(189)(U(0, fd), U(0, to_num(st)), Z, Z, Z, Z))
        print(string.format("    fstat = %d  mode=0x%X size=0x%X rdev=0x%X",
            fs, rd(st + 8), rd(st + 0x10), rd(st + 0x18)))
        print(string.format("    close = %d", sgn(make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z))))
    end
end

print("")
print("=== 358a DONE ===")
