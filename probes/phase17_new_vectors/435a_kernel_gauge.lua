-- CRASH_CLASS: LOW
-- PROBE 435a: is there a gauge for kernel objects we allocate?
--
-- Every object family that works from a game process allocates a kernel object: evf (538,
-- 0x58 bytes), osem (549, 0x60), namedobj (557, 0x18). A handle comes back, but a handle is
-- a per-process slot number, so it says nothing about the kernel heap.
--
-- 671 (resource class query) returns two numbers for selector -1: 6144/3948 in mode 1 and
-- 2560/2014 in mode 2 (55e). If either moves when objects are created, we have an
-- instrument: something that reports kernel allocations from userland. That is worth
-- knowing before any bug is found, because a primitive you cannot measure is a primitive
-- you cannot aim.
--
-- This allocates 100 of each family, re-reads the pair, frees everything and reads again.

print("=== PROBE 435a: KERNEL GAUGE ===")

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] page=0x%X", page))
if page <= 0 then print("=== 435a DONE ===") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local function gauge()
    local out = call(477, 0, 0x100, 7, 0x1002, 0xFFFFFFFF, 0)
    if out <= 0 then return -1, -1 end
    local r1 = call(671, -1, 1, out, 0x20, 0, 0)
    local a1 = to_num(memory.read_dword(out + 0))
    local b1 = to_num(memory.read_dword(out + 4))
    local r2 = call(671, -1, 2, out, 0x20, 0, 0)
    local a2 = to_num(memory.read_dword(out + 0))
    local b2 = to_num(memory.read_dword(out + 4))
    return string.format("m1=%u/%u(rv=%d) m2=%u/%u(rv=%d)", a1, b1, r1, a2, b2, r2)
end

print("[B] baseline: " .. gauge())

local name = memory.alloc(0x40)
local NAME = "omp435a"
local j = 1
while j <= #NAME do memory.write_byte(name + j - 1, NAME:byte(j)); j = j + 1 end
memory.write_byte(name + #NAME, 0)

local evf, osem, nobj = {}, {}, {}
local k = 1
while k <= 100 do
    evf[k] = call(538, page, 0, 0, 0, 0, 0)
    osem[k] = call(549, name, 0, 0, k + 1, 0)
    nobj[k] = call(557, name, 0, 0x1, 0, 0, 0)
    k = k + 1
end
print(string.format("[C] evf[1]=%d evf[100]=%d osem[1]=%d osem[100]=%d nobj[1]=%d nobj[100]=%d",
    evf[1], evf[100], osem[1], osem[100], nobj[1], nobj[100]))
print("[D] after 300 objects: " .. gauge())

k = 1
local freed = 0
while k <= 100 do
    if call(539, evf[k]) == 0 then freed = freed + 1 end
    if call(550, osem[k]) == 0 then freed = freed + 1 end
    k = k + 1
end
print(string.format("[E] freed %d of 200", freed))
print("[F] after free: " .. gauge())

print("=== 435a DONE ===")
