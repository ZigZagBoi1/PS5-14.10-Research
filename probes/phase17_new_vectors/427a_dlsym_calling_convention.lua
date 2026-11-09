-- CRASH_CLASS: LOW
-- PROBE 427a: find dlsym's calling convention and a handle that resolves
--
-- 426a called 0x24f as (handle, name) and got -1 for every name on every handle, which
-- cannot be read: either the third argument is an out pointer, or the symbol the kernel
-- wants is not a C name, or the handle is wrong. This walks all three questions at once:
-- (handle 0..15) x (name) with a real out pointer, printing both the return and the
-- pointer the call wrote.

print("=== PROBE 427a: DLSYM CONVENTION ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function rdq(a)
    local q = memory.read_qword(a)
    if type(q) == "table" then
        return to_num(q.h) * 4294967296 + to_num(q.l)
    end
    return to_num(q)
end
local function cstr(s)
    local b = memory.alloc(0x80)
    local i = 1
    while i <= #s do memory.write_byte(b + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(b + #s, 0)
    return b
end

local out = memory.alloc(0x40)
local names = { "sceKernelJitCreateSharedMemory", "sceKernelMapFlexibleMemory", "socket", "getpid", "mmap" }

local handle = 0
while handle < 16 do
    local i = 1
    while i <= #names do
        memory.write_qword(out, u64(0, 0))
        local rv = call(0x24f, handle, sgn(cstr(names[i])), sgn(out), 0, 0, 0)
        local got = rdq(out)
        if rv == 0 or (got ~= 0 and got ~= 0xFFFFFFFFFFFFFFFF) then
            print(string.format("[A] handle=%d %-32s rv=%d out=0x%X", handle, names[i], rv, got))
        end
        i = i + 1
    end
    handle = handle + 1
end
print("[A] sweep done")

-- [B] the two-argument form again with the out pointer in slot 3 and a NID-shaped name
local nid = memory.alloc(0x10)
memory.write_byte(nid + 0, 0x84)
memory.write_byte(nid + 1, 0x7C)
memory.write_byte(nid + 2, 0x5F)
memory.write_byte(nid + 3, 0x5B)
memory.write_byte(nid + 4, 0)
local rv2 = call(0x24f, 1, sgn(nid), sgn(out), 0, 0, 0)
print(string.format("[B] NID-string form rv=%d out=0x%X", rv2, rdq(out)))
print("=== 427a DONE ===")
