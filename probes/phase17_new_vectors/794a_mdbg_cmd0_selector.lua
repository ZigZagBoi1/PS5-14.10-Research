-- CRASH_CLASS: LOW
-- PROBE 794a: mdbg cmd 0 takes a 0x10-byte input struct
--
-- The 13.60 dispatcher feeds cmd 0 from 0xca067f, which first does
--   copyin(uap[1], [rbp-0xf0], 0x10)
-- so the argument is a 0x10-byte request, and the reply lands back in it.
-- Our earlier calls always sent sixteen zero bytes and got 0x100 back.
-- This probe walks the first dword as a selector and prints the reply.

print("=== PROBE 794a: mdbg cmd 0 selector ===")
print("")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
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
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local function rd(a)
    local o, v = pcall(function() return memory.read_dword(a) end)
    if o then return to_num(v) % 4294967296 end
    return 0
end
local Z = uint64(0)
local f = make_syscall(601)
for sel = 0, 0x10 do
    local p = to_num(memory.alloc(0x100))
    for i = 0, 0x3F do pcall(function() memory.write_dword(p + i * 4, 0) end) end
    pcall(function() memory.write_dword(p, sel) end)
    local r = sgn(f(U(0), U(p), Z, Z, Z, Z))
    print(string.format("  sel=%02X ret=%s  %08X %08X %08X %08X",
        sel, r, rd(p), rd(p + 4), rd(p + 8), rd(p + 12)))
end
print("=== PROBE 794a END ===")
