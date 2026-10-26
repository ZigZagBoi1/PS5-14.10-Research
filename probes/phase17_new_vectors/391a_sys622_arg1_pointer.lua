-- CRASH_CLASS: MODERATE
-- PROBE 391a: is sys 622's first argument an index or a pointer
--
-- 622 is the only handler in 400-676 that dies on its own. Measured so far: every
-- command in the 0x400 group with a successful copy of at least one byte kills the
-- process after the copy (247a), a one-byte copy also dies (245a), filling all 0x40
-- copied bytes with a valid self-pointer still dies (355c), and arg1 as an integer
-- 0-15 or as an open descriptor both die (306a, 357a). The dossier calls arg1 a
-- device index, but an index lookup that always faults looks more like a pointer
-- that is dereferenced.
--
-- This passes arg1 as four different user addresses: a zeroed page, a page holding
-- the string "gc", a page whose first qword is zero, and a page whose first qword
-- points at itself. Each call is preceded by a marker so a death names the shape.
-- If any shape survives, arg1 is a user pointer and the handler becomes shapeable.

print("=== PROBE 391a: SYS 622 ARG1 POINTER ===")
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
local sc622 = make_syscall(622)

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(x) return uint64(string.format("0x%X", x)) end
local function zero(addr, n) for i = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + i, 0) end) end end

local a1 = memory.alloc(0x1000)   -- zeroed page
local a2 = memory.alloc(0x1000)   -- "gc\0" string
local a3 = memory.alloc(0x1000)   -- qword zero
local a4 = memory.alloc(0x1000)   -- qword pointing at itself
local out = memory.alloc(0x200)
local a3b = memory.alloc(0x1000)  -- struct page used as arg3
zero(a1, 0x1000); zero(a2, 0x1000); zero(a3, 0x1000); zero(a4, 0x1000)
zero(a3b, 0x1000); zero(out, 0x200)

pcall(function()
    memory.write_byte(a2, 0x67) memory.write_byte(a2 + 1, 0x63) memory.write_byte(a2 + 2, 0)
    memory.write_qword(a4, uint64(string.format("0x%X", 0)))
end)

local function addr_of(obj)
    return sgn(uint64(obj))
end
local p1 = addr_of(a1)
local p2 = addr_of(a2)
local p3 = addr_of(a3)
local p4 = addr_of(a4)
local p3b = addr_of(a3b)
local pout = addr_of(out)
-- self pointer in a4
pcall(function() memory.write_qword(a4, u64(p4)) end)

local shapes = {
    { name = "zeroed page", v = p1 },
    { name = "string 'gc'", v = p2 },
    { name = "qword zero", v = p3 },
    { name = "self pointer", v = p4 },
}

for _, s in ipairs(shapes) do
    print(string.format("[BEFORE] cmd=0x400 arg1=%s (0x%X)", s.name, s.v))
    local ret = -999
    local ok = pcall(function()
        ret = sgn(sc622(u64(0x400), u64(s.v), u64(p3b), u64(p3b), u64(0x40), u64(0)))
    end)
    print(string.format("[AFTER ] ret=%d ok=%s out=%08X %08X", ret, tostring(ok),
        to_num(memory.read_dword(out)), to_num(memory.read_dword(out + 4))))
end

print("")
print("=== 391a DONE ===")
