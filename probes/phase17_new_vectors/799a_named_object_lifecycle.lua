-- CRASH_CLASS: MODERATE
-- PROBE 799a: the named-object table (549 create, 558 destroy)
--
-- 13.60 disassembly:
--   549 (narg 4): arg1 = pointer to a name string, copyinstr with a 0x20 bound into a fresh
--        malloc(0x20); arg2 flags with (a2 & ~0x103)==0 and (a2&3)!=3; arg3 = a signed int >= 0;
--        arg4 = an int with 0 < a4 and a3 <= a4. Then malloc(0x60), 0x8b5d55a0(obj, flags, a3, a4),
--        0x8ad598e0([proc+0xc48], &id), [obj+0x54] = 0. Registers the object in the table.
--   558 (narg 2): arg1 = a dword id, arg2 = a word flags OR'd with 0x1000; lookup in
--        [proc+0xc48]; if found: fdremove-style removal, unlock, free([obj]), free(obj).
--        558 does no reference count check and no callback.
--
-- So 549 creates and 558 destroys, on the same table. If a destroy can be repeated, or if a
-- destroy frees an object another syscall still holds, that is a use-after-free on a 0x60
-- kernel object whose first field is a user-derived string.
--
-- The probe never destroys an object twice on the same id inside one call, and it checks
-- liveness between phases.

print("=== PROBE 799a: NAMED OBJECT CREATE/DESTROY ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function A(v) return uint64(to_num(v)) end

local sc549 = make_syscall(549)
local sc558 = make_syscall(558)
local out = memory.alloc(0x100)

local function create(name, flags, a3, a4)
    local b = memory.alloc(0x40)
    for i = 0, 0x3C do safe_wb(b + i, 0) end
    for i = 1, #name do safe_wb(b + i - 1, name:byte(i)) end
    safe_wd(out, 0) safe_wd(out + 4, 0)
    local ok, rv = pcall(function()
        return sc549(A(b), A(flags), A(a3), A(a4))
    end)
    return ok and to_num(rv) or -999, safe_rd(out)
end

local function destroy(id)
    local ok, rv = pcall(function() return sc558(A(id), A(0)) end)
    return ok and to_num(rv) or -999
end

print("[A] create four named objects")
local ids = {}
for i = 1, 4 do
    local rv, o = create(string.format("OBJ%02d", i), 1, 0, 1)
    ids[i] = (rv > 0) and rv or o
    print(string.format("  name=OBJ%02d ret=%d out=%s", i, rv, o and string.format("%08X", o) or "nil"))
end

print("")
print("[B] same name twice")
local rv2, o2 = create("OBJ01", 1, 0, 1)
if rv2 > 0 then ids[5] = rv2 end
print(string.format("  ret=%d out=%s", rv2, o2 and string.format("%08X", o2) or "nil"))

print("")
print("[C] destroy each id once")
for i = 1, 5 do
    if ids[i] and ids[i] ~= 0 then
        print(string.format("  id=%08X ret=%d", ids[i], destroy(ids[i])))
    else
        print(string.format("  id[%d] missing", i))
    end
end

print("")
print("[D] destroy the first id again (repeat)")
if ids[1] and ids[1] ~= 0 then
    print(string.format("  id=%08X ret=%d", ids[1], destroy(ids[1])))
end

print("")
print("[E] create after destroy")
local rv3, o3 = create("OBJ99", 1, 0, 1)
if rv3 > 0 then o3 = rv3 end
print(string.format("  ret=%d out=%s", rv3, o3 and string.format("%08X", o3) or "nil"))
if o3 and o3 ~= 0 then print(string.format("  destroy ret=%d", destroy(o3))) end

print("")
print("[F] destroy ids that were never created")
print("  id=0        ret=" .. destroy(0))
print("  id=0x7fffffff ret=" .. destroy(0x7fffffff))
print("  id=0x12345678 ret=" .. destroy(0x12345678))

print("")
print("[G] alive")
