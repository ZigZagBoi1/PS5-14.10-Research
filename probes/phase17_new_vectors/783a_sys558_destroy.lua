-- CRASH_CLASS: HIGH
-- PROBE 783a: 558 destroy, and the table cap that stopped 557
--
-- 781a created 15 objects (ids 0x207..0x215) with no destroys; 782a's next
-- 557 then answered -1. Either the table has a small cap or the payload copy
-- started failing. Destroy the known ids and retry the create.
print("=== PROBE 783a: SYS 558 DESTROY ===")
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
    if not ok then return "ERR" end
    return to_num(r)
end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
for i=0,7 do pcall(function() memory.write_dword(page+i*4, 0x41414141+i) end) end
local function mk557(tag)
    local r=call(mk(557),page,0x1000,0,0,0,0)
    print(string.format("[A] 557(%s)=%s alive=%s",tag,tostring(r),alive()))
    return r
end
print("[0] before sweep alive="..alive())
local found,missing=0,0
for id=0x205,0x225 do
    local r=call(mk(558),id,0,0,0,0,0)
    if r==0 then found=found+1 end
    if r==0 then print(string.format("[B] 558(%08X)=0",id)) end
    if r=="ERR" then print(string.format("[B] 558(%08X)=ERR",id)) end
    missing=missing+1
end
print(string.format("[B] destroyed=%d of %d swept alive=%s",found,missing,alive()))
-- retry the create after the destroys
local a=mk557("after")
local b=mk557("after2")
-- destroy the ones we just made, twice each
if type(a)=="number" and a>0 then
    print(string.format("[C] 558(%s)=%s",tostring(a),tostring(call(mk(558),a,0,0,0,0,0))))
    print(string.format("[C] 558(%s) again=%s alive=%s",tostring(a),tostring(call(mk(558),a,0,0,0,0,0)),alive()))
end
if type(b)=="number" and b>0 then
    print(string.format("[C] 558(%s)=%s alive=%s",tostring(b),tostring(call(mk(558),b,0,0,0,0,0)),alive()))
end
-- [D] does create/destroy now churn cleanly?
local ok=0
for i=1,32 do
    local id=mk557("c"..i)
    if type(id)=="number" and id>0 then
        if call(mk(558),id,0,0,0,0,0)==0 then ok=ok+1 end
    end
end
print(string.format("[D] churn ok=%d/32 alive=%s",ok,alive()))
print("=== 783a DONE ===")
