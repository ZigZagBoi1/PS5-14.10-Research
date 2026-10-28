-- CRASH_CLASS: HIGH
-- PROBE 786a: how many 557 objects can exist, and does destroy restore capacity
print("=== PROBE 786a: SYS 557 CAPACITY ===")
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
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local page=to_num(memory.alloc(0x1000)); zero(page,0x1000)
local ids={}
for i=1,32 do
    local r=call(mk(557),page,0x1000,0,0,0,0)
    if type(r)=="number" and r>0 then ids[#ids+1]=r else print(string.format("[A] stopped at %d (ret=%s)",i,tostring(r))) break end
end
print(string.format("[A] creates-ok=%d first=%s last=%s alive=%s",#ids,tostring(ids[1]),tostring(ids[#ids]),alive()))
-- destroy them all and try again
local d=0
for _,id in ipairs(ids) do if call(mk(558),id,0,0,0,0,0)==0 then d=d+1 end end
print(string.format("[B] destroyed=%d alive=%s",d,alive()))
local ids2={}
for i=1,32 do
    local r=call(mk(557),page,0x1000,0,0,0,0)
    if type(r)=="number" and r>0 then ids2[#ids2+1]=r else break end
end
print(string.format("[C] after destroy creates=%d first=%s last=%s alive=%s",#ids2,tostring(ids2[1]),tostring(ids2[#ids2]),alive()))
-- create/destroy loop: does it stay healthy for many cycles?
local cyc=0
for i=1,40 do
    local id=call(mk(557),page,0x1000,0,0,0,0)
    if type(id)=="number" and id>0 then
        if call(mk(558),id,0,0,0,0,0)==0 then cyc=cyc+1 end
    else break end
end
print(string.format("[D] churn cycles=%d alive=%s",cyc,alive()))
print("=== 786a DONE ===")
