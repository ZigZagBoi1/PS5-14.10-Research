-- CRASH_CLASS: HIGH
-- PROBE 784a: does the worker interpret the 32 bytes 557 copies?
--
-- 557 mallocs 0x20, copies 32 user bytes into it, wraps it in 0x18
-- {[0]=payload, [8]=uap[1]}, registers it under an aio id and (when the
-- state gate is open) submits it. If the worker reads the payload as a
-- struct, a payload of bad pointers faults; zeros do not. Three creates
-- only, because the submit queue holds about two.
print("=== PROBE 784a: SYS 557 PAYLOAD ===")
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
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
local function payload(mode)
    zero(page,0x80)
    if mode=="ff" then for i=0,3 do wq(page+i*8, 0xFFFFFFFFFFFFFFFF) end end
    if mode=="z" then for i=0,3 do wq(page+i*8, 0) end end
    if mode=="mix" then wq(page,0); wq(page+8,0x1000); wq(page+0x10,0); wq(page+0x18,0) end
end
local function one(tag,mode,arg2)
    payload(mode)
    local r=call(mk(557),page,arg2 or 0x1000,0,0,0,0)
    print(string.format("[%s] 557 payload=%s arg2=%s -> %s alive=%s",tag,mode,tostring(arg2 or 0x1000),tostring(r),alive()))
    return r
end
local id1=one("A","z")
call(mk(136),0,0,0,0,0,0)  -- nanosleep(0) is not this; harmless no-op probe
print("[A] after create alive="..alive())
local id2=one("B","ff")
print("[B] after bad payload alive="..alive())
local id3=one("C","mix",0x10)
print("[C] after mixed alive="..alive())
-- destroy in reverse order; a destroy of a completed job should be clean
for i,id in ipairs({id3,id2,id1}) do
    if type(id)=="number" and id>0 then
        print(string.format("[D] 558(%s)=%s alive=%s",tostring(id),tostring(call(mk(558),id,0,0,0,0,0)),alive()))
    else
        print(string.format("[D] skip %s",tostring(id)))
    end
end
print("[E] final alive="..alive())
print("=== 784a DONE ===")
