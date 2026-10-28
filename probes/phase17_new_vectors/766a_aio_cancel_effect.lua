-- CRASH_CLASS: MODERATE
-- PROBE 766a: what aio_multi_cancel (666) does to a completed object
--
-- The delete's path holds the table lock from lookup to free, so a second 662
-- can never enter the re-lookup window. 666 is the only other operation that
-- touches a live object, so it is the candidate partner for the swap the
-- 14.20 note describes. This measures its serial effect first: state before
-- and after the cancel, and whether the object is still deletable.
print("=== PROBE 766a: AIO CANCEL EFFECT ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local U=function(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local page=0x2000
local D=to_num(memory.alloc(page)); zero(D,page)
local idc=to_num(memory.alloc(0x40)); zero(idc,0x40)
local ids=to_num(memory.alloc(0x40)); zero(ids,0x40)
local out=to_num(memory.alloc(page)); zero(out,page)
local function mkbuf() zero(D,page); zero(idc,0x40); return call(mk(669),0x1001,D,1,1,idc,0), rd(idc) or 0 end
local function poll(id)
    wd(ids,id); zero(out,page)
    local r=call(mk(664),ids,1,out,0,0,0)
    return r, rd(out) or 0
end
local function del(id)
    wd(ids,id); zero(out,page)
    local r=call(mk(662),ids,1,out,0,0,0)
    return r, rd(out) or 0
end
local function cancel(id)
    wd(ids,id); zero(out,page)
    local r=call(mk(666),ids,1,out,0,0,0)
    return r, rd(out) or 0
end
local cr,id=mkbuf()
print(string.format("[A] create=%s id=%08X",tostring(cr),id))
local r1,p1=poll(id); print(string.format("[A] poll before=%s state=%08X",tostring(r1),p1))
local cr2,id2=mkbuf()
local rr2,pp2=poll(id2)
local rc,oc=cancel(id2)
local r3,p3=poll(id2)
print(string.format("[B] id=%08X poll=%08X cancel=%s out=%08X poll after=%08X",id2,pp2,tostring(rc),oc,p3))
local rd1,d1=del(id2)
print(string.format("[B] delete after cancel=%s status=%08X",tostring(rd1),d1))
local r4,p4=poll(id); local rd2,d2=del(id)
print(string.format("[C] control id=%08X poll=%08X delete=%s status=%08X",id,p4,tostring(rd2),d2))
print("[D] health="..tostring(call(syscall.pipe,20,0,0,0,0,0,0)))
print("=== 766a DONE ===")
