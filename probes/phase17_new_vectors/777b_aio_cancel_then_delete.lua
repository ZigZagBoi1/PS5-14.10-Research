-- CRASH_CLASS: LOW
-- PROBE 777a: can cancel drain the wedged queue?
--
-- Creates have been answering state 1 (not started) since a bad run left
-- three jobs that never completed. Delete refuses them (state gate). If 666
-- cancel reaches a not-started job, canceling the old ids may drain the
-- queue and save a relaunch.
print("=== PROBE 777b: AIO CANCEL THEN DELETE ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local D=to_num(memory.alloc(0x400)); local buf=to_num(memory.alloc(0x1000))
local res=to_num(memory.alloc(0x100)); local ids=to_num(memory.alloc(0x40))
local st=to_num(memory.alloc(0x40)); local fds=to_num(memory.alloc(0x20))
local function pair()
    zero(fds,0x20); wd(fds,0xFFFF); wd(fds+4,0xFFFF)
    call(mk(135),1,1,0,fds,0,0)
    local s0,s1=rd(fds),rd(fds+4)
    if type(s0)~="number" or s0<=0 or s0==0xFFFF then return nil end
    return s0,s1
end
local function create(fd,len,bufp,resp)
    zero(D,0x400); zero(st,0x40)
    wq(D+0x00,0); wq(D+0x08,len); wq(D+0x10,bufp); wq(D+0x18,resp)
    wd(D+0x20,fd); wd(D+0x24,0)
    local r=call(mk(669),0x1001,D,1,1,st,0)
    return r, rd(st)
end
local function poll(id)
    zero(res,0x100); wd(ids,id)
    local r=call(mk(664),ids,1,res,0,0,0)
    return r, rd(res)
end
local function cancel(id)
    zero(res,0x100); wd(ids,id)
    local r=call(mk(666),ids,1,res,0,0,0)
    return r, rd(res)
end
local function del2(id)
    zero(res,0x100); wd(ids,id)
    local r=call(mk(662),ids,1,res,0,0,0)
    return r, rd(res)
end
local s0,s1=pair()
zero(buf,0x1000)
local r,id=create(s0,16,buf,res)
local p,stt=poll(id)
print(string.format("[A] before cancel: create=%s id=%08X state=%08X",tostring(r),id or 0,stt))
if stt ~= 1 then print("[A] not wedged, nothing to do") return end
-- cancel a window of ids around the wedged ones
local lo=0x0200
local hit,delok=0,0
for i=0,0x1F do
    local cand=lo+i
    local cr,co=cancel(cand)
    if cr==0 and co==4 then
        hit=hit+1
        local dr,ds=del2(cand)
        if dr==0 and ds==0 then delok=delok+1 end
        print(string.format("[B] %08X cancel=%s state=%08X delete=%s st=%08X",cand,tostring(cr),co,tostring(dr),ds))
    end
end
print(string.format("[B] window done cancelled=%d deleted=%d",hit,delok))
local r2,id2=create(s0,16,buf,res)
local p2,st2=poll(id2)
print(string.format("[C] after cancel: create=%s id=%08X state=%08X",tostring(r2),id2 or 0,st2))
print("[D] alive="..tostring(call(mk(20),0,0,0,0,0,0)))
print("=== 777b DONE ===")
