-- CRASH_CLASS: MODERATE
-- PROBE 771a: does EVFILT_SIGNAL work on 14.10?
--
-- The kernel surface reachable from the Lua loader has no memory primitive
-- left, but kqueue is untouched apart from fd filters: kevent registers and
-- polls READ filters successfully (probes 20/21).  EVFILT_SIGNAL attaches a
-- knote to a signal number, which is a different object lifetime and the
-- shape of several historical FreeBSD UAFs.  This probe only establishes
-- whether the filter exists, counts deliveries, and survives deregistration.
print("=== PROBE 771a: KQUEUE SIGNAL BASIC ===")
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
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function ww(a,v) pcall(function() memory.write_word(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local SIGUSR1=30
local EV_ADD=0x0001
local EV_DELETE=0x0002
local EV_CLEAR=0x0020
local EVFILT_SIGNAL=0xFFFA   -- -6 in 16 bits
local pid=call(mk(20),0,0,0,0,0,0)
print("[A] pid="..tostring(pid))
local act=to_num(memory.alloc(0x40)); zero(act,0x40)
wd(act,1)                       -- SIG_IGN
print("[A] sigaction(30,SIG_IGN)="..tostring(call(mk(416),SIGUSR1,act,0,0,0,0)))
local kq=call(mk(362),0,0,0,0,0,0)
print("[B] kqueue="..tostring(kq))
if type(kq)~="number" or kq<0 then print("[B] no kqueue") return end
local ch=to_num(memory.alloc(0x40)); zero(ch,0x40)
local ev=to_num(memory.alloc(0x200)); zero(ev,0x200)
local ts=to_num(memory.alloc(0x10)); zero(ts,0x10)
wq(ch+0,SIGUSR1); ww(ch+8,EVFILT_SIGNAL); ww(ch+10,EV_ADD)
print("[C] register="..tostring(call(mk(363),kq,ch,1,ev,1,ts)))
for i=1,5 do call(mk(37),pid,SIGUSR1,0,0,0,0) end
zero(ev,0x200)
local n=call(mk(363),kq,0,0,ev,4,ts)
print(string.format("[D] poll=%s ident=%d filter=%04X data=%s flags=%04X",
    tostring(n),rq(ev) or 0,rd(ev+8)%65536,rq(ev+16) or 0,rd(ev+10)%65536))
ww(ch+10,EV_DELETE)
print("[E] delete="..tostring(call(mk(363),kq,ch,1,ev,1,ts)))
for i=1,200 do call(mk(37),pid,SIGUSR1,0,0,0,0) end
zero(ev,0x200)
print("[E] poll after delete="..tostring(call(mk(363),kq,0,0,ev,4,ts)))
print("[F] alive="..tostring(call(mk(20),0,0,0,0,0,0)))
print("=== 771a DONE ===")
