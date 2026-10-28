-- CRASH_CLASS: LOW
-- PROBE 659a: why did sendmsg return -1? isolate the control message.
print("=== PROBE 659a: SENDMSG VARIANT MATRIX ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function pair()
  local sv=memory.alloc(8)
  local r=select(2,pcall(function() return mk(135)(U(1),U(1),U(0),U(N(sv)),U(0),U(0)) end))
  return N(r), rdd(N(sv)), rdd(N(sv)+4)
end
local function open_zero()
  local p=memory.alloc(16)
  for i,c in ipairs({47,100,101,118,47,122,101,114,111,0}) do wb(N(p)+i-1,c) end
  return N(select(2,pcall(function() return mk(5)(U(N(p)),U(0),U(0),U(0),U(0),U(0)) end)))
end
local data=memory.alloc(16); wb(N(data),65)
local iov=memory.alloc(16); wq(N(iov),N(data)); wq(N(iov)+8,1)
local iov4=memory.alloc(16); wq(N(iov4),N(data)); wq(N(iov4)+8,4)
local function sendm(A,ctl,clen,cflag,iv)
  local mh=memory.alloc(0x40)
  wq(N(mh),0); wd(N(mh)+8,0); wq(N(mh)+0x10,N(iv or iov)); wd(N(mh)+0x18,1)
  wq(N(mh)+0x20,ctl or 0); wd(N(mh)+0x28,clen or 0); wd(N(mh)+0x2C,0)
  if cflag then wd(N(mh)+0x30,0) end
  return N(select(2,pcall(function() return mk(28)(U(A),U(N(mh)),U(0),U(0),U(0),U(0)) end)))
end
local rv,A,B=pair(); print(string.format("[A] pair rv=%s A=%s B=%s",tostring(rv),tostring(A),tostring(B)))
print(string.format("[B] plain sendmsg=%s",tostring(sendm(A,nil,0))))
rv,A,B=pair()
local V=open_zero(); print(string.format("[C] open /dev/zero=%s",tostring(V)))
local ctl=memory.alloc(64)
for k=0,0x3F,8 do wq(N(ctl)+k,uint64(0)) end
wq(N(ctl),20); wd(N(ctl)+8,0xFFFF); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,V)
print(string.format("[D] cmsg 20/24 level=0xFFFF type=1 fd=%s sendmsg=%s",tostring(V),tostring(sendm(A,ctl,24))))
rv,A,B=pair()
wq(N(ctl),24); wd(N(ctl)+8,0xFFFF); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,V)
print(string.format("[E] cmsg 24/24 sendmsg=%s",tostring(sendm(A,ctl,24))))
rv,A,B=pair()
wq(N(ctl),20); wd(N(ctl)+8,1); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,V)
print(string.format("[F] cmsg level=1 sendmsg=%s",tostring(sendm(A,ctl,24))))
rv,A,B=pair()
wq(N(ctl),20); wd(N(ctl)+8,0xFFFF); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,V)
print(string.format("[G] cmsg 20/20 sendmsg=%s",tostring(sendm(A,ctl,20))))
rv,A,B=pair()
wq(N(ctl),20); wd(N(ctl)+8,0xFFFF); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,V)
print(string.format("[H] iov len 4 cmsg 20/24 sendmsg=%s",tostring(sendm(A,ctl,24,nil,iov4))))
rv,A,B=pair()
print(string.format("[I] iov len 4 plain sendmsg=%s",tostring(sendm(A,nil,0,nil,iov4))))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
