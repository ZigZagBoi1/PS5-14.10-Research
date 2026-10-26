-- CRASH_CLASS: LOW
-- PROBE 658a: does SCM_RIGHTS work from OUR loader? PR #152 says yes (526a).
print("=== PROBE 658a: SCM_RIGHTS FROM THE LUA LOADER ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sv=memory.alloc(8)
local r=select(2,pcall(function() return mk(135)(U(1),U(1),U(0),U(N(sv)),U(0),U(0)) end))
local A,B=rdd(N(sv)),rdd(N(sv)+4)
print(string.format("[A] socketpair rv=%s A=%s B=%s",tostring(r),tostring(A),tostring(B)))
if not A or A<=0 then return end
local V=select(2,pcall(function() return mk(5)(U(N(memory.alloc(16))),U(0),U(0),U(0),U(0),U(0)) end))
-- proper open("/dev/zero")
local path=memory.alloc(16)
for i,c in ipairs({47,100,101,118,47,122,101,114,111,0}) do pcall(function() memory.write_byte(path+i-1,c) end) end
local fv=select(2,pcall(function() return mk(5)(U(N(path)),U(0),U(0),U(0),U(0),U(0)) end))
print(string.format("[B] open /dev/zero rv=%s",tostring(fv)))
local fdv=N(fv)
if fdv<=0 then return end
local data=memory.alloc(16); pcall(function() memory.write_byte(data,65) end)
local iov=memory.alloc(16); wq(N(iov),N(data)); wq(N(iov)+8,1)
local ctl=memory.alloc(64)
local mh=memory.alloc(0x40)
wq(N(mh),0); wd(N(mh)+8,0); wq(N(mh)+0x10,N(iov)); wq(N(mh)+0x18,1)
wq(N(mh)+0x20,N(ctl)); wd(N(mh)+0x28,24); wd(N(mh)+0x30,0)
wq(N(ctl),20); wd(N(ctl)+8,0xFFFF); wd(N(ctl)+0xC,1); wd(N(ctl)+0x10,fdv)
local s=select(2,pcall(function() return mk(28)(U(A),U(N(mh)),U(0),U(0),U(0),U(0)) end))
print(string.format("[C] sendmsg rv=%s",tostring(s)))
local rb=memory.alloc(16); pcall(function() memory.write_byte(rb,0) end)
local iov2=memory.alloc(16); wq(N(iov2),N(rb)); wq(N(iov2)+8,1)
local ctl2=memory.alloc(64)
local mh2=memory.alloc(0x40)
wq(N(mh2),0); wd(N(mh2)+8,0); wq(N(mh2)+0x10,N(iov2)); wq(N(mh2)+0x18,1)
wq(N(mh2)+0x20,N(ctl2)); wd(N(mh2)+0x28,64); wd(N(mh2)+0x30,0)
local rr=select(2,pcall(function() return mk(27)(U(B),U(N(mh2)),U(0),U(0),U(0),U(0)) end))
local clen=rdd(N(mh2)+0x28)
print(string.format("[D] recvmsg rv=%s controllen=%s",tostring(rr),tostring(clen)))
if clen and clen>0 then
  local l=rd(N(ctl2)); local lev=rdd(N(ctl2)+8); local typ=rdd(N(ctl2)+0xC); local fd=rdd(N(ctl2)+0x10)
  print(string.format("[E] cmsg_len=%s level=%X type=%d fd=%s",tostring(l),lev or 0,typ or 0,tostring(fd)))
  if fd and fd>0 then
    local st=memory.alloc(0x100)
    local fr=select(2,pcall(function() return mk(189)(U(fd),U(N(st)),U(0),U(0),U(0),U(0)) end))
    print(string.format("[F] fstat(received %d) rv=%s mode=%X",fd,tostring(fr),rdd(N(st)+4) or 0))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
