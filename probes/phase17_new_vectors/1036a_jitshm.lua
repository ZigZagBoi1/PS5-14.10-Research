-- CRASH_CLASS: MODERATE
-- PROBE 1036a: 533 jitshm_create — is the JIT shared-memory path open on 14.10?
print("=== PROBE 1036a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local sc533=mk(533); local sc534=mk(534); local sc477=mk(477); local sc74=mk(74)
local names={0,1,0x1000}
local out=memory.alloc(0x40)
for i=1,#names do
  wd(out,0xDEADBEEF)
  local ok,v=pcall(function() return sc533(A(names[i]),A(0x1000),A(out),A(0)) end)
  print(string.format("[C%d] 533(name=%X,0x1000,out) rv=%s out=%X", i, names[i], tostring(ok and to_num(v) or "FI"), rd(out)))
end
-- 2-arg and 1-arg shapes
for _,n in ipairs({0,1}) do
  local ok,v=pcall(function() return sc533(A(n),A(0x1000),A(0),A(0)) end)
  print(string.format("[D] 533(%X,0x1000) rv=%s", n, tostring(ok and to_num(v) or "FI")))
end
-- if any returned an fd, try mmap with prot 7
local fd=rd(out)
if fd>0 and fd<0x1000 then
  local ok,m=pcall(function() return sc477(A(fd),A(0x1000),A(7),A(0x1002),A(fd),A(0)) end)
  print(string.format("[M] mmap(fd=%d,prot=7) rv=%s", fd, tostring(ok and to_num(m) or "FI")))
  local ok2,p=pcall(function() return sc74(A(to_num(m)),A(0x1000),A(7),A(0)) end)
  print(string.format("[M] mprotect(prot=7) rv=%s", tostring(ok2 and to_num(p) or "FI")))
end
-- 535 dl_get_list / 536 dl_get_info as a cross-check of the dynlib family
local sc535=mk(535); local sc536=mk(536)
local buf=memory.alloc(0x400)
for i=0,0x80 do wd(buf+i*4,0xCDCDCDCD) end
local ok,v=pcall(function() return sc535(A(buf),A(0x400),A(0)) end)
print(string.format("[L] 535 rv=%s b0=%X b1=%X", tostring(ok and to_num(v) or "FI"), rd(buf), rd(buf+4)))
for i=0,0x80 do wd(buf+i*4,0xCDCDCDCD) end
local ok2,v2=pcall(function() return sc536(A(buf),A(0x400),A(0)) end)
print(string.format("[L] 536 rv=%s b0=%X b1=%X", tostring(ok2 and to_num(v2) or "FI"), rd(buf), rd(buf+4)))
print("[Z] alive")
