-- CRASH_CLASS: HIGH
-- PROBE 687a: syscall 670 (narg 4) is the last unidentified member of the aio
-- syscall block. Hold two live objects, call 670 with the id array, and see
-- whether they survive (poll still 3) or disappear.
print("=== PROBE 687a: SYS 670 SHAPE ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662,sc670=mk(669),mk(664),mk(662),mk(670)
local data=memory.alloc(0x800)
for i=0,0x7FC,4 do wd(N(data)+i,0) end
local out=memory.alloc(0x40); wd(N(out),0)
local r=N(select(2,pcall(function() return sc669(U(0x1001),U(N(data)),U(2),U(1),U(N(out)),U(0)) end)))
local base=rd(N(out))
print(string.format("[A] create ret=%s base=%04X",tostring(r),base or 0))
local ids=memory.alloc(0x40)
wd(N(ids),base); wd(N(ids)+4,base+0x10000)
local chk=memory.alloc(0x40)
local function pol(i)
  wd(N(chk),0x77777777)
  pcall(function() sc664(U(N(ids)+i*4),U(1),U(N(chk)),U(0),U(0),U(0)) end)
  return rd(N(chk))
end
print(string.format("[B] poll0=%s poll1=%s",tostring(pol(0)),tostring(pol(1))))
for _,shape in ipairs({{0,2,0},{2,0,0},{1,1,0}}) do
  local page=memory.alloc(0x100); for i=0,0xFC,4 do wd(N(page)+i,0xAAAAAAAA) end
  local p1,p2,p3=shape[1],shape[2],shape[3]
  local o,rv=pcall(function() return sc670(U(N(ids)),U(p1),U(N(page)),U(p2),U(0),U(0)) end)
  print(string.format("[C] 670(ids,%d,page,%d) ok=%s rv=%s page0=%08X page4=%08X",
    p1,p2,tostring(o),tostring(rv),rd(N(page)) or 0,rd(N(page)+4) or 0))
  print(string.format("    after: poll0=%s poll1=%s",tostring(pol(0)),tostring(pol(1))))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
