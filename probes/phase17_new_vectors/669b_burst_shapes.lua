-- CRASH_CLASS: HIGH
-- PROBE 669b: which block-delete shape kills the process? One block of 32 is
-- deleted item by item (A), then in a single count=32 call (B), then sixteen
-- 2-item blocks are deleted item by item (C). A print after every stage names
-- the exact call.
print("=== PROBE 669b: BLOCK BURST SHAPES ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662=mk(669),mk(664),mk(662)
local DATA=memory.alloc(0x2000)
local OUT=memory.alloc(0x40)
local IDARR=memory.alloc(0x400)
local STAT=memory.alloc(0x400)
for i=0,0x1FFC,4 do wd(N(DATA)+i,0) end
local function addrids(bid,n) for i=0,n-1 do wd(N(IDARR)+i*4, bid+i*0x10000) end end
local function mkblock(n)
  wd(N(OUT),0)
  local o,r=pcall(function() return sc669(U(0x1001),U(N(DATA)),U(n),U(1),U(N(OUT)),U(0)) end)
  return (o and N(r)==0), rd(N(OUT)) or 0
end
local function pollall(n)
  wd(N(STAT),0)
  pcall(function() sc664(U(N(IDARR)),U(1),U(N(STAT)),U(0),U(0),U(0)) end)
  return rd(N(STAT))
end
print("[A] one block of 32, delete item by item")
local ok,bid=mkblock(32)
print(string.format("[A1] create ok=%s base=%X",tostring(ok),bid))
if not ok then return end
addrids(bid,32)
print(string.format("[A2] poll0=%X",pollall(32) or 0))
local z=0
for i=0,31 do
  local o,r=pcall(function() return sc662(U(N(IDARR)+i*4),U(1),U(N(STAT))) end)
  wd(N(STAT),0)
  pcall(function() sc662(U(N(IDARR)+i*4),U(1),U(N(STAT))) end)
  if rd(N(STAT))==0 then z=z+1 end
  if i==0 or i==31 then print(string.format("[A3] item %d done z=%d",i,z)) end
end
print(string.format("[A4] deleted=%d of 32",z))
print("[B] one block of 32, delete with count=32")
local ok2,bid2=mkblock(32)
print(string.format("[B1] create ok=%s base=%X",tostring(ok2),bid2))
if not ok2 then return end
addrids(bid2,32)
print(string.format("[B2] poll0=%X",pollall(32) or 0))
for i=0,31 do wd(N(STAT)+i*4,0x77777777) end
local o,r=pcall(function() return sc662(U(N(IDARR)),U(32),U(N(STAT))) end)
print(string.format("[B3] call ok=%s rv=%s s0=%X s31=%X",tostring(o),tostring(r),rd(N(STAT)) or 0,rd(N(STAT)+124) or 0))
print("[C] sixteen 2-item blocks, delete item by item")
local bases={}
for k=1,16 do local o3,b3=mkblock(2); if o3 then bases[k]=b3 end end
print(string.format("[C1] made=%d",#bases))
for k=1,#bases do
  for i=0,1 do
    wd(N(IDARR),bases[k]+i*0x10000)
    pcall(function() sc664(U(N(IDARR)),U(1),U(N(STAT)),U(0),U(0),U(0)) end)
    wd(N(STAT),0)
    pcall(function() sc662(U(N(IDARR)),U(1),U(N(STAT))) end)
  end
end
print("[C2] done")
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
