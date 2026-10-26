-- CRASH_CLASS: MODERATE
-- PROBE 667b: control for 667a. Same pre-allocated 32-item create/poll/delete
-- burst from the parent, 20 rounds, but no delete chains. Establishes that the
-- burst alone is safe before blaming the race.
print("=== PROBE 667b: AIO BURST CONTROL (NO CHAINS) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662=mk(669),mk(664),mk(662)
local DATA=memory.alloc(0x1000)
local OUT=memory.alloc(8)
local IDP=memory.alloc(8)
local ST=memory.alloc(8)
local NIT=32
local made,del,refused=0,0,0
for round=1,20 do
  wd(N(OUT),0)
  local r,id=N(select(2,pcall(function() return sc669(U(0x1001),U(N(DATA)),U(NIT),U(1),U(N(OUT)),U(0)) end))), rd(N(OUT)) or 0
  if r~=0 then print(string.format("[E] round %d create rv=%s",round,tostring(r))) break end
  made=made+1
  wd(N(IDP),id); wd(N(ST),0)
  pcall(function() sc664(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)
  wd(N(ST),0)
  local rr=N(select(2,pcall(function() return sc662(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)))
  if rr==0 and rd(N(ST))==0 then del=del+1 else refused=refused+1 end
  if round%5==0 then print(string.format("[D] round %d made=%d del=%d refused=%d",round,made,del,refused)) end
end
print(string.format("[H] made=%d deleted=%d refused=%d",made,del,refused))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
