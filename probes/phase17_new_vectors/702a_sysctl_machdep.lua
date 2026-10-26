-- CRASH_CLASS: MODERATE
-- PROBE 702a: sweep CTL_MACHDEP (7) nodes with a size query. The kexp payload
-- reads machdep.openpsid, so this subtree exists on the console; look for nodes
-- that answer and for any that return kernel-shaped data.
print("=== PROBE 702a: SYSCTL CTL_MACHDEP SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc=mk(202)
local mib=memory.alloc(8)
local lp=memory.alloc(8)
local buf=memory.alloc(0x1000)
local CTL=7
for node=0,200 do
  wd(N(mib),CTL) wd(N(mib)+4,node)
  wd(N(lp),0x1000)
  for i=0,0xFC0,4 do wd(N(buf)+i,0) end
  local o,r=pcall(function() return sc(U(N(mib)),U(2),U(N(buf)),U(N(lp)),U(0),U(0)) end)
  local rv=o and N(r) or -999
  local ln=rd(N(lp)) or 0
  if rv==0 then
    local parts={}
    for i=0,math.min(ln,24)-1,4 do parts[#parts+1]=string.format("%08X",N(memory.read_dword(N(buf)+i))) end
    print(string.format("OK %d.%d len=%d q=[%s]",CTL,node,ln,table.concat(parts," ")))
  elseif rv~=0 and rv~=-1 then
    print(string.format("XO %d.%d rv=%s",CTL,node,tostring(rv)))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
