-- CRASH_CLASS: MODERATE
-- PROBE 699a: walk CTL_KERN nodes with a size query (no buffer), recording the
-- length each node reports. Nodes that answer are then worth reading on 14.10.
-- Prints before every call so the last line names a killer.
print("=== PROBE 699a: SYSCTL KERN NODE WALK ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc=mk(202)
local mib=memory.alloc(8)
local lp=memory.alloc(8)
local alive=0
for node=0,250 do
  wd(N(mib),1) wd(N(mib)+4,node)
  wd(N(lp),0)
  io.write(string.format("node %d ... ",node)); io.flush()
  local o,r=pcall(function() return sc(U(N(mib)),U(2),U(0),U(N(lp)),U(0),U(0)) end)
  local rv=o and N(r) or -999
  local ln=rd(N(lp)) or 0
  if rv==0 then
    alive=alive+1
    print(string.format("OK len=%d",ln))
  else
    print(string.format("rv=%s len=%d",tostring(rv),ln))
  end
end
print(string.format("[X] nodes answering=%d",alive))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
