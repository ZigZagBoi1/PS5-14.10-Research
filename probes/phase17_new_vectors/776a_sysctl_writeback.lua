-- CRASH_CLASS: LOW
-- PROBE 776a: which kern.* sysctls accept a write from this process?
--
-- The aio submit and record paths are gated on a kernel global that is
-- exported through a sysctl handler (13.60: 0x8b4c7980 does the
-- sysctl_handle_int dance on 0xffffffff8c2a446c).  If that node is
-- writable from here, aio's record copyout becomes reachable.  Writing the
-- *same* value back tests writability without changing any state.
print("=== PROBE 776a: SYSCTL WRITE-BACK ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local sc=mk(202)
local mib=memory.alloc(16) local buf=memory.alloc(256) local lp=memory.alloc(8) local nb=memory.alloc(16)
local function wr(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
wr(mib,1)
local writable=0
for node=0,251 do
  wr(mib+4,node); wr(lp,256); wr(buf,0)
  local ok,r=pcall(function() return sc(uint64(mib),uint64(2),uint64(buf),uint64(lp),uint64(0),uint64(0)) end)
  if ok and to_num(r)==0 then
    local len=rd(lp) local v=rd(buf)
    if len==4 then
      wr(nb,v)
      local ok2,r2=pcall(function() return sc(uint64(mib),uint64(2),uint64(0),uint64(0),uint64(nb),uint64(4)) end)
      local rv = (ok2 and to_num(r2)) or -999
      if rv==0 then writable=writable+1 end
      print(string.format("kern.%-4d len=4 val=%d write=%s",node,v,tostring(rv)))
    elseif len==8 then
      print(string.format("kern.%-4d len=8",node))
    end
  end
end
print("writable int nodes: "..writable)
print("=== DONE 776a ===")
