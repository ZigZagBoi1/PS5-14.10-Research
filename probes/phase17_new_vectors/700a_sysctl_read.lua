-- CRASH_CLASS: MODERATE
-- PROBE 700a: read the 21 answering kern nodes and print their contents, flagging
-- any qword whose high half looks like a kernel address.
print("=== PROBE 700a: SYSCTL KERN NODE CONTENTS ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function hi(v) return math.floor(N(v)/4294967296) end
local sc=mk(202)
local mib=memory.alloc(8)
local lp=memory.alloc(8)
local buf=memory.alloc(0x1000)
local nodes={1,2,3,4,8,10,17,18,20,21,24,33,35,36,38,39,41,46,50,51,52}
for _,node in ipairs(nodes) do
  wd(N(mib),1) wd(N(mib)+4,node)
  wd(N(lp),0x1000)
  for i=0,0xFC0,4 do wd(N(buf)+i,0) end
  local o,r=pcall(function() return sc(U(N(mib)),U(2),U(N(buf)),U(N(lp)),U(0),U(0)) end)
  local rv=o and N(r) or -999
  local ln=N(memory.read_dword(N(lp)))or 0
  local parts={}
  for i=0,math.min(ln,32)-1,4 do parts[#parts+1]=string.format("%08X",N(memory.read_dword(N(buf)+i))) end
  local asc={}
  for i=0,math.min(ln,48)-1 do local b=N(memory.read_byte(N(buf)+i)) if b>=32 and b<127 then asc[#asc+1]=string.char(b) end end
  local kern=0
  for i=0,math.min(ln,0x400)-8,8 do
    local v=rq(N(buf)+i) if v then local h=hi(v) if h>=0xFFFF8000 and h<=0xFFFFFFFF then kern=kern+1 end end
  end
  print(string.format("[%d] rv=%d len=%d q=[%s] a='%s' kern=%d",node,N(rv),ln,table.concat(parts," "),table.concat(asc),kern))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
