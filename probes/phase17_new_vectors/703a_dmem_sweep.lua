-- CRASH_CLASS: MODERATE
-- PROBE 703a: /dev/dmem0 mapped at 16 MB granularity across 4 GB, counting
-- non-zero qwords in the first 64 KB of each window. The offset is a byte
-- offset into one linear device-memory window, so this maps out where it is
-- actually backed.
print("=== PROBE 703a: DMEM OFFSET SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function c6(n,a,b,c,d,e,f)
  local o,r=pcall(function() return mk(n)(U(a or 0),U(b or 0),U(c or 0),U(d or 0),U(e or 0),U(f or 0)) end)
  if o then return N(r) end return -999
end
local path="/dev/dmem0"
local pb=memory.alloc(#path+2)
for i=1,#path do pcall(function() memory.write_byte(N(pb)+i-1,string.byte(path,i)) end) end
local fd=c6(5,N(pb),2,0)
print(string.format("[A] open %s fd=%d",path,fd))
if fd<0 then print("[Z] no fd") return end
local found=0
for step=0,255 do
  local off=step*0x1000000
  local p=c6(477,0,0x400000,3,1,fd,off)
  if p~=nil and p>0 and p<0x800000000000 then
    local nz=0
    for i=0,0x10000-8,8 do
      local o,v=pcall(function() return memory.read_qword(p+i) end)
      if o and N(v)~=0 then nz=nz+1 end
    end
    if nz>0 then
      found=found+1
      local q1=0
      pcall(function() q1=N(memory.read_qword(p)) end)
      print(string.format("[B] off=0x%X nz=%d q0=%016X",off,nz,q1))
    end
    pcall(function() c6(73,p,0x400000) end)
  end
end
print(string.format("[C] non-empty windows=%d",found))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
