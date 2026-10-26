-- CRASH_CLASS: HIGH
-- PROBE 685a: does a CHANGED value survive in the dmem0 aperture? A RAM page
-- returns what was written; a register block either ignores it, masks it or
-- takes it. Test on zero-filled slots only, and restore each one afterwards.
print("=== PROBE 685a: DMEM CHANGE PERSISTENCE ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x2000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] fd=%d base=0x%X",fd,base))
if base==0 or base>0x800000000000 then print("[A] map failed") return end
local zeros={}
for i=0,0x3FF do
  local o,v=pcall(function() return memory.read_qword(base+i*8) end)
  if o and N(v)==0 then zeros[#zeros+1]=i end
  if #zeros>=6 then break end
end
print(string.format("[B] zero slots found=%d",#zeros))
local pat=uint64("0x0000000000ABCDEF")
for n=1,#zeros do
  local i=zeros[n]
  local a=base+i*8
  local o=pcall(function() memory.write_qword(a,pat) end)
  local o2,back=pcall(function() return memory.read_qword(a) end)
  local kept = o2 and N(back)==0xABCDEF
  print(string.format("  +%04X write=%s back=%s kept=%s",i*8,tostring(o),tostring(back),tostring(kept)))
  pcall(function() memory.write_qword(a,uint64(0)) end)
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
