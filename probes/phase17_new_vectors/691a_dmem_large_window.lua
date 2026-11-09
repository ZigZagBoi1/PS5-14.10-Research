-- CRASH_CLASS: HIGH
-- PROBE 691a: the dmem0 window at offset 0 is persistent shared memory. How far
-- does a single mapping reach, and where does non-zero data live inside it?
print("=== PROBE 691a: DMEM LARGE WINDOW ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local ok,r=pcall(function() return mk(477)(U(0),U(0x100000),U(3),U(1),U(fd),U(0)) end)
local base=N(r)
print(string.format("[A] fd=%d 1MiB map ok=%s base=0x%X",fd,tostring(ok),base))
if not ok or base==0 or base>0x800000000000 then print("[A] map failed"); print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20)))) return end
local step=0x1000
for p=0,0xFF do
  local a=base+p*step
  local nz=0; local first=0
  for i=0,7 do
    local o,v=pcall(function() return memory.read_qword(a+i*8) end)
    if not o then print(string.format("  page %03X READ FAULT",p)); break end
    if N(v)~=0 then nz=nz+1; if first==0 then first=N(v) end end
  end
  if nz>0 then print(string.format("  page %03X nonzero=%d/8 first=%016X",p,nz,first)) end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
