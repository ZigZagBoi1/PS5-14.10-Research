-- CRASH_CLASS: LOW
-- PROBE 690a: did the canary written by 689a at dmem0+0x800 survive into this
-- process? Shared device memory keeps it; per-process memory does not.
print("=== PROBE 690a: DMEM PERSISTENCE ACROSS PROCESSES ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x2000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] fd=%d base=0x%X",fd,base))
if base>0 and base<0x800000000000 then
  local o,v=pcall(function() return memory.read_qword(base+0x800) end)
  print(string.format("[B] +800 = %016X",o and N(v) or 0))
  print(string.format("[C] +000 = %016X",N(select(2,pcall(function() return memory.read_qword(base) end)))))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
