-- CRASH_CLASS: LOW
-- PROBE 677a: map the whole _umtx_op table. The dispatcher rejects op > 0x1b,
-- so 0..27 all exist. Calling each with a NULL address cannot block (EFAULT
-- first), which makes this a safe existence/shape table.
print("=== PROBE 677a: UMTX OP TABLE (NULL ADDRESS) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local sc=mk(454)
local W=memory.alloc(0x40)
for i=0,0x3C,4 do pcall(function() memory.write_dword(N(W)+i,0) end) end
for op=0,27 do
  local r=N(select(2,pcall(function() return sc(U(0),U(op),U(0),U(0),U(0),U(0)) end)))
  local r2=N(select(2,pcall(function() return sc(U(N(W)),U(op),U(0),U(0),U(0),U(0)) end)))
  print(string.format("[%02d] null=%s mapped=%s word=%08X",op,tostring(r),tostring(r2),N(memory.read_dword and memory.read_dword(N(W)) or 0)))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
