-- CRASH_CLASS: MODERATE
-- PROBE 679a: ops 13..27 with a one-millisecond timespec in the last pointer
-- argument, so any wait-shaped op returns instead of wedging the loader.
print("=== PROBE 679a: UMTX OPS 13..27 (TIMED) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local sc=mk(454)
local W=memory.alloc(0x100)
local TS=memory.alloc(16)
for op=13,27 do
  for i=0,0xFC,4 do wd(N(W)+i,0) end
  wd(N(TS),0); wd(N(TS)+4,0); wd(N(TS)+8,1000000); wd(N(TS)+12,0)
  local r=N(select(2,pcall(function() return sc(U(N(W)),U(op),U(0xDEADBEEF),U(0),U(N(TS)),U(0)) end)))
  print(string.format("[%02d] rv=%s w0=%08X w8=%08X tick=%d",op,tostring(r),N(memory.read_dword(N(W))),N(memory.read_dword(N(W)+8)),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
