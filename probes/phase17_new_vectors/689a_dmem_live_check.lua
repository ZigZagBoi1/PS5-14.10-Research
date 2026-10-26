-- CRASH_CLASS: LOW
-- PROBE 689a: is the dmem0 block live hardware or plain memory? Read it twice
-- 250 ms apart. A counter/timestamp that moves proves MMIO. Also leave a
-- canary at +0x800 so a later connection can test persistence.
print("=== PROBE 689a: DMEM LIVE vs STATIC ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return -1 end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x2000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] fd=%d base=0x%X",fd,base))
if base==0 or base>0x800000000000 then print("[A] map failed") return end
local a1={}
for i=0,0x3F do a1[i]=rq(base+i*8) end
local ts=memory.alloc(16)
pcall(function() mk(240)(U(N(ts)),U(0)) end)  -- nanosleep? harmless if absent
for k=1,2000000 do local x=k end
local a2={}
for i=0,0x3F do a2[i]=rq(base+i*8) end
local moved=0
for i=0,0x3F do
  if a1[i]~=a2[i] then moved=moved+1; print(string.format("  +%03X %016X -> %016X",i*8,a1[i],a2[i])) end
end
print(string.format("[B] changed qwords between reads = %d",moved))
pcall(function() memory.write_qword(base+0x800,uint64("0x00000000C0DEC0DE")) end)
print(string.format("[C] canary +800 = %016X",rq(base+0x800)))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
