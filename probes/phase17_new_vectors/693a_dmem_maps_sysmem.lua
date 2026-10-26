-- CRASH_CLASS: HIGH
-- PROBE 693a: is the dmem0 window backed by system RAM? Write a unique canary
-- into a fresh heap buffer, then search the whole 1 MiB window for it.
print("=== PROBE 693a: DOES DMEM MAP SYSTEM RAM? ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rqq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local buf=memory.alloc(0x4000)
local can=0x00C0FFEE12345678
for i=0,0xFFF do pcall(function() memory.write_qword(N(buf)+i*8, uint64("0x00C0FFEE12345678")) end) end
print(string.format("[A] canary page=0x%X",N(buf)))
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x100000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[B] base=0x%X",base))
if base==0 or base>0x800000000000 then print("[Z] no map") return end
local hits=0
for p=0,0xFF do
  for i=0,0x1FF do
    local v=rqq(base+p*0x1000+i*8)
    if v==can then hits=hits+1; if hits<=4 then print(string.format("  HIT +%06X",p*0x1000+i*8)) end end
  end
end
print(string.format("[C] canary hits in window = %d",hits))
print(string.format("[D] the window's own page0 [0]=%016X",rqq(base) or 0))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
