-- CRASH_CLASS: HIGH
-- PROBE 692a: one megabyte of the persistent dmem0 window, characterised:
-- kernel-shaped values, GPU-address-shaped values, repeated fill patterns and
-- any ASCII strings. This says what the window actually is.
print("=== PROBE 692a: DMEM WINDOW RECON ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rqq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x100000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] base=0x%X",base))
if base==0 or base>0x800000000000 then print("[Z] no map") return end
local nz,kern,gpu,pages=0,0,0,0
local strs={}
local sample={}
for p=0,0xFF do
  local pnz=0
  for i=0,0x1FF do
    local v=rqq(base+p*0x1000+i*8)
    if v and v~=0 then
      nz=nz+1; pnz=pnz+1
      local hi=math.floor(v/281474976710656)
      if hi>=0xFFFF then kern=kern+1 end
      if v>=0xC0000000 and v<0xD0000000 then gpu=gpu+1; if #sample<12 then sample[#sample+1]=string.format("+%06X=%08X",p*0x1000+i*8,v) end end
    end
  end
  if pnz>0 then pages=pages+1 end
end
print(string.format("[B] nonzero qwords=%d pages=%d/256 kernel-shaped=%d gpu-shaped=%d",nz,pages,kern,gpu))
for i=1,#sample do print("  gpu "..sample[i]) end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
