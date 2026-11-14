print("=== PROBE 1205a: 379 id=10 prot sweep, out-of-range va, 547 bound ===")
local function tn(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(a) a=tn(a) local hi=math.floor(a/4294967296) local lo=a-hi*4294967296
    return uint64(string.format("0x%08X%08X",hi,lo)) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local function q(addr) local lo=tn(memory.read_dword(addr)) local hi=tn(memory.read_dword(addr+4))
    return string.format("%08X%08X",hi,lo) end
local Z=uint64(0)
local pg=tn(memory.alloc(0x2000))
local va=pg-(pg%0x4000)
print(string.format("page va=0x%08X",va))
print("-- A: 379 id=10, own page, prot sweep --")
local prots={0,1,2,3,4,5,6,7,8,0x10,0x40,0x80,0x100,0x400,0x800,0x1000,0x8000,0x10000}
for i=1,#prots do
  local p=prots[i]
  local o=pcall(function() return mk(379)(U(va),U(0x1000),U(10),U(p),Z,Z) end)
  print(string.format("379 prot=0x%05X pcall=%s err=%s",p,tostring(o),ES()))
end
print("-- B: 547 out-of-range vas --")
local out=tn(memory.alloc(0x100))
local vas={0x7ffffffff000, 0xffffffff8a9c0000, 0xffffffffff600000, va+0x40000000}
for i=1,#vas do
  for j=0,0x17 do memory.write_byte(out+j,0xA5) end
  local o=pcall(function() return mk(547)(U(vas[i]),U(out),Z,Z,Z,Z) end)
  print(string.format("547 va=0x%016X pcall=%s err=%s out=%s %s %s",vas[i],tostring(o),ES(),q(out),q(out+8),q(out+16)))
end
print("-- C: 379 id=10, out-of-range va, prot=3 --")
for i=1,#vas do
  local o=pcall(function() return mk(379)(U(vas[i]),U(0x1000),U(10),U(3),Z,Z) end)
  print(string.format("379 va=0x%016X pcall=%s err=%s",vas[i],tostring(o),ES()))
end
print("=== DONE")
