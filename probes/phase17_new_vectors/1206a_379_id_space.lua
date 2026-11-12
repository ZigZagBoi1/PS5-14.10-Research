print("=== PROBE 1206a: 379 id space beyond 10, and does 547 see a prot change ===")
local function tn(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(a) a=tn(a) local hi=math.floor(a/4294967296) local lo=a-hi*4294967296
    return uint64(string.format("0x%08X%08X",hi,lo)) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local function q(addr) local lo=tn(memory.read_dword(addr)) local hi=tn(memory.read_dword(addr+4))
    return string.format("%08X%08X",hi,lo) end
local Z=uint64(0)
local out=tn(memory.alloc(0x100))
local pg=tn(memory.alloc(0x2000))
local va=pg-(pg%0x4000)
local function vma(tag)
  for j=0,0x17 do memory.write_byte(out+j,0xA5) end
  local o=pcall(function() return mk(547)(U(va),U(out),Z,Z,Z,Z) end)
  print(string.format("  547[%s] pcall=%s start=%s end=%s fl=%s",tag,tostring(o),q(out),q(out+8),q(out+16)))
end
print(string.format("va=0x%08X",va))
vma("before")
print("-- A: 379 id sweep 0x00-0xFF, prot=3 --")
local last=nil
for id=0,0xFF do
  local o=pcall(function() return mk(379)(U(va),U(0x1000),U(id),U(3),Z,Z) end)
  local e=ES()
  if e~=last then print(string.format("379 id=0x%02X pcall=%s err=%s",id,tostring(o),e)) last=e end
end
print("-- B: 379 id=10 prot=3 after --")
vma("after379")
print("-- C: id 0x100-0x104 prot=3 --")
for id=0x100,0x104 do
  local o=pcall(function() return mk(379)(U(va),U(0x1000),U(id),U(3),Z,Z) end)
  print(string.format("379 id=0x%03X pcall=%s err=%s",id,tostring(o),ES()))
end
print("=== DONE")
