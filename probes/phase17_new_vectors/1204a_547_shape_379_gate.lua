print("=== PROBE 1204a: 547 QUERY_MEMORY_PROTECTION SHAPE, 379 GATE ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function U(a) a=tn(a) local hi=math.floor(a/4294967296) local lo=a-hi*4294967296
    return uint64(string.format("0x%08X%08X",hi,lo)) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local function q(addr) local lo=tn(memory.read_dword(addr)) local hi=tn(memory.read_dword(addr+4))
    return string.format("%08X%08X",hi,lo) end
local Z=uint64(0)
local pg=tn(memory.alloc(0x1000))
local out=tn(memory.alloc(0x100))
print(string.format("page=0x%08X out=0x%08X",pg,out))
local va=pg-(pg%0x4000)
for i=0,0x17 do memory.write_byte(out+i,0xA5) end
print(string.format("-- 547(va=0x%08X,out) --",va))
local ok=pcall(function() return mk(547)(U(va),U(out),Z,Z,Z,Z) end)
print(string.format("547 pcall=%s err=%s",tostring(ok),ES()))
for i=0,0x17,8 do print(string.format("  out+%02X = %s",i,q(out+i))) end
for i=0,0x17 do memory.write_byte(out+i,0xA5) end
print(string.format("-- 547(va=0x%08X unaligned,out) --",pg+0x123))
ok=pcall(function() return mk(547)(U(pg+0x123),U(out),Z,Z,Z,Z) end)
print(string.format("547b pcall=%s err=%s",tostring(ok),ES()))
for i=0,0x17,8 do print(string.format("  out+%02X = %s",i,q(out+i))) end
print("-- 379 id sweep prot=3 on own page --")
for id=0,15 do
  local o2=pcall(function() return mk(379)(U(va),U(0x1000),U(id),U(3),Z,Z) end)
  print(string.format("379 id=%2d pcall=%s err=%s",id,tostring(o2),ES()))
end
print("=== DONE")
