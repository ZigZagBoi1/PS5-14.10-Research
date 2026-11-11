print("=== PROBE 1207a: syscall 605 five-magic service RPC, and its sibling 606 ===")
local function tn(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(a) a=tn(a) local hi=math.floor(a/4294967296) local lo=a-hi*4294967296
    return uint64(string.format("0x%08X%08X",hi,lo)) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local Z=uint64(0)
local M={0x780263ff,0x78026400,0x78028a00,0x78028300,0x19810000,0x3cc80700,
         0x00000000,0xFFFFFFFF,0x780263fe,0x78026401,0x7802c500,0x78020200,0x78020300,0x7802a500,0x7802b200}
print("-- 605(magic) --")
for i=1,#M do
  local m=M[i]
  local o=pcall(function() return mk(605)(U(m),Z,Z,Z,Z,Z) end)
  print(string.format("605 magic=0x%08X pcall=%s err=%s",m,tostring(o),ES()))
end
print("-- 606(arg1) --")
for i=1,#M do
  local m=M[i]
  local o=pcall(function() return mk(606)(Z,U(m),Z,Z,Z,Z) end)
  print(string.format("606 arg1=0x%08X pcall=%s err=%s",m,tostring(o),ES()))
end
print("-- 605 magic in arg1 instead --")
for i=1,5 do
  local m=M[i]
  local o=pcall(function() return mk(605)(Z,U(m),Z,Z,Z,Z) end)
  print(string.format("605 arg1=0x%08X pcall=%s err=%s",m,tostring(o),ES()))
end
print("=== DONE")
