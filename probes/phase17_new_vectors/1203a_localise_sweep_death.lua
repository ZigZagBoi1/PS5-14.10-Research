print("=== PROBE 1203a: LOCALISE THE SWEEP DEATH ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local Z=uint64(0)
local buf=tn(memory.alloc(0x200))
print(string.format("buf=0x%08X",buf))
for n=17,30 do
  print(string.format("try %d",n))
  local ok=pcall(function() return mk(n)(U(9999),U(0x5413),U(buf),Z,Z,Z) end)
  local es=ES()
  local oks="FALSE"
  if ok then oks="TRUE" end
  print(string.format("ok  %d pcall=%s err=%s",n,oks,es))
end
print("=== DONE")
