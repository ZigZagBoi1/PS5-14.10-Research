-- CRASH_CLASS: LOW
-- PROBE 663a: what makes a mutex a PI mutex? 655a proved the word is the owner
-- tid. Try the documented flag bits in the initial word with TRYLOCK only, so
-- nothing can block.
print("=== PROBE 663a: UMTX PI FLAG BITS (TRYLOCK ONLY) ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function op(o,a,a2) return N(select(2,pcall(function() return mk(454)(U(a),U(o),U(a2 or 0),U(0),U(0),U(0)) end))) end
local TB=memory.alloc(8); wd(N(TB),0)
pcall(function() mk(432)(U(N(TB)),U(0),U(0),U(0),U(0),U(0)) end)
print(string.format("[A] my tid=%X",rd(N(TB)) or 0))
local M=memory.alloc(8)
for _,v in ipairs({0,0x40000000,0x20000000,0x80000000,0x10000000}) do
  wd(N(M),v)
  local r1=op(5,N(M))
  local m1=rd(N(M)) or 0
  local r2=op(4,N(M))
  local m2=rd(N(M)) or 0
  local r3=op(6,N(M))
  local m3=rd(N(M)) or 0
  print(string.format("[B] start=%08X lock rv=%s M=%08X trylock rv=%s M=%08X unlock rv=%s M=%08X",v,tostring(r1),m1,tostring(r2),m2,tostring(r3),m3))
end
-- a fresh word, trylock only
wd(N(M),0)
print(string.format("[C] trylock on 0: rv=%s M=%X",tostring(op(4,N(M))),rd(N(M)) or 0))
print(string.format("[D] unlock: rv=%s M=%X",tostring(op(6,N(M))),rd(N(M)) or 0))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
