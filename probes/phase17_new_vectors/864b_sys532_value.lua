-- CRASH_CLASS: HIGH
-- PROBE 864b: syscall 532 - what does the value written to arg3 depend on?
print("=== PROBE 864b: sys532 value ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wq(a,v) local ok=pcall(function() memory.write_qword(a,v) end) return ok end
local function wd(a,v) local ok=pcall(function() memory.write_dword(a,v) end) return ok end
local function page() local a=memory.alloc(0x4000) for i=0,0x3FFF,8 do pcall(function() memory.write_qword(a+i,uint64(0)) end) end return a end
local sc=mk(532)
pcall(function() local sa=memory.alloc(0x20) for i=0,0x1F,8 do wq(sa+i,uint64(0)) end local s=mk(416) s(uint64(12),uint64(sa),uint64(0),uint64(0)) end)
local p1,p2=page(),page()
print(string.format("[0] pid=%s", tostring(mk(20)())))
local function fill(p,pat) for i=0,0x3F,4 do wd(p+i,pat) end end
local function show(p,tag) local o={} for i=0,0x3F,4 do o[#o+1]=string.format("%08X",rd(p+i) or 0) end print("   "..tag.." "..table.concat(o," ")) end
print("[A] cmd=0x18, arg2 varied, arg3=p1")
for _,v in ipairs({0,1,2,3,4,0x1000,0x12345678}) do
  fill(p1,0xAAAAAAAA)
  local ok,r=pcall(function() return sc(uint64(0x18),uint64(v),uint64(p1),uint64(0),uint64(0)) end)
  print(string.format("  a2=%08X ret=%s p1[0]=%08X p1[1]=%08X", v, ok and tostring(r) or "-", rd(p1) or 0, rd(p1+4) or 0))
end
print("[B] cmd=0x1E, arg2 varied")
for _,v in ipairs({0,1,2,3,0x1000}) do
  fill(p1,0xBBBBBBBB)
  local ok,r=pcall(function() return sc(uint64(0x1E),uint64(v),uint64(p1),uint64(0),uint64(0)) end)
  print(string.format("  a2=%08X ret=%s p1[0]=%08X p1[1]=%08X", v, ok and tostring(r) or "-", rd(p1) or 0, rd(p1+4) or 0))
end
print("[C] write size, cmd=0x18")
fill(p1,0xCCCCCCCC); sc(uint64(0x18),uint64(0),uint64(p1),uint64(0),uint64(0)); show(p1,"p1")
print("[D] other args: cmd=0x18 with arg4/arg5 = pages")
fill(p1,0xDDDDDDDD); fill(p2,0xEEEEEEEE)
local ok,r=pcall(function() return sc(uint64(0x18),uint64(0),uint64(p1),uint64(p2),uint64(p2)) end)
print(string.format("  ret=%s p1[0]=%08X p2[0]=%08X", ok and tostring(r) or "-", rd(p1) or 0, rd(p2) or 0))
print("[E] 0x18 then 0x19 then 0x1E same page")
fill(p1,0)
for _,c in ipairs({0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E}) do
  local ok,r=pcall(function() return sc(uint64(c),uint64(0),uint64(p1),uint64(0),uint64(0)) end)
  print(string.format("  cmd=%02X ret=%s p1[0]=%08X", c, ok and tostring(r) or "-", rd(p1) or 0))
end
print("[F] alive=" .. tostring(pcall(function() return mk(20)() end)))
