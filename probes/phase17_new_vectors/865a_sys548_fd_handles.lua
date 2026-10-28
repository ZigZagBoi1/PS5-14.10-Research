-- CRASH_CLASS: MODERATE
-- PROBE 865a: syscall 548 op 0 with small handles (fd-shaped) never tried before
-- 13.60 op0 requires [entry+0] < 0x4000, [entry+8] 0x4000-aligned and >= 0x4000,
-- then calls 0x3c33e0(handle, [proc+8]).
print("=== PROBE 865a: sys548 small handles ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function wq(a,v) local ok=pcall(function() memory.write_qword(a,v) end) return ok end
local function wd(a,v) local ok=pcall(function() memory.write_dword(a,v) end) return ok end
print(string.format("[0] pid=%s", tostring(mk(20)())))
local e=memory.alloc(0x100)
local sc=mk(548)
local function call548(h,len,prot,extra)
  wq(e,uint64(h)); wq(e+8,uint64(len)); wq(e+0x10,uint64(prot)); wq(e+0x18,uint64(extra))
  local ok,r=pcall(function() return sc(uint64(0),uint64(0),uint64(e),uint64(1),uint64(0)) end)
  return ok, r
end
for _,h in ipairs({0,1,2,3,16,17,0x3FFF}) do
  local ok,r=call548(h,0x4000,3,0)
  print(string.format("  h=%04X len=4000 prot=3 ret=%s", h, ok and tostring(r) or "-"))
end
for _,len in ipairs({0x8000,0x1000,0x3fff}) do
  local ok,r=call548(2,len,3,0)
  print(string.format("  h=0002 len=%X ret=%s", len, ok and tostring(r) or "-"))
end
print("[C] alive=" .. tostring(pcall(function() return mk(20)() end)))
