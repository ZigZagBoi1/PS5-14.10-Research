-- CRASH_CLASS: HIGH
-- PROBE 864a: syscall 532 command/argument matrix
-- 13.60 body 0xaf0040 (narg 5): uap[0]=cmd (r14d), uap[8]=eax, uap[0x10],
-- uap[0x18], uap[0x20]; cmd 0x20/0x2f and args ecx<7 are rejected early.
print("=== PROBE 864a: sys532 matrix ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wq(a,v) local ok=pcall(function() memory.write_qword(a,v) end) return ok end
local function hi(v) if type(v)=="table" and v.h then return to_num(v.h) end return 0 end
local function u64(h,l) return uint64(string.format("0x%X%08X", h, l)) end
local function page() local a=memory.alloc(0x4000) for i=0,0x3FFF,8 do pcall(function() memory.write_qword(a+i,uint64(0)) end) end return a end
local sc = mk(532)
-- shield: SIGSYS ignored so an absent handler is not fatal
pcall(function() local sa=memory.alloc(0x20) for i=0,0x1F,8 do wq(sa+i,uint64(0)) end local s=mk(416) s(uint64(12),uint64(sa),uint64(0),uint64(0)) end)
print(string.format("[0] pid=%s", tostring(mk(20)())))
local p1, p2 = page(), page()
local CMDS = {0,1,2,3,4,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x21,0x22,0x2C,0x2D,0x36,0x42,0x46,0x100,0x801,0x818}
print("[A] cmd sweep, all other args zero")
for _,c in ipairs(CMDS) do
  local ok, r = pcall(function() return sc(uint64(c), uint64(0), uint64(0), uint64(0), uint64(0)) end)
  print(string.format("  cmd=%04X ok=%s ret=%s", c, tostring(ok), ok and tostring(r) or "-"))
end
print("[B] accepted cmds with page pointers")
for _,c in ipairs(CMDS) do
  local ok, r = pcall(function() return sc(uint64(c), uint64(0), uint64(p1), uint64(p2), uint64(0)) end)
  local d1, d2 = rd(p1+0), rd(p2+0)
  print(string.format("  cmd=%04X ret=%s p1=%s p2=%s", c, ok and tostring(r) or "-", tostring(d1), tostring(d2)))
end
print("[C] alive=" .. tostring(pcall(function() return mk(20)() end)))
