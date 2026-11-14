-- CRASH_CLASS: MODERATE
-- PROBE 1030a: can 589 dynlib_dlopen add a module (and so move the 659 count)?
print("=== PROBE 1030a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wq(addr,val) pcall(function() memory.write_qword(addr,val) end) end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local function wrstr(addr,s) for i=1,#s do pcall(function() memory.write_byte(addr+i-1,s:byte(i)) end) end pcall(function() memory.write_byte(addr+#s,0) end) end
local shield=make_syscall(416)
local sa=memory.alloc(0x40)
for i=0,7 do wq(sa+i*8,0) end
wd(sa,1)
print("[S] shield="..tostring(shield(A(sa),0,A(0)):tonumber()))
local sc592=make_syscall(592)
local list=memory.alloc(0x200)
print("[L] list before="..tostring(rd(list)<0))
print("[L] rv5592="..tostring(to_num(select(2,pcall(function() return sc592(A(list),A(0x200),A(0)) end)))))
for i=0,7 do print(string.format("[L] q%d=%X", i, rd(list+i*8))) end
local sc589=make_syscall(589)
local pb=memory.alloc(0x100)
local ho=memory.alloc(0x20)
local paths={
 "/system/common/lib/libSceSystemService.sprx",
 "libSceSystemService.sprx",
 "/system/common/lib/libSceHttp2.sprx",
 "/system/common/lib/libkernel.sprx",
 "/system/common/lib/libSceLibcInternal.sprx",
}
for i=1,#paths do
  wrstr(pb,paths[i]); wd(ho,0)
  local ok,v=pcall(function() return sc589(A(pb),A(0),A(ho)) end)
  print(string.format("[D%d] %s rv=%s handle=%X", i, paths[i], tostring(ok and to_num(v) or "FI"), rd(ho)))
end
print("[L] after:")
local ok2,v2=pcall(function() return sc592(A(list),A(0x200),A(0)) end)
print("[L] rv5592b="..tostring(to_num(v2)))
for i=0,7 do print(string.format("[L] q%d=%X", i, rd(list+i*8))) end
print("[Z] alive")
