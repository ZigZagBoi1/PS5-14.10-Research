-- CRASH_CLASS: MODERATE
-- PROBE 1031a: alternative argument shapes for 589 dynlib_dlopen / 594 load_prx
print("=== PROBE 1031a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local function wq(addr,val) pcall(function() memory.write_qword(addr,val) end) end
local function wrstr(addr,s) for i=1,#s do pcall(function() memory.write_byte(addr+i-1,s:byte(i)) end) end pcall(function() memory.write_byte(addr+#s,0) end) end
local sc592=make_syscall(592)
local list=memory.alloc(0x200); local cap=memory.alloc(8); local cnt=memory.alloc(8)
wd(cap,0x200); wd(cnt,0)
local ok,v=pcall(function() return sc592(A(list),A(cap),A(cnt)) end)
print("[A] 592 rv="..tostring(ok and to_num(v) or "FI").." count="..rd(cnt))
local n=rd(cnt)
local handles={}
for i=0,math.min(n,40)-1 do handles[i+1]=rd(list+i*4) end
print(string.format("[A] h0=%d h1=%d h2=%d", handles[1] or -1, handles[2] or -1, handles[3] or -1))
local sc589=make_syscall(589)
local sc595=make_syscall(595)
local sc594=make_syscall(594)
local ho=memory.alloc(0x20)
-- shape 1: string name, 2 args
local names={"libSceSystemService.sprx","libSceNet.sprx","libkernel.sprx","libSceLibcInternal.sprx"}
for i=1,#names do
  local ok2,v2=pcall(function() return sc589(names[i],A(ho)) end)
  print(string.format("[S%d] 589(str2) %s rv=%s h=%X", i, names[i], tostring(ok2 and to_num(v2) or "FI"), rd(ho)))
end
-- shape 2: string name, 3 args flags
for i=1,#names do
  local ok2,v2=pcall(function() return sc589(names[i],uint64(0),A(ho)) end)
  print(string.format("[T%d] 589(str3) %s rv=%s h=%X", i, names[i], tostring(ok2 and to_num(v2) or "FI"), rd(ho)))
end
-- shape 3: load_prx with string
for i=1,#names do
  local ok2,v2=pcall(function() return sc594(names[i],uint64(0),A(ho)) end)
  print(string.format("[U%d] 594(str) %s rv=%s h=%X", i, names[i], tostring(ok2 and to_num(v2) or "FI"), rd(ho)))
end
-- unload a listed handle
for i=1,3 do
  if handles[i] then
    local ok3,v3=pcall(function() return sc595(A(handles[i])) end)
    print(string.format("[V%d] 595 handle=%X rv=%s", i, handles[i], tostring(ok3 and to_num(v3) or "FI")))
  end
end
local ok4,v4=pcall(function() return sc592(A(list),A(cap),A(cnt)) end)
print("[Z] 592b rv="..tostring(ok4 and to_num(v4) or "FI").." count="..rd(cnt).." alive")
