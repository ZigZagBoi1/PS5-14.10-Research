-- CRASH_CLASS: MODERATE
-- PROBE 1032a: does 594 load_prx admit modules that are not already in the list?
print("=== PROBE 1032a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local sc592=make_syscall(592); local sc594=make_syscall(594)
local list=memory.alloc(0x400); local cap=memory.alloc(8); local cnt=memory.alloc(8)
local function count()
  wd(cap,0x400); wd(cnt,0)
  local ok,v=pcall(function() return sc592(A(list),A(cap),A(cnt)) end)
  return rd(cnt), (ok and to_num(v) or -999)
end
local n0=count(); print("[A] count0="..n0)
local ho=memory.alloc(0x20)
local names={
 "libSceAudioOut.sprx","libScePad.sprx","libSceUserService.sprx","libSceCommonDialog.sprx",
 "libSceSaveData.sprx","libSceSysUtil.sprx","libSceNetCtl.sprx","libSceHttp.sprx",
 "libSceVideoRecording.sprx","libSceCamera.sprx","libSceMouse.sprx","libSceKeyboard.sprx",
}
for i=1,#names do
  wd(ho,0)
  local ok,v=pcall(function() return sc594(names[i],uint64(0),A(ho)) end)
  local c=count()
  print(string.format("[P%d] %-32s rv=%s h=%X count=%d", i, names[i], tostring(ok and to_num(v) or "FI"), rd(ho), c))
end
local c2=count(); print("[Z] count_final="..c2.." alive")
