-- CRASH_CLASS: MODERATE
-- PROBE 1034a: 629 physhm_open with arg1==1 (the branch that skips path copyin and both authority tests)
print("=== PROBE 1034a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local sc629=make_syscall(629)
local buf=memory.alloc(0x100)
for i=0,0x40 do wd(buf+i*4,0x41414141) end
local shapes={
 {1,0x1000,0,0},
 {1,0x1000,3,3},
 {1,0x1000,0x1000,3},
 {1,0x100000,0,0},
 {1,0x1000,0,0,0,0},
 {1},
 {1,0,0,0},
 {1,0x1000,1,1},
}
for i,s in ipairs(shapes) do
  local ok,v=pcall(function() return sc629(A(s[1]),A(s[2] or 0),A(s[3] or 0),A(s[4] or 0),A(s[5] or 0),A(s[6] or 0)) end)
  print(string.format("[P%d] (%d,0x%X,0x%X,0x%X) rv=%s b0=%X", i, s[1], s[2] or 0, s[3] or 0, s[4] or 0, tostring(ok and to_num(v) or "FI"), rd(buf)))
end
-- path shapes on the non-1 branch for reference
local pb=memory.alloc(0x100)
local function wrstr(addr,str) for k=1,#str do pcall(function() memory.write_byte(addr+k-1,str:byte(k)) end) end pcall(function() memory.write_byte(addr+#str,0) end) end
wrstr(pb,"/dev/physhm")
for i=0,2 do
  local ok,v=pcall(function() return sc629(A(pb),A(0x1000),A(i),A(3),A(0),A(0)) end)
  print(string.format("[Q%d] path flags=%d rv=%s", i, i, tostring(ok and to_num(v) or "FI")))
end
print("[Z] alive")
