-- CRASH_CLASS: HIGH
-- PROBE 1041a: does the loader's own `run_lua_code_in_new_thread` work on 14.10?
-- thread.lua carries it but warns it "has a chance to crash the game process because of
-- unfixed race condition in native primitives".  If it does work it gives concurrent Lua,
-- which is the one thing every aio race probe so far lacked: thr_create children can only
-- run straight-line native chains, so every attempt cost a spawn and the loop counts
-- stayed at 30-40.  This probe only asks whether the thread starts, prints, and runs
-- alongside the caller; it makes no kernel calls from the child.
print("=== PROBE 1041a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

print("[A] run_lua_code_in_new_thread = "..tostring(type(run_lua_code_in_new_thread)))
if type(run_lua_code_in_new_thread) ~= "function" then print("[Z] not exposed"); return end

local flag=memory.alloc(0x40)
local fa=tonumber(tostring(flag):match("0x(%x+)"),16)
for o=0,0x38,8 do pcall(function() memory.write_qword(uint64(fa+o),uint64(0)) end) end
print(string.format("[B] shared page = %X", fa))

local src = string.format([[
local fa = %d
local function wd(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd4(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
print("CHILD-ALIVE")
wd4(fa+8, 1)
local n = 0
for i=1,200000 do n = n + 1 end
wd4(fa+20, 2)
wd(fa+16, n)
wd4(fa+12, 1)
print("CHILD-DONE n="..tostring(n))
]], fa)

local ok, err = pcall(function()
  local t = run_lua_code_in_new_thread(src, { async = true })
  return t
end)
print("[C] spawn ok="..tostring(ok).." err="..tostring(err))
local function rdq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end); if o then return to_num(v) end return -1 end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end); if o then return to_num(v) end return -1 end

local spins = 0
for i=1,20 do
  for j=1,200000 do spins = spins + 1 end
  local alive, done, cnt = rdd(fa+8), rdd(fa+12), rdq(fa+16)
  print(string.format("[D] i=%d parent_spins=%d child_alive=%d child_done=%d child_n=%d", i, spins, alive, done, cnt))
  if done == 1 then break end
end
print("[Z] end")
