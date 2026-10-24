-- CRASH_CLASS: MODERATE
-- PROBE 490b: does the loader's thread table run a Lua function on a new thread?
-- 490a listed: thread.init / new / run / join / initialized / thr_handle_addr.
-- If run() executes a Lua closure in a second OS thread, the aio race needs no
-- ROP and no gadget hunting: two Lua threads can call 662 at the same time.
print("=== PROBE 490b: loader Lua threads ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
print("initialized = " .. tostring(thread.initialized))
if thread.init then
  local ok, rv = pcall(thread.init)
  print("init -> ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
end
print("initialized after init = " .. tostring(thread.initialized))
local flag = memory.alloc(0x100)
pcall(function() memory.write_dword(flag, 0) end)
local body = function(a)
  pcall(function() memory.write_dword(flag, 0x1234) end)
  pcall(function() memory.write_dword(flag + 4, a or 0) end)
  return 7
end
local ok, t = pcall(thread.new, body)
print("new -> ok=" .. tostring(ok) .. " t=" .. type(t) .. " " .. tostring(t))
if ok and type(t) == "table" then
  local ok2, rv2 = pcall(function() return t:run(0x55) end)
  print("run -> ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))
  local waited = 0
  while to_num(memory.read_dword(flag)) ~= 0x1234 and waited < 300000 do waited = waited + 1 end
  print(string.format("marker=%#x arg=%#x spins=%d", to_num(memory.read_dword(flag)),
        to_num(memory.read_dword(flag + 4)), waited))
  local ok3, rv3 = pcall(function() return t:join() end)
  print("join -> ok=" .. tostring(ok3) .. " rv=" .. tostring(rv3))
  print("after join marker=" .. string.format("%#x", to_num(memory.read_dword(flag))))
end
print("=== PROBE 490b COMPLETE ===")
