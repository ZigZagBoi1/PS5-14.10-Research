-- CRASH_CLASS: MODERATE
-- PROBE 495a: is `memory` available inside the helper's thread state?
-- A shared flag would let the two callers meet inside the delete window instead
-- of racing by luck. The runner copies its own globals into _G, so test the one
-- primitive the barrier needs before building it.
print("=== PROBE 495a: memory inside the thread ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
end
local flag = memory.alloc(0x100)
pcall(function() memory.write_dword(flag, 0) end)
local body = string.format(
  "local ok = pcall(function() memory.write_dword(%d, 0xBEEF0001) end)\n" ..
  "local ok2 = pcall(function() memory.write_dword(%d, ok and 1 or 2) end)\n",
  addrnum(flag), addrnum(flag) + 4)
local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
print("helper ok=" .. tostring(ok) .. " thr=" .. type(thr))
if ok and type(thr) == "table" then
  local spins = 0
  while to_num(memory.read_dword(flag)) ~= 0xBEEF0001 and spins < 4000000 do spins = spins + 1 end
  print(string.format("flag=%#x mem_ok=%d spins=%d", to_num(memory.read_dword(flag)),
        to_num(memory.read_dword(flag + 4)), spins))
  pcall(function() return thr:join() end)
end
print("=== PROBE 495a COMPLETE ===")
