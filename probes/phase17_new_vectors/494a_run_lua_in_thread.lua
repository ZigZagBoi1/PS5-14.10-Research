-- CRASH_CLASS: HIGH
-- PROBE 494a: the loader's own Lua-in-a-new-thread helper
-- thread.lua defines run_lua_code_in_new_thread(lua_code, opt) after the
-- thread class. thread:new(sc, ...) + run(true) died on the first spawn, but the
-- dedicated helper exists to run a whole Lua body in the new thread (it builds
-- the state and the chain itself), which is the supported way to get a second
-- concurrent caller for 662. First dump its source, then try one trivial body.
print("=== PROBE 494a: run_lua_code_in_new_thread ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local src
local ok, f = pcall(io.open, "/savedata0/thread.lua", "r")
if ok and f then src = f:read("*a"); f:close() end
if src then
  local n = 0
  for line in src:gmatch("[^\n]*\n?") do
    if #line > 0 then
      n = n + 1
      if n >= 121 and n <= 279 then print(string.format("%3d| %s", n, (line:gsub("\n$", "")))) end
    end
  end
else
  print("thread.lua unreadable")
end
print("--- typeof run_lua_code_in_new_thread = " .. type(run_lua_code_in_new_thread))
local flag = memory.alloc(0x100)
pcall(function() memory.write_dword(flag, 0) end)
if type(run_lua_code_in_new_thread) == "function" then
  local code = string.format("memory.write_dword(%d, 0xC0FFEE01)", flag)
  print("--- calling helper with a 4-byte write")
  local ok2, err = pcall(run_lua_code_in_new_thread, code, { async = true })
  print("--- helper ok=" .. tostring(ok2) .. " err=" .. tostring(err))
  local spins = 0
  while to_num(memory.read_dword(flag)) ~= 0xC0FFEE01 and spins < 3000000 do spins = spins + 1 end
  print(string.format("--- flag=%#x spins=%d", to_num(memory.read_dword(flag)), spins))
end
print("=== PROBE 494a COMPLETE ===")
