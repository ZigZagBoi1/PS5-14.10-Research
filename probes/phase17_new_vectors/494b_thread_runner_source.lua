-- CRASH_CLASS: MODERATE
-- PROBE 494b: read the runner the thread helper loads, then use the helper
-- 494a showed run_lua_code_in_new_thread builds a fresh Lua state, pushes a
-- serialised data blob into _data_from_loader, loads lua_runner (a string whose
-- LUA_PATH is substituted) and starts thread:new(eboot_addrofs.lua_pcall, L, ...).
-- What that runner exposes as globals decides whether a second thread can call
-- 662 at all, so read it before trying.
print("=== PROBE 494b: thread runner source ===")
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
      if n >= 119 and n <= 232 then
        local clean = line:gsub("\n$", "")
        print(n .. "| " .. clean)
      end
    end
  end
  print("total lines=" .. n)
else
  print("thread.lua unreadable")
end
print("=== PROBE 494b COMPLETE ===")
