-- CRASH_CLASS: HIGH
-- PROBE 494c: run a minimal body through run_lua_code_in_new_thread
-- 494b: the helper builds a fresh state, copies the loader's tables into _G,
-- re-resolves every syscall with fcall(fn_addr, syscall_no), repoints print to
-- client_fd and runs _lua_code with loadstring + pcall. A body that only prints
-- proves the second thread starts and can reach the socket before anything
-- calls 662 on it.
print("=== PROBE 494c: second-thread body ===")
io.stdout:setvbuf("no")
print("type(helper) = " .. type(run_lua_code_in_new_thread))
local ok, thr = pcall(run_lua_code_in_new_thread, 'print("THREAD-OK")',
  { async = true, client_fd = nil })
print("call ok=" .. tostring(ok) .. " thr=" .. type(thr))
if ok and type(thr) == "table" then
  local jok, jerr = pcall(function() return thr:join() end)
  print("join ok=" .. tostring(jok) .. " err=" .. tostring(jerr))
end
print("=== PROBE 494c COMPLETE ===")
