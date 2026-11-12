-- CRASH_CLASS: MODERATE  (Thrd_create through the loader's own API; the module warns of a race)
-- PROBE 1175a: is run_lua_code_in_new_thread usable as a throwaway thread?
-- Why it matters: 601 commands 0x08 and 0x0C park forever inside the kernel and cost a relaunch every
-- time. If a *second* thread can take the parking call, the main thread keeps sweeping.
-- The loader ships the API at .local/loader_payload/thread.lua:104-279 and its own comment warns
-- "a chance to crash the game process because of unfixed race condition in native primitives".
-- Stage 1: a thread that only prints (does the API work, and can we see its output over our socket).
-- Stage 2: a thread that calls 601 0x0C (the command measured to park) while main keeps printing.
print("=== PROBE 1175a: LOADER THREAD API ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function spin(n) local x=0 for i=1,n do x=x+i end return x end

local fd = 0
do
  local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end)
  if ok then fd = v end
  print(string.format("[F] probe socket fd=%d (0 = the thread cannot send here)", fd))
end

local function run_thread(label, code)
  local ok, res = pcall(run_lua_code_in_new_thread, code, { async = true, client_fd = fd })
  if ok then print(string.format("[%s] spawn ok", label))
  else print(string.format("[%s] spawn FAILED: %s", label, tostring(res))) end
  return ok
end

print("[1] spawning print-only thread")
local s1 = run_thread("1", [[
  print("T1 state alive; pipe="..tostring(syscall and syscall.pipe and syscall.pipe.fn_addr))
  for i=1,4 do print("THREAD-ALIVE "..i) end
  print("THREAD-DONE")
]])
for i=1,6 do print(string.format("MAIN-%d", i)) spin(4000000) end
print(string.format("[1] main survived stage 1, spawn_ok=%s", tostring(s1)))

if s1 then
  print("[2] spawning thread that calls 601 cmd 0x0C (the known parker)")
  local park_ok = run_thread("2", [[
    local buf = memory.alloc(0x1000)
    local okp, pipe = pcall(function() return syscall.pipe and syscall.pipe.fn_addr end)
    print("T2 pipe_ok="..tostring(okp).." fn="..tostring(pipe))
    local ok, rv = pcall(function()
      local t = {}
      for k,v in pairs(syscall.pipe) do t[k]=v end
      t.syscall_no = 601
      setmetatable(t, getmetatable(syscall.pipe))
      return t(0x0C, buf, 0x1000, 0, 0, 0)
    end)
    print("T2 601 0x0C returned ok="..tostring(ok).." rv="..tostring(rv))
  ]])
  for i=1,8 do print(string.format("MAIN2-%d", i)) spin(6000000) end
  print(string.format("[2] main survived stage 2, park_thread_spawn_ok=%s", tostring(park_ok)))
else
  print("[2] SKIPPED: stage 1 did not spawn")
end

print("[Z] alive")
print("=== 1175a DONE ===")
