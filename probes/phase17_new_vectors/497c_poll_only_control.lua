-- CRASH_CLASS: RISKY
-- PROBE 497b: delete while another thread polls the same object
-- The delete body releases the table entry at 0x3afc67 and then re-reads the
-- object's sub-object array at 0x3afd0c before freeing at 0x3afee8. Two deletes
-- cannot overlap because the entry is gone, but poll 664 runs the completion
-- path over the same sub-objects, so it is the second caller that can free or
-- replace the slot the delete is about to free. The thread spins on that call;
-- the parent deletes as soon as the thread says it is looping.
print("=== PROBE 497c: polling thread with no delete (control) ===")
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
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res1 = memory.alloc(0x400)
local res2 = memory.alloc(0x400)
local gate = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end
local body = "local t = {}\n" ..
             "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
             "t.syscall_no = 664\n" ..
             "setmetatable(t, getmetatable(syscall.pipe))\n" ..
             "while memory.read_dword(GATE) == 0 do end\n" ..
             "memory.write_dword(GATE + 4, 1)\n" ..
             "for i = 1, 400 do pcall(function() t(IDS, 1, RES2) end) end\n" ..
             "memory.write_dword(GATE + 8, 1)\n"
body = body:gsub("GATE", tostring(addrnum(gate)))
body = body:gsub("IDS", tostring(addrnum(ids)))
body = body:gsub("RES2", tostring(addrnum(res2)))

local rounds = 40
local done = 0
for r = 1, rounds do
  local id = create()
  if not id then print(string.format("round %d create failed", r)); break end
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() return sc664(uint64(ids), uint64(1), uint64(res2)) end)
  pcall(function() memory.write_dword(gate, 0) end)
  pcall(function() memory.write_dword(gate + 4, 0) end)
  pcall(function() memory.write_dword(gate + 8, 0) end)
  for off = 0, 0x40 - 1, 4 do pcall(function() memory.write_dword(res1 + off, 0x77777777) end) end
  local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
  if not ok or type(thr) ~= "table" then print(string.format("round %d spawn failed", r)); break end
  local spins = 0
  while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
  pcall(function() memory.write_dword(gate, 1) end)
  local myok, myrv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res1)) end)
  local jspins = 0
  while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
  pcall(function() return thr:join() end)
  local s1 = to_num(memory.read_dword(res1))
  local s2 = to_num(memory.read_dword(res2))
  print(string.format("round %2d id=%d parentpoll=%s/%#x threadpoll=%#x", r, id,
        myok and tostring(to_num(myrv)) or "-", s1, s2))
  done = done + 1
end
print(string.format("rounds completed=%d", done))
print("=== PROBE 497b COMPLETE ===")
