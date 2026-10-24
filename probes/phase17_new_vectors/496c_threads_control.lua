-- CRASH_CLASS: MODERATE
-- PROBE 496c: six helper threads that only spin and touch memory
-- 496b put six threads behind one gate and the process died, but it died with
-- six fresh Lua states as well as six syscalls, so that run cannot say which of
-- the two matters. This is the control: the same spawn count, the same gate, the
-- same page writes, and no 662 at all.
print("=== PROBE 496c: six idle threads behind one gate ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
end
local THREADS = 6
local gate = memory.alloc(0x200)
local function body_for(slot)
  local txt = "while memory.read_dword(GATE) == 0 do end\n" ..
    "memory.write_dword(GATE + 4 + SLOT * 4, 1)\n" ..
    "for i = 1, 100 do memory.write_dword(GATE + 0x100 + SLOT * 4, i) end\n" ..
    "memory.write_dword(GATE + 0x40 + SLOT * 4, 1)\n"
  txt = txt:gsub("GATE", tostring(addrnum(gate)))
  txt = txt:gsub("SLOT", tostring(slot))
  return txt
end
for r = 1, 3 do
  for off = 0, 0x1FF - 1, 4 do pcall(function() memory.write_dword(gate + off, 0) end) end
  local threads, okall = {}, true
  for slot = 1, THREADS do
    local ok, thr = pcall(run_lua_code_in_new_thread, body_for(slot), { async = true })
    if not ok or type(thr) ~= "table" then print(string.format("round %d spawn %d failed", r, slot)); okall = false; break end
    threads[slot] = thr
  end
  if not okall then break end
  local spins = 0
  while spins < 8000000 do
    local n = 0
    for slot = 1, THREADS do n = n + to_num(memory.read_dword(gate + 4 + slot * 4)) end
    if n >= THREADS then break end
    spins = spins + 1
  end
  pcall(function() memory.write_dword(gate, 1) end)
  local jspins = 0
  while jspins < 8000000 do
    local n = 0
    for slot = 1, THREADS do n = n + to_num(memory.read_dword(gate + 0x40 + slot * 4)) end
    if n >= THREADS then break end
    jspins = jspins + 1
  end
  for slot = 1, THREADS do pcall(function() return threads[slot]:join() end) end
  local line = string.format("round %d counters", r)
  for slot = 1, THREADS do line = line .. string.format(" %d", to_num(memory.read_dword(gate + 0x100 + slot * 4))) end
  print(line)
end
print("=== PROBE 496c COMPLETE ===")
