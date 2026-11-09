-- CRASH_CLASS: MODERATE
-- PROBE 496d: how many helper threads survive the gate, 2 then 3 then 4
-- 496c proved six gated threads are fatal on their own, with no syscall in the
-- body, so the concurrency limit is a property of the helper and not of AIO.
-- This walks the count upward in one connection: each stage prints before it
-- spawns, so whatever kills the process names the count that did it.
print("=== PROBE 496d: helper thread count limit ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
end
local gate = memory.alloc(0x400)
local function body_for(slot)
  local txt = "while memory.read_dword(GATE) == 0 do end\n" ..
    "memory.write_dword(GATE + 4 + SLOT * 4, 1)\n" ..
    "for i = 1, 100 do memory.write_dword(GATE + 0x200 + SLOT * 4, i) end\n" ..
    "memory.write_dword(GATE + 0x80 + SLOT * 4, 1)\n"
  txt = txt:gsub("GATE", tostring(addrnum(gate)))
  txt = txt:gsub("SLOT", tostring(slot))
  return txt
end
local function stage(n, rounds)
  for r = 1, rounds do
    print(string.format("[stage %d round %d] spawning", n, r))
    for off = 0, 0x3FF - 1, 4 do pcall(function() memory.write_dword(gate + off, 0) end) end
    local threads, okall = {}, true
    for slot = 1, n do
      local ok, thr = pcall(run_lua_code_in_new_thread, body_for(slot), { async = true })
      if not ok or type(thr) ~= "table" then
        print(string.format("[stage %d] spawn %d failed", n, slot)); okall = false; break
      end
      threads[slot] = thr
      print(string.format("[stage %d] spawned %d", n, slot))
    end
    if not okall then return false end
    local spins = 0
    while spins < 20000000 do
      local got = 0
      for slot = 1, n do got = got + to_num(memory.read_dword(gate + 4 + slot * 4)) end
      if got >= n then break end
      spins = spins + 1
    end
    print(string.format("[stage %d round %d] all ready after %d spins", n, r, spins))
    pcall(function() memory.write_dword(gate, 1) end)
    local jspins = 0
    while jspins < 20000000 do
      local got = 0
      for slot = 1, n do got = got + to_num(memory.read_dword(gate + 0x80 + slot * 4)) end
      if got >= n then break end
      jspins = jspins + 1
    end
    for slot = 1, n do pcall(function() return threads[slot]:join() end) end
    local line = string.format("[stage %d round %d] counters", n, r)
    for slot = 1, n do line = line .. string.format(" %d", to_num(memory.read_dword(gate + 0x200 + slot * 4))) end
    print(line)
  end
  return true
end
for _, n in ipairs({ 2, 3, 4 }) do
  if not stage(n, 2) then break end
  print(string.format("[stage %d] survived", n))
end
print("=== PROBE 496d COMPLETE ===")
