-- CRASH_CLASS: LOW
-- PROBE 502e: how many live aio objects does the per-process table hold?
-- 502c left 300 helper objects behind and every later create failed, so measure
-- the cap directly: create until a create returns id 0, then delete the lot and
-- see whether creates work again.
print("=== PROBE 502e: aio object cap ===")
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
local sc_c, sc_p, sc_d = make_syscall(669), make_syscall(664), make_syscall(662)
local data, out = memory.alloc(0x200), memory.alloc(0x40)
local ids = memory.alloc(0x800)
local res = memory.alloc(0x800)
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end
local D, O = hx(to_num(data)), hx(to_num(out))
local MAX = 400
local made, firstfail = 0, nil
for i = 0, MAX - 1 do
  pcall(function() memory.write_dword(out, 0) end)
  local ok = pcall(function() return sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if ok and id ~= 0 then
    made = made + 1
    pcall(function() memory.write_dword(ids + made * 4, id) end)
  else
    firstfail = i
    break
  end
  if (i + 1) % 64 == 0 then print("created=" .. made) end
end
print("made=" .. made .. " firstfail=" .. tostring(firstfail))
local clean, other = 0, 0
local off = 1
while off <= made do
  local n = math.min(0x80, made - off + 1)
  for o = 0, n * 4 - 1, 4 do pcall(function() memory.write_dword(res + o, 0x77777777) end) end
  local ok, ret = pcall(function() return sc_d(uint64(hx(to_num(ids) + off * 4)), n, uint64(hx(to_num(res)))) end)
  for k = 0, n - 1 do
    local st = to_num(memory.read_dword(res + k * 4))
    if st == 0 then clean = clean + 1 else other = other + 1 end
  end
  off = off + n
end
print(string.format("delete clean=%d other=%d", clean, other))
local made2 = 0
for i = 1, 16 do
  pcall(function() memory.write_dword(out, 0) end)
  pcall(function() sc_c(1, uint64(D), 1, 1, uint64(O)) end)
  local id = to_num(memory.read_dword(out))
  if id ~= 0 then made2 = made2 + 1 end
end
print("after-delete creates=" .. made2 .. "/16")
print("=== PROBE 502e COMPLETE ===")
