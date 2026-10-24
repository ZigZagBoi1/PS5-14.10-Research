-- CRASH_CLASS: LOW
-- PROBE 502f: poll-then-delete at scale, and why 502e's deletes failed
-- 502e created 400 objects and every delete reported a non-zero status. Either the
-- delete needs a completed object (state 3/4, set by poll) or the call itself failed.
-- Here: [A] create 8, poll, delete with ret and statuses printed; [B] create 64,
-- poll, delete; [C] repeat [B] four times to see whether the table wears out.
print("=== PROBE 502f: poll then delete at scale ===")
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
local ids = memory.alloc(0x1000)
local res = memory.alloc(0x1000)
for o = 0, 0x1FC, 4 do pcall(function() memory.write_dword(data + o, 0) end) end
local D, O = hx(to_num(data)), hx(to_num(out))
local IDS, RES = to_num(ids), to_num(res)

local function batch(n, label)
  local made = 0
  for i = 0, n - 1 do
    pcall(function() memory.write_dword(out, 0) end)
    local ok = pcall(function() return sc_c(1, uint64(D), 1, 1, uint64(O)) end)
    local id = to_num(memory.read_dword(out))
    if ok and id ~= 0 then pcall(function() memory.write_dword(ids + i * 4, id) end); made = made + 1 end
  end
  local pr = pcall(function() return sc_p(uint64(hx(IDS)), made, uint64(hx(RES))) end)
  local s = {}
  for i = 0, math.min(made, 4) - 1 do s[#s + 1] = string.format("%X", to_num(memory.read_dword(res + i * 4))) end
  local okd, retd = pcall(function() return sc_d(uint64(hx(IDS)), made, uint64(hx(RES))) end)
  local clean, zero, other = 0, 0, 0
  for i = 0, made - 1 do
    local st = to_num(memory.read_dword(res + i * 4))
    if st == 0 then clean = clean + 1 elseif st == 0x77777777 then zero = zero + 1 else other = other + 1 end
  end
  print(string.format("%s made=%d poll-ret=%s polls=%s delete-ret=%s clean=%d other=%d untouched=%d",
    label, made, tostring(pr), table.concat(s, ","), tostring(retd), clean, other, zero))
end

batch(8, "A")
for i = 1, 4 do batch(64, "B" .. i) end
print("=== PROBE 502f COMPLETE ===")
