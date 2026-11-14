-- CRASH_CLASS: SAFE
-- PROBE 1161a: dump 638's utc_to_localtime record table by boundary bisection
--
-- 1160a established the ABI by measurement: uap = {int64 input, uint64 value_out,
-- uint64 record_out, uint64 correction_out}; record_out receives the 16-byte
-- Record16 {int64 key; int32 offset; int32 correction} read from the global
-- table, value_out receives input+offset+correction, correction_out receives a
-- 4-byte "nearest correction". Stepping input by +1 does not advance the record
-- (index = last key <= input), so this probe finds the next boundary by
-- exponential search + bisection and walks the whole table that way.
--
-- 13.60 body: table 0xffffffff8e2d5920 (RVA 0x42d5920), count 0xffffffff8e2d7920
-- = table+0x2000 (512 slots), mode 0xffffffff8e4305b0.
print("=== PROBE 1161a: 638 TABLE DUMP ===")

local function to_num(v)
  if type(v) == "table" then
    if v.tonumber then local ok, r = pcall(function() return v:tonumber() end); if ok and r then return r end end
    if v.h and v.l then return v.h * 2^32 + v.l end
  end
  return tonumber(v) or 0
end
local function make_syscall(num)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = num
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function rd(a)
  local ok, v = pcall(function() return memory.read_dword(a) end)
  if not ok or v == nil then return nil end
  local ok2, n = pcall(function() return v:tonumber() end)
  if ok2 and n ~= nil then return n end
  return nil
end
local function wr(a, v) local ok = pcall(function() memory.write_dword(a, v) end); return ok end
local function hex64(h, l) return string.format("%08X%08X", h, l) end
local function sgn64(h, l)
  if h >= 2147483648 then
    local nh, nl = 4294967295 - h, 4294967295 - l
    nl = nl + 1
    if nl > 4294967295 then nl = 0; nh = nh + 1 end
    return -(nh * 4294967296 + nl)
  end
  return h * 4294967296 + l
end
local function sgn32(v) if v >= 2147483648 then return v - 4294967296 end return v end

local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do pcall(function() memory.write_qword(sa + o, 0) end) end
wr(sa, 1); wr(sa + 8, 2)
pcall(function() return make_syscall(416)(12, sa, 0) end)

local vout = memory.alloc(8)
local rout = memory.alloc(16)
local cout = memory.alloc(16)
local SENT = 0xA5A5A5A5
local function fill()
  for o = 0, 12, 4 do wr(rout + o, SENT) end
  for o = 0, 4, 4 do wr(vout + o, SENT); wr(cout + o, SENT) end
end
fill()
local proved = true
for o = 0, 12, 4 do if rd(rout + o) ~= SENT then proved = false end end
print(string.format("[S] sentinel fill proved=%s rec=%X %X %X %X", tostring(proved),
  rd(rout) or 0, rd(rout + 4) or 0, rd(rout + 8) or 0, rd(rout + 12) or 0))

local c638 = make_syscall(638)
local calls, budget = 0, 40000
-- string.format("%X") re-casts through long; build the hex from two dwords so
-- no value above 2^32 ever reaches the format call.
local function num_to_hex(v)
  local u = v
  if u < 0 then u = u + 18446744073709551616 end
  local hi = math.floor(u / 4294967296)
  local lo = u - hi * 4294967296
  return string.format("0x%08X%08X", hi, lo)
end

-- one full read of the selected record, with exact field offsets
local function rec(input)
  fill()
  local ok, rv = pcall(function() return c638(uint64(input), uint64(vout), uint64(rout), uint64(cout)) end)
  calls = calls + 1
  local r = { rv = ok and to_num(rv) or -9999, input_hex = input }
  if not ok then return nil end
  local kh, kl = rd(rout + 4), rd(rout)
  if kh == nil or kl == nil then return nil end
  r.hex = hex64(kh, kl)
  r.key = sgn64(kh, kl)
  r.off = sgn32(rd(rout + 8) or 0)
  r.corr = sgn32(rd(rout + 12) or 0)
  r.nearest = sgn32(rd(cout) or 0)
  r.val = sgn64(rd(vout + 4) or 0, rd(vout) or 0)
  return r
end

local cache = {}
local function key_at(input_hex)
  local c = cache[input_hex]
  if c then return c end
  local r = rec(input_hex)
  if r == nil then return nil end
  cache[input_hex] = r
  return r
end

-- signed 64-bit helpers on hex strings: only +/- and doubling are needed
local function h2n(h)  -- exact-ish: keys live in +-2^40, so doubles are exact
  return tonumber(h, 16)
end

print(string.format("[0] start input 0xC000000000000000 -> key %s", (key_at("0xC000000000000000") or {}).hex or "ERR"))
local first = key_at("0xC000000000000000")
if first == nil then print("[X] first read failed"); print("=== DONE ==="); return end
print(string.format("  first record key=%s (%d) off=%d corr=%d nearest=%d val=%d rv=%d",
  first.hex, first.key, first.off, first.corr, first.nearest, first.val, first.rv))

-- boundary search: smallest T > k with record(T) ~= record(k)
local function next_boundary(k, khex)
  local lo = k
  local step = 1
  local hi = k + step
  local guard = 0
  while true do
    if calls > budget then return nil, "budget" end
    local r = key_at(num_to_hex(hi))
    if r == nil then return nil, "read" end
    if r.hex ~= khex then break end
    lo = hi
    step = step * 2
    hi = k + step
    guard = guard + 1
    if guard > 46 then return nil, "no-boundary" end
  end
  while hi - lo > 1 do
    if calls > budget then return nil, "budget" end
    local mid = lo + math.floor((hi - lo) / 2)
    local r = key_at(num_to_hex(mid))
    if r == nil then return nil, "read" end
    if r.hex ~= khex then hi = mid else lo = mid end
  end
  return hi
end

local rows = { first }
local k = first.key
local stop = "cap"
for i = 2, 512 do
  local nb, why = next_boundary(k, rows[#rows].hex)
  if nb == nil then stop = why or "end"; break end
  if nb > 4102444800 then stop = "past-2100"; break end
  local r = key_at(num_to_hex(nb))
  if r == nil then stop = "read"; break end
  -- the record at the boundary must be the next one, and its own key must equal nb
  if r.key ~= nb then
    print(string.format("  [~] boundary input %d selects key %d (mismatch)", nb, r.key))
  end
  rows[#rows + 1] = r
  k = r.key
  if #rows <= 12 or (#rows % 32) == 0 then
    print(string.format("  [%d] key=%s (%d) off=%d corr=%d nearest=%d rv=%d",
      #rows, r.hex, r.key, r.off, r.corr, r.nearest, r.rv))
  end
end

print(string.format("[W] records=%d calls=%d stop=%s last_key=%s", #rows, calls, stop, rows[#rows].hex))
local bad = 0
for i = 1, #rows do
  local r0 = rows[i]
  local key_ok = (r0.key > -2208988800) and (r0.key < 4102444800)
  local off_ok = (r0.off >= -50400) and (r0.off <= 50400)
  local cor_ok = (r0.corr >= -7200) and (r0.corr <= 7200) and (r0.nearest >= -7200) and (r0.nearest <= 7200)
  if not (key_ok and off_ok and cor_ok) then
    bad = bad + 1
    if bad <= 10 then
      print(string.format("  [!] %d key=%s (%d) off=%d corr=%d nearest=%d", i, r0.hex, r0.key, r0.off, r0.corr, r0.nearest))
    end
  end
end
print(string.format("[C] out-of-plausible-range=%d of %d (key 1900..2100, offset +-14h, correction +-2h)", bad, #rows))
print(string.format("[T] 512-slot window: records_gt_512=%s", tostring(#rows > 512)))
local r1 = rows[1]
print(string.format("[A] row1 value=%d  input+off+corr=%d  delta=%d",
  r1.val, r1.key + r1.off + r1.corr, r1.val - (r1.key + r1.off + r1.corr)))
print(string.format("[Z] alive pid=%d", to_num(make_syscall(20)())))
print("=== DONE ===")
