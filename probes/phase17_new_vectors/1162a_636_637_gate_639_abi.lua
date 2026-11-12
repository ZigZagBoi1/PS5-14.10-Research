-- CRASH_CLASS: SAFE
-- PROBE 1162a: the write half of the timezone table is bit-62 gated (636/637),
-- and 639 takes a five-slot uap (the inverse conversion).
--
-- 636 set_timezone_info (sys_636.c, target 0xffffffff8b07e4d0) would copy
-- count*16 bytes of USER data into the global timezone table
-- 0xffffffff8e2d5920 - a bounded 8 KB kernel .data write - but its first act is
--   if (!sub_ffffffff8afc8f90(PTR(td,0x140))) return 1;
-- and that helper is (*(u64*)(authority+0x60) >> 62) & 1, the credential bit we
-- do not hold (bit 61). Check ordering: if the gate precedes validation, even
-- count=0 and count=513 return EPERM(1) instead of EINVAL(22).
-- 637 set_phys_fmem_limit has a benign argument check (value<17 -> EINVAL) and
-- reaches the same gate only on the cross-process path.
-- 639 localtime_to_utc: uap = {int64 input; int32 policy; pad; value_out;
-- record_out; correction_out} (five 8-byte slots), value = input-off-correction.
print("=== PROBE 1162a: 636/637 GATES AND 639 ABI ===")

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

local err = get_error_string
local function why(rv)
  if rv ~= -1 then return "" end
  local ok, s = pcall(function() return err() end)
  return ok and (" errno=" .. tostring(s)) or ""
end

local SENT = 0xA5A5A5A5
local recs = memory.alloc(32)
for o = 0, 28, 4 do wr(recs + o, SENT) end
-- a plausible tz record: key = 0, offset 0, correction 0
for o = 0, 12, 4 do wr(recs + o, 0) end

local c636, c637, c638, c639 = make_syscall(636), make_syscall(637), make_syscall(638), make_syscall(639)

local function t636(label, rp, count)
  local ok, rv = pcall(function() return c636(uint64(rp), count) end)
  local r = ok and to_num(rv) or -9999
  print(string.format("[636/%s] records=%s count=%d -> rv=%d%s", label, rp == 0 and "NULL" or "buf", count, r, why(r)))
end
t636("gate-first check", 0, 1)
t636("count 0", recs, 0)
t636("count 1", recs, 1)
t636("count 2", recs, 2)
t636("count 512", recs, 512)
t636("count 513", recs, 513)
t636("count 0x10000", recs, 65536)

local function t637(label, pid, value)
  local ok, rv = pcall(function() return c637(pid, uint64(value)) end)
  local r = ok and to_num(rv) or -9999
  print(string.format("[637/%s] pid=%d value=0x%X -> rv=%d%s", label, pid, value, r, why(r)))
end
t637("value 0", 0, 0)
t637("value 1", 0, 1)
t637("value 16", 0, 16)
t637("value 17", 0, 17)
t637("value 0x1000", 0, 0x1000)
t637("pid 1", 1, 0x1000)

-- 639: five slots, policy in the low dword of slot 1
local vout = memory.alloc(8)
local rout = memory.alloc(16)
local cout = memory.alloc(16)
local function fill()
  for o = 0, 12, 4 do wr(rout + o, SENT) end
  for o = 0, 4, 4 do wr(vout + o, SENT); wr(cout + o, SENT) end
end
local function t639(label, input_hex, policy_lo)
  fill()
  local ok, rv = pcall(function() return c639(uint64(input_hex), uint64(policy_lo), uint64(vout), uint64(rout), uint64(cout)) end)
  local r = ok and to_num(rv) or -9999
  local kh, kl = rd(rout + 4), rd(rout)
  local key = (kh and kl) and sgn64(kh, kl) or 0
  local val = sgn64(rd(vout + 4) or 0, rd(vout) or 0)
  local corr = sgn32(rd(cout) or 0)
  print(string.format("[639/%s] input=%s policy=%d -> rv=%d key=%d value=%d nearest=%d%s",
    label, input_hex, sgn32(policy_lo), r, key, val, corr, why(r)))
end
t639("policy -1 behind boundary", "0xFFFFFFFFFDC7BB71", 0xFFFFFFFF)
t639("policy -1 at boundary",      "0xFFFFFFFFFDC7BB70", 0xFFFFFFFF)
t639("policy -1 epoch 0",          "0x0000000000000000", 0xFFFFFFFF)
t639("policy 0",                   "0x0000000000000000", 0)

local function t638(input_hex)
  fill()
  local ok, rv = pcall(function() return c638(uint64(input_hex), uint64(vout), uint64(rout), uint64(cout)) end)
  local r = ok and to_num(rv) or -9999
  local kh, kl = rd(rout + 4), rd(rout)
  print(string.format("[638/compare] input=%s -> rv=%d key=%d value=%d nearest=%d",
    input_hex, r, (kh and kl) and sgn64(kh, kl) or 0, sgn64(rd(vout + 4) or 0, rd(vout) or 0), sgn32(rd(cout) or 0)))
end
t638("0xFFFFFFFFFDC7BB71")
t638("0x0000000000000000")
print(string.format("[Z] alive pid=%d", to_num(make_syscall(20)())))
print("=== DONE ===")
