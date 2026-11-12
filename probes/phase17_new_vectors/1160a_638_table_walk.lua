-- CRASH_CLASS: SAFE
-- PROBE 1160a: 638 is utc_to_localtime - walk its whole record table
--
-- 1027a called 638(input, 0, buf, 0x100): uap = {input, value_out, record_out,
-- correction_out}, so the qword pair it read was record_out, the 16-byte
-- Record16 {key, offset, correction} copied from the global table, and the
-- 4-byte correction_out aimed at address 0x100 returned EFAULT - that is why
-- rv was -1 while data had already been written. 1027a's 0xFFFFFFFFFDC7BB70 is
-- a *negative epoch key* (two's complement -37242000 s) and 0xE10 is
-- offset=3600, one hour. This probe settles it by walking every record.
--
-- 13.60 body (results/kernel_handlers/decompiled/sys_638.c): table
-- 0xffffffff8e2d5920 (RVA 0x42d5920), count 0xffffffff8e2d7920, mode
-- 0xffffffff8e4305b0; the count global sits table+0x2000 = 512 slots, so a
-- count above 512 would make the handler read past its table into .data.
-- index = lo-1 in [0,count-1]; value = input + offset + correction; copyouts
-- of 8 / 16 / 4 bytes to uap+0x08 / +0x10 / +0x18.
print("=== PROBE 1160a: 638 TABLE WALK ===")

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
-- memory.read_dword returns a uint64 object (memory.lua:41-44), never a Lua
-- number: tonumber(obj) is nil, only obj:tonumber() gives the value.
local function rd(a)
  local ok, v = pcall(function() return memory.read_dword(a) end)
  if not ok or v == nil then return nil end
  local ok2, n = pcall(function() return v:tonumber() end)
  if ok2 and n ~= nil then return n end
  return nil
end
local function wr(a, v) local ok = pcall(function() memory.write_dword(a, v) end); return ok end
local function hex64(h, l) return string.format("0x%08X%08X", h, l) end
-- exact two's complement, no doubles above 2^53
local function sgn(h, l)
  if h >= 2147483648 then
    local nh, nl = 4294967295 - h, 4294967295 - l
    nl = nl + 1
    if nl > 4294967295 then nl = 0; nh = nh + 1 end
    return -(nh * 4294967296 + nl)
  end
  return h * 4294967296 + l
end
local function inc_hex(h, l)
  local nl, nh = l + 1, h
  if nl > 4294967295 then nl = 0; nh = nh + 1 end
  return hex64(nh, nl)
end

-- shield: absent slots raise SIGSYS with the default disposition
local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do pcall(function() memory.write_qword(sa + o, 0) end) end
wr(sa, 1); wr(sa + 8, 2)
pcall(function() return make_syscall(416)(12, sa, 0) end)

local vout = memory.alloc(8)     -- uap+0x08, 8-byte value
local rout = memory.alloc(16)    -- uap+0x10, Record16
local cout = memory.alloc(16)    -- uap+0x18, 4-byte nearest correction
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
local MAX = 600
local rows = {}
local input = "0xC000000000000000"   -- very negative: index = 0
local stop = "cap"

for i = 1, MAX do
  fill()
  local ok, rv = pcall(function() return c638(uint64(input), uint64(vout), uint64(rout), uint64(cout)) end)
  local r = ok and to_num(rv) or -9999
  local kh, kl = rd(rout + 4), rd(rout)
  if kh == nil or kl == nil then stop = "read-failed"; break end
  local oh, ol = rd(rout + 12) or 0, rd(rout + 8) or 0
  local vh, vl = rd(vout + 4) or 0, rd(vout) or 0
  local key, off, val = sgn(kh, kl), sgn(oh, ol), sgn(vh, vl)
  local corr = sgn(rd(cout + 4) or 0, rd(cout) or 0)
  local hex = hex64(kh, kl)
  rows[i] = { i = i, hex = hex, key = key, off = off, corr = corr, val = val, rv = r,
              raw_corr = string.format("%08X%08X", rd(cout + 4) or 0, rd(cout) or 0) }
  if i <= 6 or (i % 64) == 0 then
    print(string.format("  [%d] key=%s (%d) off=%d corr=%d val=%d rv=%d",
      i, hex, key, off, corr, val, r))
  end
  if r == 34 then stop = "count=0-ERANGE"; break end
  if i > 1 and rows[i - 1].hex == hex then stop = "record-repeated"; break end
  input = inc_hex(kh, kl)
end

local n = #rows
print(string.format("[W] records=%d first=%s last=%s stopped=%s", n,
  n > 0 and rows[1].hex or "-", n > 0 and rows[n].hex or "-", stop))

local bad, neg = 0, 0
for i = 1, n do
  local r0 = rows[i]
  if r0.key < 0 then neg = neg + 1 end
  local key_ok = (r0.key > -2208988800) and (r0.key < 4102444800)
  local off_ok = (r0.off >= -50400) and (r0.off <= 50400)
  local cor_ok = (r0.corr >= -7200) and (r0.corr <= 7200)
  if not (key_ok and off_ok and cor_ok) then
    bad = bad + 1
    if bad <= 12 then
      print(string.format("  [!] %d key=%s (%d) off=%d corr=%d val=%d raw_corr=%s",
        i, r0.hex, r0.key, r0.off, r0.corr, r0.val, r0.raw_corr))
    end
  end
end
print(string.format("[C] out-of-range records=%d negative_keys=%d (epoch window 1900..2100, offsets +-14h)", bad, neg))
print(string.format("[T] table window is 512 slots (count global at table+0x2000): count_gt_512=%s",
  tostring(n > 512)))

if n > 0 then
  local r0 = rows[1]
  local expect = r0.key + r0.off + r0.corr
  print(string.format("[A] row1 key=%d off=%d corr=%d -> value %d, arithmetic expects %d (delta %d)",
    r0.key, r0.off, r0.corr, r0.val, expect, r0.val - expect))
end
print(string.format("[Z] alive pid=%d", to_num(make_syscall(20)())))
print("=== DONE ===")
