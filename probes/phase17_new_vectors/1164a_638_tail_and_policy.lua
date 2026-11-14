-- CRASH_CLASS: SAFE
-- PROBE 1164a: after 1163a - the table continues past 2100, and the policy slot
--              only matters when lo >= 2, which 1163a's sweep accidentally skipped
--
-- 1163a measured (results/phase17_new_vectors/1163a_639_five_slots_20261104_145220.txt):
--   * 639's uap is five slots and value = input - offset - correction (delta 0 in
--     three mid-table cases, so the _DAT_8e4305b0 < 0 branch is NOT taken on 14.10);
--   * the lo < 2 guard is present: input 0xFFFFFFFFFF000000 returned record 0 with
--     rv = 0 and no panic, so table[-1] is unreachable;
--   * [F] above-last (input 0x100000000) returned key 4128627600, which is past
--     4102444800 (2100-01-01) and past 1161a's horizon stop "past-2100", so the
--     table has records 1161a deliberately did not walk.
--   * [E] policy sweep used input 0, where lo = 1 and the body short-circuits into
--     the lo < 2 branch *before* policy is read, so it could not have measured
--     policy at all.
--
-- Width and indexing facts this probe has to respect (1161a, 1163a):
--   * the record key is an int64 and its tail value exceeds 2^31 (1161a ends on record
--     257 = 4096573200; 1163a [F] read 4128627600), so the key is rebuilt from BOTH
--     dwords and sign-extended on the high one. A sign-extended low dword prints
--     4096573200 as -198394096 and makes every "key > 4096573200" test false;
--   * 1161a's dump stops at record 257 because its *input* crossed 2100, not because
--     the table ended - that is the question [A]/[A2] answer;
--   * the "nearest" 4-byte correction_out is the only output that can change while the
--     key stays the same, so [B]/[B2] print it: a policy that only gates the lo-2
--     lookback is invisible in key/off/corr/delta.
--
-- This probe answers three things with read-only calls:
--   A. how many records exist past 4096573200, and what the true last key is;
--   B. whether the policy dword changes selection or arithmetic for an input whose
--      index is >= 2 (it gates the "-2 lookback", sys_638.c:389/396-413);
--   C. whether 638 and 639 select the same record for the same input.
--
-- SAFE: every call is 638 or 639 with an in-table or just-past-the-end input, all
-- three destinations are 0x20-byte allocations, nothing is written outside our own
-- heap, no lock is held across a copy_out, and every call is pcall'd. The only
-- theoretically unrecoverable read (table[lo-2] without its guard) is excluded by
-- 1163a's measurement that the guard is present. [AV] adds one 639 call 13 years past
-- the tail and one 638 at key-1, both the same just-past-the-end class as 1163a's [F].
--
-- REVIEW (correctness pass) 2026-11-04: the record key is ONE int64, but call638/
-- call639 returned its two dwords sign-extended independently, so any key >= 2^31
-- (2038) printed negative - and every key this probe walks (4096573200..4128627600)
-- is past that. Effect: [A]'s stop test (input > key + 125e6) was therefore always
-- true, so the walk quit three probes past 4096573200 and never reached the
-- 4128627600 record; [A2]'s guard (key > 4096573200) was false, so the backwards walk
-- never ran and reported 0 records above the horizon - the opposite of the measurement
-- it exists to make. Keys are now rebuilt from both dwords (key64), [A] keeps the
-- 40-probe cap but prints why it stopped, [AV] re-checks the claimed top by a second
-- route (639 from 13 years past it, 638 at key-1), [A2] reports whether its 24-step cap
-- bit, and [B]/[B2] print the "nearest" output plus a selection-changed summary.
print("=== PROBE 1164a: TABLE TAIL AND POLICY ===")

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
local function si32(x) if x == nil then return nil end if x >= 2147483648 then return x - 4294967296 end return x end
local function u32(x) if x < 0 then return x + 4294967296 end return x end
local function dec(x) if x == nil then return "-" end return string.format("%.0f", x) end
local function errno()
  local ok, e = pcall(function() return get_error_string() end)
  if ok and e then return tostring(e) end
  return "?"
end
local function hexstr(hi, lo) return string.format("0x%08X%08X", hi, lo) end
-- exact split of a non-negative Lua number below 2^53 into hi/lo dwords, so an
-- input above 2^32 does not silently wrap inside string.format
local function hexnum(n)
  local hi = math.floor(n / 4294967296)
  local lo = n - hi * 4294967296
  return hexstr(hi, lo)
end

local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do pcall(function() memory.write_qword(sa + o, 0) end) end
wr(sa, 1); wr(sa + 8, 2)
local sok, srv = pcall(function() return make_syscall(416)(12, sa, 0) end)
print(string.format("[S] SIGSYS shield 416(SIGSYS, SIG_IGN) pcall=%s rv=%s", tostring(sok), dec(sok and to_num(srv) or nil)))

local c638, c639 = make_syscall(638), make_syscall(639)
-- 0x20 bytes each: an 8-byte value, a 16-byte record and a 4-byte nearest all fit,
-- so a mis-sized body cannot spill into the neighbouring allocation.
local vout, rout, cout = memory.alloc(0x20), memory.alloc(0x20), memory.alloc(0x20)
local keyout = memory.alloc(0x20)
local SENT = 0xA5A5A5A5
-- record key = ONE int64: signed HIGH dword * 2^32 + UNSIGNED low dword. call638/call639
-- hand back both dwords unsigned (rd), so key64(0, 4128627600) = 4128627600 and
-- key64(-1 + 2^32, 4257725296) = -37242000; a sign-extended LOW dword alone is not a key.
local function key64(kh, kl)
  if kh == nil or kl == nil then return nil end
  if kl == SENT or kh == SENT then return nil end   -- record_out untouched: no record written
  return si32(kh) * 4294967296 + u32(kl)
end
local function fill()
  for o = 0, 0x1C, 4 do wr(vout + o, SENT); wr(rout + o, SENT); wr(cout + o, SENT); wr(keyout + o, SENT) end
end
fill()
local proved = true
for o = 0, 0x1C, 4 do if rd(rout + o) ~= SENT or rd(vout + o) ~= SENT then proved = false end end
print(string.format("[S] sentinel fill proved=%s", tostring(proved)))

-- one 638 call: it writes value (8 B), record (16 B), nearest (4 B) from three slots
local function call638(input_hex)
  fill()
  local ok, rv = pcall(function()
    return c638(uint64(input_hex), uint64(vout), uint64(rout), uint64(cout))
  end)
  local r = ok and to_num(rv) or -9999
  -- key dwords come back UNSIGNED (key64 rebuilds the int64); off/corr are int32 fields
  return r, rd(rout + 4), rd(rout), si32(rd(rout + 8)), si32(rd(rout + 12))
end
-- one 639 call: five slots, policy in the low dword of the second
local function call639(input_hex, policy)
  fill()
  local ok, rv = pcall(function()
    return c639(uint64(input_hex), uint64(policy), uint64(vout), uint64(rout), uint64(cout))
  end)
  local r = ok and to_num(rv) or -9999
  return r, rd(rout + 4), rd(rout), si32(rd(rout + 8)), si32(rd(rout + 12))
end

-- C first: do the two numbers agree on a mid input?
print("[C] 638 vs 639 on input 1000000000 (key, off, corr, nearest)")
local r638, k638h, k638l, o638, c638f = call638("0x000000003B9ACA00")
local k638v, n638 = key64(k638h, k638l), si32(rd(cout))
local r639, k639h, k639l, o639, c639f = call639("0x000000003B9ACA00", 0)
local k639v, n639 = key64(k639h, k639l), si32(rd(cout))
print(string.format("  638 rv=%d key=%s off=%s corr=%s near=%s", r638, dec(k638v), dec(o638), dec(c638f), dec(n638)))
print(string.format("  639 rv=%d key=%s off=%s corr=%s near=%s  same_key=%s",
  r639, dec(k639v), dec(o639), dec(c639f), dec(n639),
  tostring(k638v ~= nil and k638v == k639v)))

-- A: walk past 1161a's horizon. Each probe returns the last key <= input, so the
-- true last record is the largest key the table holds: step upward until the
-- selected key stops moving for three probes AND the input is years past it.
print("[A] records past 4096573200 (1161a's horizon stop)")
local step = 7776000            -- 90 days
local input = 4096573200
local lastkey, stable, prevkey = nil, 0, nil
local found = 0
local why = "cap40"
for i = 1, 40 do
  local r, kh, kl, off, corr = call638(hexnum(input))
  local kk = key64(kh, kl)
  if kk == nil then
    print(string.format("  [%02d] input=%s no record (rv=%d)", i, dec(input), r))
    why = "read-failed"
    break
  end
  if kk ~= prevkey then
    found = found + 1
    print(string.format("  [%02d] input=%s key=%s off=%s corr=%s", i, dec(input), dec(kk), dec(off), dec(corr)))
    prevkey = kk
    stable = 0
  else
    stable = stable + 1
  end
  lastkey = kk
  if stable >= 3 and input > kk + 125000000 then why = "stable+4y"; break end  -- ~4 years past it
  input = input + step
end
print(string.format("  [A] distinct keys seen=%d highest_key=%s stop=%s", found, dec(lastkey), why))
if why == "cap40" then
  print("  [A] 40 probes exhausted: highest_key is the 40th probe, NOT proven to be the last record")
end

-- "highest" is a claim about absence, so check it by a second route before believing it:
-- 639 (a separate handler over the same table) must clamp to the same key from 13 years
-- past it, and 638 at key-1 must land strictly lower. Either failing means the 40-probe
-- cap stopped the walk inside the table.
if lastkey ~= nil and lastkey > 0 then
  local rv2, kh2, kl2 = call639(hexnum(lastkey + 400000000), 0)
  local kfar = key64(kh2, kl2)
  local rv3, kh3, kl3 = call638(hexnum(lastkey - 1))
  local kprev = key64(kh3, kl3)
  print(string.format("  [AV] 639 far=%s -> key=%s rv=%d same=%s | 638 key-1 -> key=%s rv=%d lower=%s",
    dec(lastkey + 400000000), dec(kfar), rv2, tostring(kfar == lastkey),
    dec(kprev), rv3, tostring(kprev ~= nil and kprev < lastkey)))
end

-- how many records sit between the horizon key and the highest one?
print("[A2] exact-key walk backwards from the highest key")
local key = lastkey
local back = 0
while back < 24 and key ~= nil and key > 4096573200 do
  local r, kh, kl = call638(hexnum(key - 1))
  local kk = key64(kh, kl)
  if kk == nil or kk == key then break end
  back = back + 1
  print(string.format("  [%02d] %s", back, dec(kk)))
  key = kk
end
print(string.format("  [A2] records between horizon and top=%d%s (stopped at %s)",
  back, (back >= 24) and "+ walk capped at 24" or "", dec(key)))

-- B: policy, with an index >= 2 so the body actually reads it
-- lo >= 2 is not assumed: 1161a's dump puts key 985482000 between record 32 (530672400)
-- and record 64 (1035680400), so lo ~ 60, unlike the lo = 1 that made 1163a's [E] vacuous.
-- policy is "(int)param_2[1]" under the guard "lo < 2 || policy < 0", so the 0xFFFFFFFF
-- row is a third case (lookback skipped), not a bit pattern.
print("[B] policy with input 1000000000 (index >= 2)")
local pols = { 0, 1, 2, "0x00000000FFFFFFFF" }
local pkeys = {}
for i = 1, #pols do
  local r, kh, kl, off, corr = call639("0x000000003B9ACA00", pols[i])
  local kk, nearv = key64(kh, kl), si32(rd(cout))
  local vlo = si32(rd(vout))          -- value fits int32 here (<= 1e9)
  pkeys[i] = kk
  -- a nil off/corr is a failed record copy; folding it to 0 would report a false
  -- arithmetic anomaly, so exp goes nil instead.
  local exp = nil
  if off ~= nil and corr ~= nil then exp = 1000000000 - off - corr end
  local delta = (vlo ~= nil and exp ~= nil) and (vlo - exp) or nil
  print(string.format("  policy=%-10s rv=%d key=%s off=%s corr=%s near=%s delta=%s",
    tostring(pols[i]), r, dec(kk), dec(off), dec(corr), dec(nearv), dec(delta)))
end
-- delta is 0 by construction for whichever record was selected (exp is built from the
-- same call's off/corr), so it separates only the _DAT_8e4305b0 < 0 branch. A change of
-- SELECTION can show only as a different key; a change confined to the lo-2 lookback can
-- show only as a different near. Both columns are printed above.
local selsame = true
for i = 2, #pols do if pkeys[i] == nil or pkeys[i] ~= pkeys[1] then selsame = false end end
print(string.format("  [B] selection_same_for_all_policies=%s", tostring(selsame)))

-- B2: the same test on a second index, in case the lookback lands elsewhere.
-- value = 1e8 - off - corr still fits int32 here, so the delta test stays valid.
print("[B2] policy with input 100000000 (index >= 2, different record)")
for i = 1, #pols do
  local r, kh, kl, off, corr = call639("0x0000000005F5E100", pols[i])
  local kk, nearv = key64(kh, kl), si32(rd(cout))
  local vlo = si32(rd(vout))
  local exp = nil
  if off ~= nil and corr ~= nil then exp = 100000000 - off - corr end
  local delta = (vlo ~= nil and exp ~= nil) and (vlo - exp) or nil
  print(string.format("  policy=%-10s rv=%d key=%s off=%s corr=%s near=%s delta=%s",
    tostring(pols[i]), r, dec(kk), dec(off), dec(corr), dec(nearv), dec(delta)))
end

local okz, pidz = pcall(function() return make_syscall(20)() end)
print(string.format("[Z] alive pid=%d", okz and to_num(pidz) or -1))
print("=== DONE ===")
