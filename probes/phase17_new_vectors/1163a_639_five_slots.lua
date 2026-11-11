-- CRASH_CLASS: SAFE
-- PROBE 1163a: 639 is localtime_to_utc - its FIVE-slot ABI, its arithmetic, and its lower guard
--
-- 13.60 body (results/kernel_handlers/decompiled/sys_638.c, the 639 half):
--   struct { int64_t input; int32_t policy; int32_t pad;
--            uintptr_t value_out; uintptr_t record_out; uintptr_t correction_out; };
-- five 8-byte uap slots at +0x00/+0x08/+0x10/+0x18/+0x20, i.e. one more slot than 638.
-- Same table 0xffffffff8e2d5920 (RVA 0x42d5920), same count global at table+0x2000.
-- value = input - offset - correction (638 adds, 639 subtracts). The interior
-- read table[lo-2] is guarded by "(int)lo < 2" (sys_638.c:389), so lo-2 >= 0 and
-- the reachable index stays in [0, n-1]: 639 reads one more record per call than
-- 638 but cannot address one outside the table. This probe measures whether that
-- guard is what runs on 14.10, and whether the policy slot changes the selection.
--
-- SAFE: every destination is an allocated page, every input is an in-table or
-- just-outside-the-table epoch value, no execute-only page is touched, and the
-- whole body is pcall'd. A bad destination is -1 + EFAULT because the copy_out
-- helper installs its own onfault (COPYOUT_CLASS_CLOSED.md:41-49). The ONE read
-- that is not recoverable is the interior table[lo-2] load (sys_639.asm:3430,
-- :3432), a plain movslq: 639 guards it with lo >= 2 (:3419), and if 14.10 has
-- dropped that guard the index is -1 and the address is 0x0000000F8E2D5918/1C,
-- so a kernel #PF there has pcb_onfault == NULL and panics. [F2] below-first is
-- the only call in this file that can reach that path, and it now runs last.
print("=== PROBE 1163a: 639 FIVE-SLOT ABI ===")

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
local function hex64(h, l) return string.format("0x%08X%08X", h, l) end
local function sgn(h, l)
  if h >= 2147483648 then
    local nh, nl = 4294967295 - h, 4294967295 - l
    nl = nl + 1
    if nl > 4294967295 then nl = 0; nh = nh + 1 end
    return -(nh * 4294967296 + nl)
  end
  return h * 4294967296 + l
end
local function si32(d)  -- one int32 field, sign-extended on its own
  if d == nil then return nil end
  if d >= 2147483648 then return d - 4294967296 end
  return d
end
-- every measured quantity can exceed 2^31, so it prints through %.0f, never %d
local function dec(v)
  if v == nil then return "-" end
  return string.format("%.0f", v)
end
local function errno()
  local ok, e = pcall(function() return get_error_string() end)
  if ok and e then return tostring(e) end
  return "?"
end
local function i64(hi, lo)  -- build a uint64 from two dwords, sign-extended hex string
  return hex64(hi, lo)
end

-- shield: absent slots raise SIGSYS with the default disposition
local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do pcall(function() memory.write_qword(sa + o, 0) end) end
wr(sa, 1); wr(sa + 8, 2)
pcall(function() return make_syscall(416)(12, sa, 0) end)

local c639 = make_syscall(639)
local vout = memory.alloc(8)
local rout = memory.alloc(16)
local cout = memory.alloc(8)
local SENT = 0xA5A5A5A5
local function wr_ok(a)  -- "this dword no longer holds the sentinel"
  local v = rd(a)
  return v ~= nil and v ~= SENT
end
local function fill()
  for o = 0, 4, 4 do wr(vout + o, SENT) end
  for o = 0, 12, 4 do wr(rout + o, SENT) end
  for o = 0, 4, 4 do wr(cout + o, SENT) end
end
fill()
local proved = true
for o = 0, 4, 4 do if rd(vout + o) ~= SENT then proved = false end end
for o = 0, 12, 4 do if rd(rout + o) ~= SENT then proved = false end end
for o = 0, 4, 4 do if rd(cout + o) ~= SENT then proved = false end end
print(string.format("[S] sentinel fill proved=%s v=%X rec=%X %X %X %X c=%X", tostring(proved),
  rd(vout) or 0, rd(rout) or 0, rd(rout + 4) or 0, rd(rout + 8) or 0, rd(rout + 12) or 0, rd(cout) or 0))

local function call639(input_hex, policy, vo, ro, co)
  fill()
  local ok, rv = pcall(function()
    return c639(uint64(input_hex), uint64(policy), uint64(vo), uint64(ro), uint64(co))
  end)
  local r = ok and to_num(rv) or -9999
  local e = (r == -1) and errno() or ""
  -- Record16 = {int64 key; int32 offset; int32 correction;} (sys_638.c:16-19):
  -- key at +0, offset at +8, correction at +12. rd(rout+12) is the correction
  -- dword, NOT the high half of a 64-bit offset, so each int32 is sign-extended
  -- on its own. Buffers are read through the globals because [C] passes a zero
  -- slot, and rd(0) would be a wild read of the probe's own making.
  local kh, kl = rd(rout + 4), rd(rout)
  local rw = (kh ~= nil and kh ~= SENT) or (kl ~= nil and kl ~= SENT)
  local vh, vl = rd(vout + 4), rd(vout)
  local vw = (vh ~= nil and vh ~= SENT) or (vl ~= nil and vl ~= SENT)
  local cn = rd(cout)
  local nw = (cn ~= nil and cn ~= SENT)
  local key = rw and sgn(kh, kl) or nil
  local off = rw and si32(rd(rout + 8)) or nil
  local corr = rw and si32(rd(rout + 12)) or nil
  local val = vw and sgn(vh, vl) or nil
  local nearest = nw and si32(cn) or nil
  return r, e, key, off, corr, val, nearest, vw, rw
end

-- [A] well-formed call: policy 0, all three destinations valid
print("[A] well-formed call, five slots")
local r, e, key, off, corr, val, nearest, vw, rw = call639("0xC000000000000000", 0, vout, rout, cout)
-- no arithmetic claim on this row: 0xC000000000000000 is 2^62, past double
-- precision, so it is here for the field mapping and the two write flags only
print(string.format("  rv=%d errno=%s value_written=%s record_written=%s", r, e, tostring(vw), tostring(rw)))
print(string.format("  key=%s off=%s corr=%s val=%s nearest=%s",
  dec(key), dec(off), dec(corr), dec(val), dec(nearest)))

-- [B] the arithmetic: value = input - offset - correction (sys_638.c:443), using the
-- selected record's OWN offset and correction. The 4-byte out at uap+0x20 is the
-- "nearest" correction, a different field that can come from a different index, so
-- it is reported but never enters the delta.
print("[B] arithmetic on three mid-table inputs")
local probes = { "0x0000000000000000", "0x000000003B9ACA00", "0x00000000F42CBF10" }
for i = 1, #probes do
  local rr, ee, key, off, corr, val, nearest, vw, rw = call639(probes[i], 0, vout, rout, cout)
  local inp = tonumber(probes[i]:sub(3), 16)   -- < 2^32, exact in a double
  if not (vw and rw) or off == nil or corr == nil or val == nil then
    print(string.format("  input=%s rv=%d errno=%s NOT-WRITTEN vout=%s rout=%s",
      dec(inp), rr, ee, tostring(vw), tostring(rw)))
  else
    local exp = inp - off - corr
    print(string.format("  input=%s rv=%d key=%s off=%s corr=%s val=%s nearest=%s expects=%s delta=%s",
      dec(inp), rr, dec(key), dec(off), dec(corr), dec(val), dec(nearest), dec(exp), dec(val - exp)))
  end
end

-- [C] each destination may be zero (skipped), and the call still succeeds
print("[C] zero destinations are skipped")
local zshapes = {
  { "v=0", 0, rout, cout },
  { "r=0", vout, 0, cout },
  { "c=0", vout, rout, 0 },
  { "all-0", 0, 0, 0 },
}
for i = 1, #zshapes do
  local s = zshapes[i]
  fill()
  local ok, rv = pcall(function() return c639(uint64("0x0000000000000000"), uint64(0), uint64(s[2]), uint64(s[3]), uint64(s[4])) end)
  local r2 = ok and to_num(rv) or -9999
  print(string.format("  %-6s rv=%d errno=%s vout=%s rout=%s cout=%s", s[1], r2, (r2 == -1) and errno() or "-",
    wr_ok(vout) and "written" or "skipped",
    wr_ok(rout) and "written" or "skipped",
    wr_ok(cout) and "written" or "skipped"))
end

-- [D] a wild destination: EFAULT, and the earlier copies must already have landed
print("[D] wild destination 0x100 on the LAST slot only")
-- one call, so the buffers and the rv describe the same execution: the first call's
-- rv used to be discarded and the printed buffers came from a different call than
-- the printed rv. "written" is now an equality test against the refilled sentinel.
-- This is also the five-slot discriminator: under a four-slot uap the 16-byte record
-- would land in vout and the 4 correction bytes in rout, with rv 0 rather than EFAULT.
local r3, e3, _k3, _o3, _c3, _v3, _n3, w3v, w3r = call639("0x0000000000000000", 0, vout, rout, 0x100)
print(string.format("  rv=%d errno=%s value_written=%s record_written=%s vout=%X rout=%X",
  r3, e3, tostring(w3v), tostring(w3r), rd(vout) or 0, rd(rout) or 0))

-- [E] policy: the low dword of slot 1 - does any value change the path?
print("[E] policy sweep (slot +0x08 low dword)")
local pols = { 0, 1, 2, 3, "0x00000000FFFFFFFF" }
-- policy is (int)param_2[1] (sys_638.c:388): it gates the whole interior read when
-- negative, and on the iVar2==0 / iVar1==0 pair it can step the index from lo-1 to
-- lo-2, so a policy that changes the answer must change the printed key.
for i = 1, #pols do
  local r4, e4, key4, off4, corr4, val4, near4 = call639("0x0000000000000000", pols[i], vout, rout, cout)
  print(string.format("  policy=%s rv=%d errno=%s key=%s off=%s corr=%s val=%s nearest=%s",
    tostring(pols[i]), r4, e4, dec(key4), dec(off4), dec(corr4), dec(val4), dec(near4)))
end

-- [F] the lower edge around record 0; below-first is NOT here. It is the only
-- input that can reach table[-1] if 14.10 dropped the "(int)lo < 2" guard
-- (sys_639.asm:3419), so it runs last of all, in [F2], where a panic costs one row.
print("[F] lower edge (first key is -37242000 = 0xFFFFFFFFFDC7BB70)")
local edges = {
  { "first-key",   "0xFFFFFFFFFDC7BB70" },
  { "first+1",     "0xFFFFFFFFFDC7BB71" },
  { "zero",        "0x0000000000000000" },
  { "above-last",  "0x0000000100000000" },
}
for i = 1, #edges do
  local rr, ee, key6, off6 = call639(edges[i][2], 0, vout, rout, cout)
  print(string.format("  %-11s rv=%d errno=%s key=%s off=%s", edges[i][1], rr, ee, dec(key6), dec(off6)))
end

-- [G] the control. 638 takes the same input on buffers that were just refilled, so
-- its result cannot be a leftover of the 639 rows above - the old version read rout
-- without a fill(), which is the previous 639 call's record, and printed only its low
-- dword. 638 must put the 8-byte value at uap+0x08 and the 16-byte record at +0x10;
-- if vout came back holding a record instead of a scalar, the 638 uap would not be
-- the shape the corpus documents and neither row could be interpreted.
print("[G] slot-alignment control: 638 (four slots) on the same input, after a refill")
local c638 = make_syscall(638)
fill()
local ok5, rv5 = pcall(function() return c638(uint64("0x0000000000000000"), uint64(vout), uint64(rout), uint64(cout)) end)
local r5 = ok5 and to_num(rv5) or -9999
local vh5, vl5 = rd(vout + 4), rd(vout)
local kh5, kl5 = rd(rout + 4), rd(rout)
local w5v, w5r = wr_ok(vout), wr_ok(rout)
print(string.format("  638 rv=%d errno=%s vout=%s value=%s rout=%s key=%s off=%s",
  r5, (r5 == -1) and errno() or "-",
  w5v and "written" or "sentinel",
  w5v and dec(sgn(vh5, vl5)) or "-",
  w5r and "written" or "sentinel",
  w5r and dec(sgn(kh5, kl5)) or "-",
  w5r and dec(si32(rd(rout + 8))) or "-"))

-- [F2] the guard itself, last: input below the first key => lo = 1, and 639 reads
-- table[lo-2] only when lo >= 2 (sys_639.asm:3419 cmp $0x2,%ecx / setl, or policy
-- < 0 at :3417). With the guard the index is 0 and the load is table[0], inside
-- .data. Without it the index is -1 and the load is the plain movslq at
-- sys_639.asm:3430 / :3432, addressed as 0x0000000F8E2D5918 / ...1C because the
-- index is zero-extended (:3424 lea -0x2,%ecx, :3427 mov %r9,%r11, :3428 shl $4),
-- i.e. a user-range page with no onfault, so a kernel #PF there panics rather than
-- returning EFAULT. Everything before this row is already measured; a capture that
-- stops here answers "guard absent on 14.10".
print("[F2] below-first: the only call that can reach table[-1]")
local zr, ze, zkey, zoff, zcor, zval, znear = call639("0xFFFFFFFFFF000000", 0, vout, rout, cout)
print(string.format("  below-first rv=%d errno=%s key=%s off=%s corr=%s val=%s nearest=%s",
  zr, ze, dec(zkey), dec(zoff), dec(zcor), dec(zval), dec(znear)))

local okz, pidz = pcall(function() return make_syscall(20)() end)
print(string.format("[Z] alive pid=%d", okz and to_num(pidz) or -1))
print("=== DONE ===")
