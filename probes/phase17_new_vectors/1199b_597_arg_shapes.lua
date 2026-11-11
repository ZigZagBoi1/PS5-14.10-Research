-- CRASH_CLASS: HIGH (597 kills on six zeros, measured twice: presence sweep and 1199a shape 1)
-- PROBE 1199b: the 597 argument shape hunt. 1199a died on shape 1 (six zeros) before any
-- non-zero shape ran, so the question "does 597 ignore its arguments or dereference arg1?"
-- is still open. This probe runs the SURVIVABLE shapes first and the known-lethal zeros last,
-- so every relaunch buys one more data point instead of one less.
-- S1: arg1 = mapped 0x100 buffer, byte0 = 0x13 (module id), rest zero; args 2..6 zero.
-- S2: arg1 = mapped 0x1a8 record whose first qword is 0x1a8 (the 608/660 size convention),
--     arg2 = 0x40 (the bit 597 is supposed to OR in).
-- S3: six zeros (expected kill) - last, confirms the death is reproducible in this build.
-- Each surviving shape is followed immediately by the 608 level-2 oracle (id 0x13 and 0x00).
print("=== PROBE 1199b: 597 argument shapes, least lethal first ===")
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
local s608 = mk(608)
local s596 = mk(596)
local s597 = mk(597)
local function probe608(id, label)
  sent(B2, 0x3FC)
  wq(B2, 0x1a8)
  local ok, rv = pcall(function() return s608(U(id), U(0), U(B2), U(0), U(0)) end)
  local r = ok and N(rv) or -999
  if r ~= 0 then print(string.format("[608] %s id=%02X rv=%d errno=%s", label, id, r, es())) return nil end
  print(string.format("[608] %s id=%02X +110=%s +128=%s +130=%s +148=%s +150=%s +158=%s",
    label, id, qw(B2,0x110), qw(B2,0x128), qw(B2,0x130), qw(B2,0x148), qw(B2,0x150), qw(B2,0x158)))
  return table.concat({qw(B2,0x110), qw(B2,0x128), qw(B2,0x130), qw(B2,0x148), qw(B2,0x150), qw(B2,0x158)}, "|")
end
-- ---------- P0: neighbour control + oracle ----------
local ok596, rv596 = pcall(function() return s596(U(0), U(0), U(0), U(0), U(0)) end)
print(string.format("[596] control rv=%d errno=%s (known present, returns 0)", ok596 and N(rv596) or -999, es()))
local base13 = probe608(0x13, "P0")
local base00 = probe608(0x00, "P0")
-- ---------- S1: mapped buffer, module id in byte 0 ----------
sent(B, 0x3FC)
wd(B, 0x13)
print("[597] --- S1 arg1=mapped{B}=0x13, args2..6=0 ---")
local ok, rv = pcall(function() return s597(U(B), U(0), U(0), U(0), U(0)) end)
print(string.format("[597] S1 rv=%d (0x%X) errno=%s", ok and N(rv) or -999, ok and N(rv) or -1, es()))
local a13 = probe608(0x13, "S1")
local a00 = probe608(0x00, "S1")
if base13 and a13 then print("[ORACLE] S1 id13 "..((a13==base13) and "UNCHANGED" or "CHANGED")) end
if base00 and a00 then print("[ORACLE] S1 id00 "..((a00==base00) and "UNCHANGED" or "CHANGED")) end
-- ---------- S2: 0x1a8 record convention, arg2 = 0x40 ----------
sent(B, 0x3FC)
wq(B, 0x1a8)
wd(B+8, 0x13)
print("[597] --- S2 arg1=mapped{B}= {0x1a8, id 0x13}, arg2=0x40 ---")
local ok2, rv2 = pcall(function() return s597(U(B), U(0x40), U(0), U(0), U(0)) end)
print(string.format("[597] S2 rv=%d (0x%X) errno=%s", ok2 and N(rv2) or -999, ok2 and N(rv2) or -1, es()))
local b13 = probe608(0x13, "S2")
if base13 and b13 then print("[ORACLE] S2 id13 "..((b13==base13) and "UNCHANGED" or "CHANGED")) end
-- ---------- S3: known-lethal zeros, last ----------
print("[597] --- S3 six zeros about to run (expected kill) ---")
local ok3, rv3 = pcall(function() return s597(U(0), U(0), U(0), U(0), U(0)) end)
print(string.format("[597] S3 rv=%d (0x%X) errno=%s -- 597 survives zeros on this build", ok3 and N(rv3) or -999, ok3 and N(rv3) or -1, es()))
local c13 = probe608(0x13, "S3")
if base13 and c13 then print("[ORACLE] S3 id13 "..((c13==base13) and "UNCHANGED" or "CHANGED")) end
print("[Z] alive")
print("=== DONE ===")
