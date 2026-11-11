-- CRASH_CLASS: SAFE (reads the VM map only; nothing is executed, no 629 mapping is created)
-- PROBE 1251a: calibrate syscall 674 as a PROT_EXEC oracle
--
-- Context: 1245a proved that an anonymous mmap with prot=7 returns a page that
-- cannot be executed (fcall faults with CS=0x43, RIP=page).  1248a wants 674 (VM
-- map query) as a NON-FATAL oracle for "did the kernel keep PROT_EXEC on this
-- mapping?" so the one fatal fcall is only spent when the oracle agrees.
-- 674 has never been calibrated on 14.10.
--
-- Two hard lessons are baked into this version, both from the 17:01 and 17:03 runs:
--   * memory.read_dword/read_byte return uint64 tables here, not numbers - every
--     read goes through N() or the probe dies on "attempt to compare table with number".
--   * 674 is called EXACTLY ONCE, with the one shape that is known to work
--     (probes/phase14_final_push/55f_674_deep_dump.lua:63-73: STRIDE=72, MAX=512,
--     arg5=0x40000000) into a buffer with 0x100 bytes of slack, because 55f allocates
--     STRIDE*MAX+0x100 and a tight buffer is not worth the risk.  Alternative
--     argument shapes are NOT probed blind here: the 17:03 run tried them and the
--     game went down with the loader.
--
-- Layout under test: 72-byte records, start +0x00, end +0x08, prot +0x18, name inline
-- from +0x20.  Every mapping is created BEFORE the snapshot, because a snapshot taken
-- earlier cannot describe a mapping that did not exist yet.

print("=== PROBE 1251a: 674 EXEC-ORACLE CALIBRATION ===")
print("")

local function N(v)
  if type(v) == "table" and v.tonumber then return v:tonumber() end
  return tonumber(v) or 0
end
local function mk(n)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = n
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function hex(v) return string.format("0x%X", v) end
local function u64(h, l) return h * 4294967296 + l end
local function bit(v, n)
  local d = 1
  for _ = 1, n do d = d * 2 end
  return math.floor(v / d) - math.floor(v / (d * 2)) * 2
end
local function bitname(p)
  local s = ""
  if bit(p, 0) == 1 then s = s .. "r" else s = s .. "-" end
  if bit(p, 1) == 1 then s = s .. "w" else s = s .. "-" end
  if bit(p, 2) == 1 then s = s .. "x" else s = s .. "-" end
  return s
end

local sc674 = mk(674)
local sc477 = mk(477)
local sc5   = mk(5)
local sc189 = mk(189)

local function mmap(addr, len, prot, flags, fd, off)
  local ok, rv = pcall(function()
    return sc477(uint64(addr), uint64(len), uint64(prot), uint64(flags), uint64(fd), uint64(off))
  end)
  if not ok then return nil, "pcall" end
  local v = N(rv)
  if v <= 0 or v > 0x7FFFFFFFFFFF then return nil, hex(v) end
  return v
end

-- [1] every mapping first
print("[1] creating the mappings under test")
local anon3 = mmap(0, 0x4000, 3, 0x1002, -1, 0)
print(string.format("    anon prot=3  -> %s", anon3 and hex(anon3) or "FAILED"))

local anon7 = mmap(0, 0x4000, 7, 0x1002, -1, 0)
print(string.format("    anon prot=7  -> %s", anon7 and hex(anon7) or "FAILED"))
if anon7 then
  memory.write_byte(anon7, 0x90)
  print(string.format("    anon prot=7  writable, read back %02X", N(memory.read_byte(anon7))))
end

local fd, fsize = -1, 0
do
  local ok, rv = pcall(function() return sc5("/app0/eboot.bin", 0, 0) end)
  if ok then fd = N(rv) end
  print(string.format("    open(/app0/eboot.bin) -> %d", fd))
  if fd >= 0 then
    local st = memory.alloc(0x100)
    for i = 0, 0x3F do memory.write_dword(st + i * 4, 0) end
    local ok2, rv2 = pcall(function() return sc189(fd, st) end)
    if ok2 and N(rv2) == 0 then
      fsize = u64(N(memory.read_dword(N(st) + 0x5C)), N(memory.read_dword(N(st) + 0x58)))
      print(string.format("    fstat -> size=%s", hex(fsize)))
    else
      print(string.format("    fstat failed rv=%s", tostring(rv2)))
    end
  end
end

local file_map = {}
if fd >= 0 then
  local len = 0x4000
  if fsize > 0 and fsize < len then len = fsize end
  local prots = {1, 5, 7}
  for i = 1, 3 do
    local prot = prots[i]
    local a, err = mmap(0, len, prot, 2, fd, 0)
    if a then
      file_map[prot] = a
      print(string.format("    file prot=%d  -> %s  first dword %08X", prot, hex(a), N(memory.read_dword(a))))
    else
      print(string.format("    file prot=%d  -> FAILED %s", prot, err))
    end
  end
end
print("    step 1 ok")

-- [2] the single snapshot
print("")
print("[2] one 674 call, 55f shape (STRIDE=72 MAX=512 arg5=0x40000000), buffer +0x100 slack")
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local cnt = memory.alloc(16)
memory.write_dword(cnt, 0)
memory.write_dword(cnt + 4, 0)
local ok, rv = pcall(function()
  return sc674(uint64(N(buf)), uint64(STRIDE), uint64(MAX), uint64(N(cnt)), uint64(0x40000000))
end)
local ret = ok and N(rv) or -1
local n = ok and N(memory.read_dword(cnt)) or 0
print(string.format("    674 -> rv=%d errno=%s count=%d", ret, tostring(get_error_string()), n))
if not ok then
  print("    pcall failed: " .. tostring(rv))
  print("=== DONE 1251a ===")
  return
end
if n < 0 then n = 0 end
if n > MAX then n = MAX end
if n == MAX then
  print("    WARNING: count hit MAX - the map may be truncated, raise MAX before trusting misses")
end

local snap = {}
for i = 0, n - 1 do
  local b = N(buf) + i * STRIDE
  snap[#snap + 1] = {
    s = u64(N(memory.read_dword(b + 4)), N(memory.read_dword(b))),
    e = u64(N(memory.read_dword(b + 12)), N(memory.read_dword(b + 8))),
    p = N(memory.read_dword(b + 0x18)),
    base = b,
  }
end
print(string.format("    parsed %d records", #snap))
print("    step 2 ok")

local function name_of(rec)
  local s = ""
  for off = 0x20, 0x46 do
    local c = N(memory.read_byte(rec.base + off))
    if c >= 32 and c < 127 then s = s .. string.char(c) else s = s .. "." end
  end
  return s
end

print("")
print("[3] the first three records, to show the real layout")
for i = 1, 3 do
  if snap[i] then
    print(string.format("    [%d] %s - %s  prot=%s %s  name=%s",
          i, hex(snap[i].s), hex(snap[i].e), hex(snap[i].p), bitname(snap[i].p), name_of(snap[i])))
  end
end
print("    step 3 ok")

local function find_rec(addr)
  for i = 1, #snap do
    local r = snap[i]
    if addr >= r.s and addr < r.e then return r end
  end
  return nil
end
local function report(label, addr)
  local r = find_rec(addr)
  if r == nil then
    print(string.format("    %-11s %s  (no 674 record covers it)", label, hex(addr)))
    return nil
  end
  print(string.format("    %-11s %s  %s - %s  prot=%s %s  name=%s",
        label, hex(addr), hex(r.s), hex(r.e), hex(r.p), bitname(r.p), name_of(r)))
  return r
end

print("")
print("[4] the calibration set")
local rec_anon3 = anon3 and report("anon prot3", anon3) or nil
local rec_anon7 = anon7 and report("anon prot7", anon7) or nil
local rec_f1 = file_map[1] and report("file prot1", file_map[1]) or nil
local rec_f5 = file_map[5] and report("file prot5", file_map[5]) or nil
local rec_f7 = file_map[7] and report("file prot7", file_map[7]) or nil

local eboot_text = nil
do
  local ok3, v3 = pcall(function() return N(eboot_base) end)
  if ok3 and v3 and v3 > 0x1000 then eboot_text = v3 end
  if eboot_text == nil then
    for i = 1, #snap do
      if name_of(snap[i]):find("eboot") then eboot_text = snap[i].s end
    end
  end
  print(string.format("    eboot text candidate = %s", eboot_text and hex(eboot_text) or "unknown"))
end
local rec_etext = eboot_text and report("eboot text", eboot_text) or nil
print("    step 4 ok")

print("")
print("[5] full 72-byte dump of one record (self-describing layout)")
local dump_rec = rec_f7 or rec_anon7 or rec_etext or snap[1]
if dump_rec then
  print(string.format("    record for %s:", hex(dump_rec.s)))
  for off = 0, 0x40, 8 do
    print(string.format("      +%02X  %08X_%08X", off,
          N(memory.read_dword(dump_rec.base + off + 4)),
          N(memory.read_dword(dump_rec.base + off))))
  end
  print(string.format("      name bytes +0x20.. = %s", name_of(dump_rec)))
end
print("    step 5 ok")

print("")
print("[6] VERDICT")
local function x(p) return p ~= nil and bit(p, 2) == 1 end
print(string.format("    anon prot7  prot=%s exec=%s   (ground truth: NOT executable, 1245a)",
      rec_anon7 and hex(rec_anon7.p) or "n/a", tostring(x(rec_anon7 and rec_anon7.p))))
print(string.format("    anon prot3  prot=%s exec=%s   (ground truth: NOT executable)",
      rec_anon3 and hex(rec_anon3.p) or "n/a", tostring(x(rec_anon3 and rec_anon3.p))))
print(string.format("    file prot7  prot=%s exec=%s   (unknown - this is the question)",
      rec_f7 and hex(rec_f7.p) or "n/a", tostring(x(rec_f7 and rec_f7.p))))
print(string.format("    eboot text  prot=%s exec=%s   (ground truth: EXECUTABLE)",
      rec_etext and hex(rec_etext.p) or "n/a", tostring(x(rec_etext and rec_etext.p))))

if rec_etext == nil then
  print("    oracle INCONCLUSIVE: no known-executable control found in the map")
elseif x(rec_etext.p) and not x(rec_anon7 and rec_anon7.p) then
  print("    oracle USABLE: separates a known-executable region from the known-dead anon prot7 page")
  print("    -> 1248a's gate is meaningful; if file prot7 reports exec, run 1251b")
elseif x(rec_anon7 and rec_anon7.p) then
  print("    oracle USELESS for exec: it reports PROT_EXEC on a page 1245a proved cannot execute")
  print("    -> recorded protection is the REQUESTED protection, not the effective one")
  print("    -> skip 1248a; go straight to 1251b")
else
  print("    no exec reported anywhere - check whether eboot text was really located")
end

print("")
print("=== DONE 1251a ===")
