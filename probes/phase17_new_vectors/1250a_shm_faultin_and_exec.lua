-- CRASH_CLASS: LOW  (no faulting dereference; every memory.read_byte is pcall-guarded
-- and only touches VAs the kernel returned from mmap)
-- PROBE 1250a: shared memory (629) revisited.
--
-- Two corrections drive this probe:
--
-- 1. 629 is NOT "physhm".  Decoding the create path at 0x91bca0 shows name lookup
--    ("cmp r13,1 ; je anon", then a global list walk with strncmp at 0x91bd86),
--    per-process accounting from [proc+0x5c0] and [proc+0x5d0], a flags check
--    ("test r15b,1 ; jne error", "test r15d,0xffdff1fc ; jne error" = only
--    0x0002xxxx | 0x203 are legal), and an 0x200000 size class split.  This is
--    POSIX shm_open, an ordinary page-backed object.
--
-- 2. Probe 1240a concluded "the mapping is not present" from
--    write(socket, va, 0x20) == -1 EFAULT.  That inference is invalid: FreeBSD
--    copyin runs under a fault handler that turns a not-PRESENT user page into a
--    fixup return, it does not fault the page in.  A freshly mmap'ed page is
--    demand-zero, so EFAULT is the expected result even for a perfectly good
--    mapping.  This probe touches the page from userland first, then repeats the
--    kernel-side read.
--
-- Third question: does 477 accept PROT_EXEC on a shm object (an executable user
-- page would let us run native code instead of Lua).
--
-- REV 2 (this run) - Lua 5.1 / loader ABI fixes:
--   * rev 1 passed a Lua table ({0,0}) as socketpair's fd-out pointer and also
--     called mk(135) with no arguments twice; a table is not a pointer, so the
--     call either raised inside the pcall-less body or wrote nothing we could
--     read.  The fds now come from a memory.alloc(8) buffer read back with
--     memory.read_dword.
--   * recvfrom(29) is now called with all six arguments (fd, buf, len, flags,
--     from, fromlenp).  MSG_DONTWAIT is 0x80; 0x40 is MSG_WAITALL and wedges.
--   * NEW [C2]: syscall 674 (VM map) is used as a NON-FATAL protection oracle.
--     It reports the protection the kernel recorded for a region, so we can ask
--     "did PROT_EXEC survive mmap()" without executing anything.  The anon prot=7
--     page is carried as the control: 1245a proved it faults on instruction
--     fetch, so whatever 674 says about it calibrates the field.
print("=== PROBE 1250a: shm (629) fault-in correction, exec mapping, offsets ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return nil end
local function wr(a,v) local ok = pcall(function() memory.write_byte(a,v) end) return ok end
local function mmap(addr,len,prot,flags,fd,off) return N(mk(477)(addr,len,prot,flags,fd,off)) end
local function okva(a) return a ~= nil and a > 0 and a < 0x800000000000 end
local function has_bit(v, b) return v ~= nil and (v % (b*2)) >= b end

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
  if snap == nil then return nil end
  for _, r in ipairs(snap) do
    if r.s <= addr and addr < r.e then return r end
  end
  return nil
end
local function prot_report(snap, tag, addr)
  if not okva(addr) then print(string.format("    %-14s va=0x%X  (no mapping)", tag, addr)) return end
  local r = vm_lookup(snap, addr)
  if r == nil then
    print(string.format("    %-14s va=0x%X  NOT FOUND in 674 map", tag, addr))
  else
    print(string.format("    %-14s va=0x%X  rec=[0x%X,0x%X) prot=%X  exec=%s  r=%s w=%s x=%s",
          tag, addr, r.s, r.e, r.p, tostring(has_bit(r.p,4)),
          tostring(has_bit(r.p,1)), tostring(has_bit(r.p,2)), tostring(has_bit(r.p,4))))
  end
end

print(string.format("[0] pid=%d", N(mk(20)())))
local shm = mk(629)

print("[A] 629 anon form, flags sweep (bit0 must be set, bits outside 0x200203 rejected)")
local fds = {}
for _,fl in ipairs({0,1,2,3,0x200,0x201,0x20000,0x200000,0x400000}) do
  local rv = N(shm(1, 0x4000, fl, 0))
  print(string.format("    flags=%06X -> rv=%d errno=\"%s\"", fl, rv, ES()))
  if rv >= 0 and rv < 0x10000 then fds[#fds+1] = {fl, rv} end
end
local fd = fds[1] and fds[1][2] or -1
print(string.format("[A] first usable fd = %d (flags %s)", fd, fds[1] and string.format("%X", fds[1][1]) or "-"))

if fd >= 0 then
  -- ---------------------------------------------------------------- B
  print("[B] mmap the shm object read/write")
  local va = mmap(0, 0x4000, 3, 1, fd, 0)
  print(string.format("    477(0,0x4000,3,MAP_SHARED,%d,0) -> va=0x%X errno=\"%s\"", fd, va, ES()))
  if okva(va) then
    -- B1: FIRST byte BEFORE any touch, guarded.
    local first = rd(va)
    print(string.format("    [B1] read_byte(va) before any touch -> %s", first and string.format("%02X", first) or "FAULT"))
    -- B2: user-touch the page (write 8 bytes then read them back)
    for i = 0, 7 do wr(va + i, 0x40 + i) end
    local s = ""
    for i = 0, 7 do local v = rd(va + i); s = s .. (v and string.format("%02X", v) or "??") end
    print("    [B2] after user write, user read -> " .. s)

    -- B3: kernel-side copyin of the same page, before and after a longer touch.
    -- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, &sv)
    local fp = memory.alloc(8)
    memory.write_dword(fp, 0)
    memory.write_dword(fp + 4, 0)
    local rv = N(mk(135)(1, 1, 0, uint64(fp)))
    local s1, s2 = N(memory.read_dword(fp)), N(memory.read_dword(fp + 4))
    print(string.format("    [B3] socketpair -> rv=%d s1=%d s2=%d errno=\"%s\"", rv, s1, s2, ES()))
    if rv == 0 and s1 > 2 and s2 > 2 and s1 < 0x10000 and s2 < 0x10000 then
      local buf = mmap(0, 0x1000, 3, 0x1002, -1, 0)
      local function kernel_read(tag)
        local n1 = N(mk(4)(s1, va, 8))
        local e1 = ES()
        local got, n2 = "", 0
        if okva(buf) then
          n2 = N(mk(29)(s2, buf, 64, 0x80, 0, 0))
          if n2 > 0 then
            for i = 0, n2 - 1 do got = got .. string.format("%02X", rd(buf + i) or 0) end
          end
        end
        print(string.format("    %s write(sock,va,8)=%d errno=\"%s\" recv=%d data=%s", tag, n1, e1, n2, got))
      end
      kernel_read("[B3a] cold page ")
      -- touch a whole page, retry: a demand-zero page that was never touched is the
      -- 1240a EFAULT case.  If this one succeeds, 1240a's inference was the artifact.
      for i = 0, 0x3FF do wr(va + i, 0xA5) end
      kernel_read("[B3b] touched   ")
      mk(6)(s1); mk(6)(s2)
    end
  end

  -- ---------------------------------------------------------------- C
  print("[C] executable mapping of the shm object")
  local ctrl = mmap(0, 0x4000, 7, 0x1002, -1, 0)   -- control: 1245a proved this cannot exec
  local cands = {}
  for _,p in ipairs({4, 5, 6, 7}) do
    local va2 = mmap(0, 0x4000, p, 1, fd, 0)
    print(string.format("    477(prot=%X) -> va=0x%X errno=\"%s\"", p, va2, ES()))
    if okva(va2) then cands[#cands+1] = {p, va2} end
  end
  print("[C2] 674 recorded protection (non-fatal exec oracle; control = anon prot=7)")
  local snap = vm_snapshot()
  if snap == nil then
    print("    674 unavailable (call failed or count out of range)")
  else
    print(string.format("    674 returned %d regions", #snap))
    prot_report(snap, "anon prot7", ctrl)
    for _,c in ipairs(cands) do
      prot_report(snap, string.format("shm prot%X", c[1]), c[2])
    end
  end

  -- ---------------------------------------------------------------- D
  print("[D] page offsets into the shm object")
  for _,off in ipairs({0x1000, 0x2000, 0x40000000, 0x7FFFFFFFF000}) do
    local rv2 = mmap(0, 0x1000, 3, 1, fd, off)
    print(string.format("    477(off=%X) -> rv=0x%X errno=\"%s\"", off, rv2, ES()))
  end
end

print("[E] 629 named form: which name shape is accepted")
local nbuf = mmap(0, 0x1000, 3, 0x1002, -1, 0)
if okva(nbuf) then
  for _,n in ipairs({"shm", "/shm", "/", "/a", "/shm/test", "/SceShm"}) do
    for k = 1, #n do wr(nbuf + k - 1, string.byte(n, k)) end
    wr(nbuf + #n, 0)
    local rv = N(shm(nbuf, 0x4000, 1, 0))
    print(string.format("    name=%-12s -> rv=%d errno=\"%s\"", "\""..n.."\"", rv, ES()))
  end
end
print("=== DONE 1250a ===")
