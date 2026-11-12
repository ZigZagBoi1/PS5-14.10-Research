-- CRASH_CLASS: LOW (mmap/fstat/674 on a descriptor we just created; no execution, no 628)
-- PROBE 1250c: the shm object behind 629, now that the call shape is known.
--
-- Probe 1250b established the shape empirically:
--   629(1, 2, 0) -> 22     (22 was a free descriptor in that process)
--   629(1, fl, 0) -> -1 EINVAL for fl in {0,1,3,0x200,0x201,0x203,0x20000,0x200000}
-- so arg1 == 1 is the anon sentinel, arg2 is oflag, arg3 is mode, and oflag=2
-- (O_RDWR) is the only accepted value.  oflag=1 dies on the decoded "test r15b,1"
-- (O_WRONLY rejected) and 0x200/0x20000/0x200000 die on "test r15d,0xffdff1fc".
-- 1250a's nine uniform EINVALs were all caused by sending the size 0x4000 as oflag.
--
-- This probe answers, without executing anything:
--   [A] does 629(1,2,0) really return a descriptor, and is it stable
--   [B] what does fstat say about the object (size tells us what we can map)
--   [C] can the object be mmap'ed MAP_SHARED, and is it readable/writable
--   [D] 674's recorded protection for prot=1..7 on this object, with the anon prot=7
--       page as the control that 1245a proved cannot execute
-- The execution test is deliberately NOT here; 1248a owns the fatal step.
print("=== PROBE 1250c: 629 shm object inventory ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h, v.l end return 0, N(v) end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function qs(v) if v == nil then return "????????????????" end local h,l = hilo(v) return string.format("%08X_%08X", h, l) end
local function rd32(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return nil end
local function rd(a) local ok,v = pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return nil end
local function wr(a,v) local ok = pcall(function() memory.write_byte(a,v) end) return ok end
local function mmap(addr,len,prot,flags,fd,off) return N(mk(477)(addr,len,prot,flags,fd,off)) end
local function okva(a) return a ~= nil and a > 0 and a < 0x800000000000 end
local function has_bit(v, b) return v ~= nil and (v % (b*2)) >= b end
local function peek(addr, n)
  local s = ""
  for i=0,n-1 do local v = rd(addr+i); s = s .. (v and string.format("%02X", v) or "??") end
  return s
end

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
  if not okva(addr) then print(string.format("    %-18s va=0x%X  (no mapping)", tag, addr)) return nil end
  local r = vm_lookup(snap, addr)
  if r == nil then
    print(string.format("    %-18s va=0x%X  NOT FOUND in 674 map", tag, addr))
    return nil
  end
  print(string.format("    %-18s va=0x%X rec=[0x%X,0x%X) prot=%X  r=%s w=%s x=%s",
        tag, addr, r.s, r.e, r.p,
        tostring(has_bit(r.p,1)), tostring(has_bit(r.p,2)), tostring(has_bit(r.p,4))))
  return r
end

print(string.format("[0] pid=%d", N(mk(20)())))

print("[A] 629(1, O_RDWR=2, 0) three times - is the return value a descriptor?")
local fds = {}
for i = 1, 3 do
  local rv = N(mk(629)(1, 2, 0))
  print(string.format("    call %d -> rv=%d errno=\"%s\"", i, rv, ES()))
  if rv >= 0 and rv < 0x10000 then fds[#fds+1] = rv end
end
local fd = fds[1] or -1
print(string.format("[A] fd candidates: %s", #fds > 0 and table.concat(fds, ",") or "none"))

if fd >= 0 then
  print("[B] fstat the object")
  local SB = mmap(0, 0x1000, 3, 0x1002, -1, 0)
  if okva(SB) then
    for i=0,0x1ff do wr(SB+i, 0) end
    local rv = N(mk(189)(fd, uint64(SB)))
    print(string.format("    fstat(%d) -> rv=%d errno=\"%s\"", fd, rv, ES()))
    if rv == 0 then
      for r = 0, 0x90, 0x10 do
        print(string.format("      +%02X %s %s", r, qs(rq(SB+r)), qs(rq(SB+r+8))))
      end
      local d18 = rd32(SB+0x18)
      print(string.format("      candidates: mode=%o size(qword@0x70)=%s",
            d18 and (d18 % 65536) or -1, qs(rq(SB+0x70))))
    end
  end

  print("[C] MAP_SHARED mapping of the object")
  local m_rw = mmap(0, 0x4000, 3, 1, fd, 0)
  print(string.format("    477(0,0x4000,3,MAP_SHARED,%d,0) -> 0x%X errno=\"%s\"", fd, m_rw, ES()))
  if okva(m_rw) then
    print(string.format("      head before touch: %s", peek(m_rw, 16)))
    for i = 0, 7 do wr(m_rw + i, 0x40 + i) end
    print(string.format("      head after  user write: %s", peek(m_rw, 16)))
    local m_r2 = mmap(0, 0x4000, 3, 1, fd, 0)
    if okva(m_r2) then
      print(string.format("      second mapping sees: %s  %s",
            peek(m_r2, 16),
            (string.sub(peek(m_r2, 16),1,4) == "4041") and "*** SHARED: writes are visible across mappings ***" or ""))
    else
      print(string.format("      second mapping failed (0x%X)", m_r2))
    end
  end

  print("[D] 674 recorded protection, prot=1..7 on the shm object")
  local ctrl = mmap(0, 0x4000, 7, 0x1002, -1, 0)
  local cands = {}
  for _,p in ipairs({1, 2, 3, 4, 5, 6, 7}) do
    local va = mmap(0, 0x4000, p, 1, fd, 0)
    print(string.format("    477(prot=%X) -> 0x%X errno=\"%s\"", p, va, ES()))
    if okva(va) then cands[#cands+1] = {p, va} end
  end
  local snap = vm_snapshot()
  if snap == nil then
    print("    674 unavailable")
  else
    print(string.format("    674 returned %d regions", #snap))
    prot_report(snap, "anon prot7 ctrl", ctrl)
    for _,c in ipairs(cands) do
      prot_report(snap, string.format("shm prot%X", c[1]), c[2])
    end
  end

  print("[E] size / offset probes")
  for _,len in ipairs({0x1000, 0x4000, 0x200000, 0x2000000}) do
    local va = mmap(0, len, 3, 1, fd, 0)
    print(string.format("    477(len=0x%X) -> 0x%X errno=\"%s\"", len, va, ES()))
  end
  for _,off in ipairs({0x1000, 0x4000, 0x40000000}) do
    local va = mmap(0, 0x1000, 3, 1, fd, off)
    print(string.format("    477(off=0x%X) -> 0x%X errno=\"%s\"", off, va, ES()))
  end
end
print("=== DONE 1250c ===")
