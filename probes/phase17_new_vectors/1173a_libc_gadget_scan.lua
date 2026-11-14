-- CRASH_CLASS: SAFE  (reads only inside libc's mapped text; no syscall that can block)
-- PROBE 1173a: what userland gadgets does this libc actually contain?
-- Two capabilities are blocked on gadget availability, both discovered by the microarch review:
--   * a bare `syscall; ret` would let thr_create(430) run a raw syscall on a throwaway thread, so a
--     command that parks inside the kernel (601 0x08, 0x0C) no longer wedges the loader;
--   * a VEX `vmovdqu [rdi], ymm0` store would let us read the kernel's YMM residue after a syscall
--     (docs/MICROARCH_FEASIBILITY_14_10.md H1), which is the only candidate that needs no gate at all.
-- This probe only reads bytes: libc_base is set by the loader (main.lua:13) and the scan stays inside
-- the first 0x180000 bytes, which is mapped text (libc_addrofs offsets reach 0x11c010).
print("=== PROBE 1173a: LIBC GADGET SCAN ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local base = N(libc_base)
print(string.format("[A] libc_base=%s", hexn(base)))
if base == 0 then print("[A] libc_base is not resolvable in this loader - stop"); print("=== 1173a DONE ==="); return end
local function rd4(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local SCAN = 0x120000 -- measured limit: the 1173a crash report's context holds 0x15b17c000 = libc_base+0x120000, so the window ends there
local pats = {
  { name="syscall;ret        (0f 05 c3)", mask=0xFFFFFF, val=0xC3050F },
  { name="syscall;jb         (0f 05 72)", mask=0xFFFFFF, val=0x72050F },
  { name="syscall           (0f 05)",     mask=0xFFFF,   val=0x050F },
  { name="vzeroupper        (c5 f8 77)",  mask=0xFFFFFF, val=0x77F8C5 },
  { name="vmovupd [rdi],ymm0 (c5 fd 11 07)", mask=0xFFFFFFFF, val=0x0711FDC5 },
  { name="vmovups [rdi],ymm0 (c5 fc 11 07)", mask=0xFFFFFFFF, val=0x0711FCC5 },
  { name="vmovdqu [rdi],ymm0 (c5 fe 7f 07)", mask=0xFFFFFFFF, val=0x077FFEC5 },
}
local hits = {}
for i=1,#pats do hits[i] = { n=0, first={} } end
local bad = 0
for off=0,SCAN-1,4 do
  if off % 0x30000 == 0 then print(string.format("[P] %X/%X", off, SCAN)) end -- keeps the socket busy; send_probe kills a silent probe
  local dw = rd4(base+off)
  if dw < 0 then bad = bad + 1 else
    for i=1,#pats do
      local p = pats[i]
      if (dw % (p.mask+1)) == p.val then
        local h = hits[i]
        h.n = h.n + 1
        if #h.first < 6 then h.first[#h.first+1] = off end
      end
    end
  end
end
for i=1,#pats do
  local h = hits[i]
  local s = ""
  for k=1,#h.first do s = s .. string.format("%X ", h.first[k]) end
  print(string.format("[%s] count=%d first=[%s]", pats[i].name, h.n, s))
end
print(string.format("[Z] scanned=%X unreadable_dwords=%d (0 means the whole window is mapped)", SCAN, bad))
print("=== 1173a DONE ===")
