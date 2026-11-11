-- CRASH_CLASS: MODERATE  (reads one page at a time; a read past a mapping kills the process but localises itself)
-- PROBE 1183a: page-at-a-time AVX gadget scan for libkernel and eboot.
-- 1182a tried 0x40000 at a time and died inside the first chunk of libkernel_base = 0x81A8AC000 with no
-- chunk line, so the window (or the mapping) ends inside it. Here every 0x1000 page prints its own line,
-- so a fault names the exact page and the next run resumes at PAGE_START+1.
-- Gadgets wanted (docs/MICROARCH_FEASIBILITY_14_10.md H1): a userland store from ymm0 - vmovdqu [rdi],ymm0
--  (c5 fe 7f 07), vmovupd (c5 fd 11 07), vmovups (c5 fc 11 07) - plus vzeroupper (c5 f8 77) as a proxy for
-- AVX code density. libc (0x120000, 1173a) has none of the stores.
print("=== PROBE 1183a: PAGE SCAN FOR AVX STORES ===")
local REGION = "libkernel" -- REGION_SELECT
local PAGE_START = 1 -- PAGE_START_SELECT
local PAGES = 0x100  -- pages of 0x1000 to walk from PAGE_START
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local base = 0
if REGION == "libkernel" then base = N(libkernel_base) elseif REGION == "eboot" then base = N(eboot_base) else base = N(libc_base) end
print(string.format("[R] region=%s base=%s pages=%X from %X", REGION, hexn(base), PAGES, PAGE_START))
local PATS = {
  { name="vmovupd", val=0x0711FDC5 },
  { name="vmovups", val=0x0711FCC5 },
  { name="vmovdqu", val=0x077FFEC5 },
  { name="vzeroup", val=0x77F8C5, mask=0xFFFFFF },
}
local totals = { 0, 0, 0, 0 }
for pg=PAGE_START,PAGE_START+PAGES-1 do
  local off = pg * 0x1000
  local hits = {}
  for pi=1,#PATS do hits[pi] = {} end
  local bad = 0
  for o=0,0xFFC,4 do
    local dw = RD(base+off+o)
    if dw < 0 then bad = bad + 1 else
      for pi=1,#PATS do
        local p = PATS[pi]
        local mask = p.mask or 0xFFFFFFFF
        if (dw % (mask+1)) == p.val then
          totals[pi] = totals[pi] + 1
          if #hits[pi] < 3 then hits[pi][#hits[pi]+1] = o end
        end
      end
    end
  end
  local s = ""
  for pi=1,#PATS do
    if #hits[pi] > 0 then
      s = s .. string.format(" %s(%d)@", PATS[pi].name, #hits[pi])
      for k=1,#hits[pi] do s = s .. string.format("%X ", off + hits[pi][k]) end
    end
  end
  if bad > 0 then
    print(string.format("[P %X] UNREADABLE=%d (page is not mapped)", pg, bad))
  else
    print(string.format("[P %X] ok%s", pg, s))
  end
end
print(string.format("[SUM] %s totals: vmovupd=%d vmovups=%d vmovdqu=%d vzeroupper=%d", REGION, totals[1], totals[2], totals[3], totals[4]))
print("[Z] alive")
print("=== DONE ===")
