-- CRASH_CLASS: MODERATE  (reads the start of libkernel and the game eboot; a read past a mapping kills the process, not the kernel)
-- PROBE 1182a: is there a VEX ymm0 store anywhere in userland?
-- docs/MICROARCH_FEASIBILITY_14_10.md H1: the kernel's AVX code leaves kernel data in the YMM registers
-- across a syscall, and the only thing needed to read it is a userland gadget that stores ymm0 to memory:
-- vmovdqu [rdi],ymm0  (c5 fe 7f 07  /  c5 fd 11 07  /  c5 fc 11 07). 1173a found ZERO such gadget in
-- libc (0x120000 bytes). libkernel and the game eboot are the other two userland images and neither has
-- ever been scanned for AVX. Progress is printed per 0x40000 chunk so a read past a mapping localises.
-- The match is a 4-byte window at 4-byte alignment, so an unaligned store is missed; a byte-level pass
-- can follow if this finds nothing.
print("=== PROBE 1182a: VEX YMM0 STORE SCAN IN EBOOT AND LIBKERNEL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local REGIONS = {
  { name="libkernel", base=N(libkernel_base) },
  { name="eboot",     base=N(eboot_base) },
}
local PATS = {
  { name="vmovupd[rdi]", val=0x0711FDC5 },
  { name="vmovups[rdi]", val=0x0711FCC5 },
  { name="vmovdqu[rdi]", val=0x077FFEC5 },
  { name="vzeroupper",   val=0x77F8C5, mask=0xFFFFFF },
}
local CHUNK, MAXOFF = 0x40000, 0x400000
for _,reg in ipairs(REGIONS) do
  print(string.format("[R] %s base=%s", reg.name, hexn(reg.base)))
  if reg.base == 0 then
    print("[R] base unresolved - skipped")
  else
    for coff=0,MAXOFF-CHUNK,CHUNK do
      local counts = {}
      for pi=1,#PATS do counts[pi] = { n=0, first={} } end
      local bad = 0
      for off=coff,coff+CHUNK-4,4 do
        local dw = RD(reg.base+off)
        if dw < 0 then bad = bad + 1 else
          for pi=1,#PATS do
            local p = PATS[pi]
            local mask = p.mask or 0xFFFFFFFF
            if (dw % (mask+1)) == p.val then
              local h = counts[pi]
              h.n = h.n + 1
              if #h.first < 4 then h.first[#h.first+1] = off end
            end
          end
        end
      end
      local s = ""
      for pi=1,#PATS do
        local h = counts[pi]
        if h.n > 0 then
          s = s .. string.format(" %s=%d(", PATS[pi].name, h.n)
          for k=1,#h.first do s = s .. string.format("%X ", h.first[k]) end
          s = s .. ")"
        end
      end
      if s == "" then s = " none" end
      print(string.format("[%s +%X]%s unreadable=%d", reg.name, coff, s, bad))
      if bad > 0 then print("[R] unreadable dwords - region ended inside the chunk"); break end
    end
  end
end
print("[Z] alive")
print("=== DONE ===")
