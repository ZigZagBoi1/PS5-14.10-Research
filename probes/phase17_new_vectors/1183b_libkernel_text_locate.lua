-- CRASH_CLASS: MODERATE
-- PROBE 1183b: find where libkernel is actually readable, starting from a pointer we KNOW is executable.
-- 1183a died on page 0 AND page 1 of libkernel_base = memory.read_qword(mod_info+0x160) (syscall.lua:52),
-- so that derived "base" is not a readable address on 14.10. But the loader calls into libkernel for every
-- syscall: syscall.syscall_address (syscall.lua:27-28) = *libc gettimeofday import + 7, which is libkernel
-- .text, and x86-64 has no execute-without-read, so that page must be readable. Start there.
print("=== PROBE 1183b: LOCATE READABLE LIBKERNEL TEXT ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local u16 = function(x) return x % 65536 end
local IMP = nil
pec = pcall(function() IMP = N(libc_addrofs.gettimeofday_import) end)
print("[I] libc gettimeofday import slot = " .. hexn(IMP))
local ptr = 0
pcall(function() ptr = N(memory.read_qword(IMP)) end)
print("[I] *slot (libkernel text ptr)  = " .. hexn(ptr))
local sa = 0
pcall(function() sa = N(syscall.syscall_address) end)
print("[I] syscall.syscall_address     = " .. hexn(sa))
local b0 = 0
pcall(function() b0 = N(libkernel_base) end)
print("[I] libkernel_base (derived)    = " .. hexn(b0))
print(string.format("[I] sa - b0                     = %s", hexn(sa - b0)))
-- read the bytes at the wrapper: expect 0f 05 (syscall) somewhere near sa
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local function bytes(a,n)
  local s = ""
  for i=0,n-1 do local dw = RD(a + (i - (i % 4))) if dw < 0 then s = s .. "??" else s = s .. string.format("%02X ", (dw / math.floor(2^(8*(i%4)))) % 256) end end
  return s
end
print("[W] bytes at sa-8: " .. bytes(sa-8, 24))
-- page scan upward from the wrapper page
local PAGE = math.floor(sa / 4096)
local PAGES = 0x100
print(string.format("[S] walking %d pages upward from page %s", PAGES, hexn(PAGE*4096)))
local PATS = {
  { name="vmovupd", val=0x0711FDC5 },
  { name="vmovups", val=0x0711FCC5 },
  { name="vmovdqu", val=0x077FFEC5 },
}
local tot = {0,0,0}
local vzu = 0
for k=0,PAGES-1 do
  local pg = PAGE + k
  local base = pg * 4096
  local hits = {{},{},{}}
  for o=0,0xFFC,4 do
    local dw = RD(base + o)
    if dw >= 0 then
      for pi=1,3 do if (dw % 4294967296) == PATS[pi].val then tot[pi]=tot[pi]+1 if #hits[pi]<2 then hits[pi][#hits[pi]+1]=o end end end
      if (dw % 16777216) == 0x77F8C5 then vzu = vzu + 1 end
    end
  end
  local s = ""
  for pi=1,3 do if #hits[pi] > 0 then s = s .. string.format(" %s@", PATS[pi].name) for j=1,#hits[pi] do s = s .. string.format("%X ", base + hits[pi][j]) end end end
  print(string.format("[P %X]%s", pg, s))
end
print(string.format("[SUM] pages=%d vmovupd=%d vmovups=%d vmovdqu=%d vzeroupper=%d", PAGES, tot[1], tot[2], tot[3], vzu))
print("[Z] alive")
print("=== DONE ===")
