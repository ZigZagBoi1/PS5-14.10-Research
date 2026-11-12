-- CRASH_CLASS: MODERATE  (raw ropchain; syscall;ret -> pop rsi;ret -> vmovups [rsi],ymm0; ret)
-- PROBE 1190a: why does the in-chain ymm0 store fire after getpid but not after 196/638?
-- 1189a: [C] store-only -> 32 zero bytes; [P] getpid then store -> 32 zero bytes;
--        [G] 196 then store -> buffer untouched; [T] 638 then store -> only the kernel's own 8-byte value_out landed.
-- Here every case re-loads rsi from a fresh 'pop rsi; ret' AFTER the syscall, so the store target cannot be
-- confused with a syscall argument, and each case stores rax into a slot first so the syscall's return value is
-- visible even if the store never runs.
print("=== PROBE 1190a: IN-CHAIN STORE AFTER FOUR SYSCALL SHAPES ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local be  = N(eboot_base)
local SC  = N(syscall.syscall_address)
local GAD = be + 0xF7CB7
local BUF  = N(memory.alloc(0x100))
local BUF2 = N(memory.alloc(0x100))
print("[A] eboot=" .. hexn(be) .. " store=" .. hexn(GAD) .. " sc=" .. hexn(SC))
print("[A] BUF=" .. hexn(BUF) .. " BUF2=" .. hexn(BUF2))
local function fill(addr, v) for i=0,0x3C,4 do pcall(function() memory.write_dword(addr+i, v) end) end end
local function bytes(addr, n)
  local o, buf = pcall(function() return memory.read_buffer(addr, n) end)
  if o and type(buf)=="string" and #buf==n then
    return (string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end))
  end
  return "READ-FAIL"
end
local function words(addr, count)
  local out = {}
  for i=0,count-1 do
    local o, q = pcall(function() return memory.read_qword(addr + i*8) end)
    if o then out[#out+1] = string.format("%08X%08X", math.floor(N(q)/4294967296), N(q)%4294967296) else out[#out+1] = "????" end
  end
  return table.concat(out, " ")
end
local CASES = {
  { tag="C0", desc="no syscall, store only", build=function(c) end },
  { tag="C1", desc="getpid(20), no arguments", sys=20,
    args=function(c) end },
  { tag="C2", desc="196(fd 0, BUF2, 0, 0)", sys=196,
    args=function(c) c:push_set_rdi(0) c:push_set_rsi(BUF2) c:push_set_rdx(0) c:push_set_rcx(0) end },
  { tag="C3", desc="638(1000000000, BUF2, 0, 0) - the measured call shape", sys=638,
    args=function(c) c:push_set_rdi(U(1000000000)) c:push_set_rsi(BUF2) c:push_set_rdx(0) c:push_set_rcx(0) end },
  { tag="C4", desc="638(1, 2, 3, 4) - all arguments invalid", sys=638,
    args=function(c) c:push_set_rdi(1) c:push_set_rsi(2) c:push_set_rdx(3) c:push_set_rcx(4) end },
}
for _, case in ipairs(CASES) do
  fill(BUF, 0xC7) fill(BUF2, 0xD3)
  local rv_slot = N(memory.alloc(8))
  pcall(function() memory.write_qword(rv_slot, U(0xEEEEEEEE)) end)
  local ok, err = pcall(function()
    local chain = ropchain()
    if case.sys then case.args(chain) end
    if case.sys then chain:push_set_rax(case.sys) chain:push(SC) end
    chain:push_store_rax_into_memory(rv_slot)   -- record rv (if the chain survived the syscall)
    chain:push_set_rsi(BUF)                     -- load the store target AFTER the syscall
    chain:push(GAD)                             -- vmovups [rsi], ymm0 ; ret
    local th = thread:new(chain)
    th:run(false)
  end)
  local rv = "?" pcall(function() rv = N(memory.read_qword(rv_slot)) end)
  print(string.format("[%s] %s", case.tag, case.desc))
  print(string.format("     run ok=%s err=%s rv=%s", tostring(ok), tostring(err), hexn(rv)))
  print("     BUF  " .. bytes(BUF, 32) .. "  | " .. words(BUF, 4))
  print("     BUF2 " .. bytes(BUF2, 32) .. "  | " .. words(BUF2, 4))
end
print("[Z] alive")
print("=== DONE ===")
