-- CRASH_CLASS: LOW
-- PROBE 493a: look for a syscall instruction in eboot's readable RX range
-- The loader's gadget table has pop rax/rdi/rsi/rdx/rcx/r8 and a call gadget but
-- no "syscall; ret". A second thread that can issue 662 itself needs one, so the
-- image the gadgets come from (0x17B4xxxx..0x17F1xxxx) is scanned for 0f 05.
print("=== PROBE 493a: syscall opcode scan ===")
io.stdout:setvbuf("no")
local lo, hi, step = 0x17B00000, 0x18000000, 0x10000
local hits = 0
local unreadable = 0
for a = lo, hi - step, step do
  local ok, buf = pcall(function() return memory.read_buffer(a, step) end)
  if not ok or not buf then
    unreadable = unreadable + 1
  else
    local i = 1
    while true do
      local s, e = buf:find("\15\5", i, true)
      if not s then break end
      local addr = a + s - 1
      hits = hits + 1
      if hits <= 12 then
        local ctx = buf:sub(math.max(1, s - 4), math.min(#buf, e + 4))
        local hex = {}
        for k = 1, #ctx do hex[#hex + 1] = string.format("%02x", ctx:byte(k)) end
        print(string.format("  0x%08X  %s", addr, table.concat(hex, " ")))
      end
      i = e + 1
    end
  end
end
print(string.format("scanned %#x..%#x hits=%d unreadable_chunks=%d", lo, hi, hits, unreadable))
print("=== PROBE 493a COMPLETE ===")
