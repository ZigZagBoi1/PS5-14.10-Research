-- CRASH_CLASS: MODERATE
-- PROBE 493b: syscall opcode scan restricted to the gadget module
-- 493a started at 0x17B00000 and died. Every gadget the loader ships lives in
-- 0x17B40042..0x17F095F3, so that window is mapped and readable; scan only it,
-- one 0x10000 chunk at a time, printing progress so a death is locatable.
print("=== PROBE 493b: bounded syscall scan ===")
io.stdout:setvbuf("no")
local lo, hi, step = 0x17B40000, 0x17F20000, 0x10000
local hits = 0
for a = lo, hi - step, step do
  io.write(string.format("  chunk %#x ... ", a))
  local ok, buf = pcall(function() return memory.read_buffer(a, step) end)
  if not ok or type(buf) ~= "string" or #buf < step then
    print("unreadable")
  else
    local n = 0
    local i = 1
    while true do
      local s, e = buf:find("\15\5", i, true)
      if not s then break end
      n = n + 1
      hits = hits + 1
      if hits <= 10 then
        local ctx = buf:sub(math.max(1, s - 6), math.min(#buf, e + 6))
        local hex = {}
        for k = 1, #ctx do hex[#hex + 1] = string.format("%02x", ctx:byte(k)) end
        print(string.format("\n    HIT %#x  %s", a + s - 1, table.concat(hex, " ")))
        io.write("    ")
      end
      i = e + 1
    end
    print(string.format("ok hits=%d", n))
  end
end
print(string.format("total hits=%d", hits))
print("=== PROBE 493b COMPLETE ===")
