-- CRASH_CLASS: SAFE  (only chunk 00 of eboot, which 1184a already read without faulting)
-- PROBE 1186a: dump 1 MB of eboot text as hex so capstone can find a REAL gadget offline:
--   store ymmN to [controlled reg] followed by a ret within a few instructions.
-- Entering a store mid-function is possible but it runs the following instructions, so the offline pass has to
-- show exactly what comes after; a store that ends a basic block is the only safe entry point.
print("=== PROBE 1186a: EBOOT 1MB HEX DUMP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local base = 0
pcall(function() base = N(eboot_base) end)
print("[A] eboot_base=" .. hexn(base))
local CH = 0x10000
for k=0,15 do
  local a = base + k*CH
  local o, buf = pcall(function() return memory.read_buffer(a, CH) end)
  if o and type(buf) == "string" and #buf == CH then
    local hex = string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end)
    print(string.format("[D %02X] off=%X len=%X", k, k*CH, CH))
    for i=1,#hex,128 do print(string.sub(hex, i, i+127)) end
  else
    print(string.format("[D %02X] READ-FAIL off=%X", k, k*CH))
  end
end
print("[Z] alive")
print("=== 1186a DONE ===")
