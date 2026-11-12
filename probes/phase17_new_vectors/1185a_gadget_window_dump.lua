-- CRASH_CLASS: SAFE  (reads only windows that 1184a already read successfully)
-- PROBE 1185a: hex-dump the bytes around 1184a's chunk-00 gadget candidates so capstone can say whether they
-- are real ymm0 stores or matching noise (1184a counted 704 per MB while vzeroupper was 0, which is suspicious).
-- Offsets are RELATIVE to eboot_base because every connection is a fresh process with fresh ASLR.
print("=== PROBE 1185a: GADGET WINDOW DUMP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local base = 0
pcall(function() base = N(eboot_base) end)
print("[A] eboot_base=" .. hexn(base))
local OFFS = { 0x7C0, 0x149B, 0x157A, 0x9AB8, 0xDAB8 }
local BACK, FWD = 0x40, 0x30
for _,off in ipairs(OFFS) do
  local a = base + off - BACK
  local o, buf = pcall(function() return memory.read_buffer(a, BACK + FWD) end)
  if o and type(buf) == "string" and #buf == BACK + FWD then
    local hex = string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end)
    print(string.format("[W] off=%X addr=%s start=%X", off, hexn(a), off - BACK))
    for i=1,#hex,64 do print(" " .. string.sub(hex, i, i+63)) end
  else
    print(string.format("[W] off=%X READ-FAIL", off))
  end
end
print("[Z] alive")
print("=== 1185a DONE ===")
