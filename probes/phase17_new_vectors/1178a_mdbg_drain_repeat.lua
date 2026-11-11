-- CRASH_CLASS: SAFE  (three commands that return; no parkers, main thread only)
-- PROBE 1178a: the two commands that write zero dwords are the drain candidates - do they fill on a
-- second call? 1176b/1177a measured 601(cmd, buf, 0x1000, 0,0,0) for every command 0x00..0x2F:
-- only 0x0E (8 zero bytes), 0x1A (4 zero bytes) and 0x00 (8 bytes, 0x00000100) wrote anything, and
-- nothing ever contained text. docs/HANDLER_SHAPE_HUNT_14_10.md says the log drain lazily CREATES the
-- "mdbglog" and every 601 call appends "mDBG: Debughandler starting(...)". If the log starts empty, the
-- first call returns zero bytes and only a SECOND call can return text - which the sweep never tried.
-- So: each candidate is called three times in a row, buffer refilled between calls, full first 128
-- bytes printed as dwords and ASCII every time.
print("=== PROBE 1178a: 601 DRAIN CANDIDATES, REPEATED ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local base = N(memory.alloc(0x4000))
print(string.format("[F] buf=0x%08X", base % 4294967296))
local function refill() for i=0,0x3FFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end end
local function call601(cmd, len)
  local ok, rv = pcall(function()
    local t = {}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no = 601
    setmetatable(t, getmetatable(syscall.pipe))
    return t(U(cmd), U(base), U(len), U(0), U(0), U(0))
  end)
  if not ok then return nil, tostring(rv) end
  return N(rv)
end
local function show(tag, maxbytes)
  local hex, ascii = "", ""
  for i=0,124,4 do hex = hex .. string.format("%08X ", RD(base+i)) end
  for b=0,maxbytes-1 do
    local d = RD(base + (b - b % 4))
    local v = math.floor(d / 2^((b % 4) * 8)) % 256
    if v >= 32 and v < 127 then ascii = ascii .. string.char(v) else ascii = ascii .. "." end
  end
  local tail = ""
  for i=0x3F00,0x3FFC,4 do local d=RD(base+i); if d ~= 0xA5A5A5A5 then tail = tail .. string.format("@%X=%08X ", i, d) end end
  print(string.format("[%s] dw=%s", tag, hex))
  print(string.format("[%s] ascii=\"%s\" tail_changed=%s", tag, ascii, tail == "" and "none" or tail))
end

local CAND = { 0x00, 0x0E, 0x1A, 0x0B, 0x0D, 0x13, 0x14, 0x19, 0x1D, 0x20 }
for _,cmd in ipairs(CAND) do
  for round=1,3 do
    refill()
    local rv, err = call601(cmd, 0x4000)
    if rv == nil then
      print(string.format("[%02X/%d] call failed: %s", cmd, round, err))
    else
      print(string.format("[%02X/%d] rv=%d", cmd, round, rv))
      show(string.format("%02X/%d", cmd, round), 128)
    end
  end
end
print("[Z] alive")
print("=== DONE ===")
