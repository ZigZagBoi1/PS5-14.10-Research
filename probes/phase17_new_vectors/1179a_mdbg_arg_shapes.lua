-- CRASH_CLASS: SAFE  (only commands already measured to return; main thread only)
-- PROBE 1179a: the log drain never appeared with the sweep's one argument shape. Before widening the
-- command space, widen the ARGUMENT space on the commands that return cleanly.
-- 1178a showed these all return 0 and write nothing with (buf, len, 0): 0x0B 0x0D 0x13 0x14 0x19 0x1D
-- 0x20, and these write fixed out-params: 0x00 -> {0x100,0}, 0x0E -> {0,0}, 0x1A -> {0}.
-- The drain body (docs/HANDLER_SHAPE_HUNT_14_10.md finding 1) builds a uio from a user buffer and a
-- length and uiomove()s log text out, so the two plausible orderings are (buf,len) - the baseline - and
-- (len,buf). A third possibility is that the buffer is the THIRD argument and the first two are
-- (something, length). Each shape is tried with a 0x200 and a 0x4000 length at both candidate offsets,
-- and the whole 0x4000 buffer is checked for any changed dword.
print("=== PROBE 1179a: 601 ARGUMENT-SHAPE MATRIX ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local base = N(memory.alloc(0x4000))
print(string.format("[F] buf=0x%08X", base % 4294967296))
local function refill() for i=0,0x3FFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end end
local function call601(a,b,c,d,e,f)
  local ok, rv = pcall(function()
    local t = {}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no = 601
    setmetatable(t, getmetatable(syscall.pipe))
    return t(U(a), U(b), U(c), U(d), U(e), U(f))
  end)
  if not ok then return nil end
  return N(rv)
end
local function scan()
  local changed, first, hex = 0, -1, ""
  for i=0,0x3FFC,4 do
    local d = RD(base+i)
    if d ~= -1 and d ~= 0xA5A5A5A5 then
      changed = changed + 1
      if first < 0 then first = i end
      if changed <= 8 then hex = hex .. string.format("@%X=%08X ", i, d) end
    end
  end
  return changed, first, hex
end
local CAND = { 0x00, 0x0B, 0x0D, 0x0E, 0x13, 0x14, 0x19, 0x1A, 0x1D, 0x20 }
-- arg tuples: name then six arguments
local SHAPES = {
  { name="A buf,0x200",        args={ nil, "BUF", 0x200, 0, 0, 0 } },
  { name="B buf,0x4000",       args={ nil, "BUF", 0x4000, 0, 0, 0 } },
  { name="C 0x200,buf",        args={ nil, 0x200, "BUF", 0, 0, 0 } },
  { name="D 0x4000,buf",       args={ nil, 0x4000, "BUF", 0, 0, 0 } },
  { name="E 0,buf,0x4000",     args={ nil, 0, "BUF", 0x4000, 0, 0 } },
  { name="F buf,0x4000,1",     args={ nil, "BUF", 0x4000, 1, 0, 0 } },
  { name="G buf,0x4000,,1",    args={ nil, "BUF", 0x4000, 0, 1, 0 } },
}
local hits = 0
for ci=1,#CAND do
  local cmd = CAND[ci]
  for si=1,#SHAPES do
    refill()
    local a = SHAPES[si].args
    local a1 = a[1] == nil and cmd or a[1]
    local a2 = a[2] == "BUF" and base or a[2]
    local a3 = a[3] == "BUF" and base or a[3]
    local rv = call601(a1, a2, a3, a[4], a[5], a[6])
    local changed, first, hex = scan()
    if rv == nil then
      print(string.format("[%02X/%s] call failed", cmd, SHAPES[si].name))
    elseif changed > 0 or rv ~= 0 then
      print(string.format("[%02X/%s] rv=%d changed=%d first=%d %s", cmd, SHAPES[si].name, rv, changed, first, hex))
      if changed > 8 then hits = hits + 1 end
    end
  end
end
print(string.format("[SUM] shapes=%d commands=%d big_writes=%d", #SHAPES, #CAND, hits))
print("[Z] alive")
print("=== DONE ===")
