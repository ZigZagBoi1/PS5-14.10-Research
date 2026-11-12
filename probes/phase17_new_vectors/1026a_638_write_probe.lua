-- CRASH_CLASS: MODERATE
-- PROBE 1026a: what do 638 / 592 / 659 actually write, and is the value stable?
--
-- 1025a (sony copyout sweep) found three handlers that write into a sentinel
-- buffer despite returning -1: 638 shape C wrote 0xFFFFFFFFFDC7BB70 (a
-- supervisor-shaped qword), 638 shape B wrote 0xE10, 639 wrote -0xE10,
-- 592 shape A wrote 20 qwords of small integer pairs, 659 wrote 2 qwords.
-- A stable supervisor-shaped value out of a syscall would be the KASLR leak
-- every earlier probe failed to find, so measure it properly.

print("=== PROBE 1026a: 638/592/659 WRITE PROBE ===")

local function to_num(v)
  if type(v) == "table" then
    if v.tonumber then local ok, r = pcall(function() return v:tonumber() end); if ok then return r end end
    if v.h and v.l then return v.h * 2^32 + v.l end
  end
  return tonumber(v) or 0
end
local function as_addr(x) return uint64(string.format("0x%X", to_num(x))) end
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
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end return nil end

local SENT = 0xCCCCCCCC
local function fill() for o = 0, 0x1F8, 8 do wq(ba + o, SENT) end end
local function dump(tag, n)
  local out = {}
  for i = 0, n - 1 do
    local v = rq(ba + i * 8)
    out[#out + 1] = string.format("%X", v or 0)
  end
  print(string.format("  %s %s", tag, table.concat(out, " ")))
end
local function count()
  local c = 0
  for o = 0, 0x1F8, 8 do if rq(ba + o) ~= SENT then c = c + 1 end end
  return c
end

-- shield so an absent handler cannot take the process
local sa = memory.alloc(0x40)
for o = 0, 0x38, 8 do wq(sa + o, 0) end
wd(sa + 0x08, 2)                      -- ca_flags = SA_SIGINFO, as 353a read back
wd(sa, 1)                             -- SIG_IGN
local ok_s = pcall(function() return make_syscall(416)(12, sa, 0) end)
print(string.format("[0] shield ok=%s pid=%d", tostring(ok_s), to_num(make_syscall(20)())))

ba = memory.alloc(0x200)
if not ba then print("[!] alloc failed") return end

local pid = to_num(make_syscall(20)())
-- argument shapes copied verbatim from 1025a: ba goes in slot 1 (A), 2 (B) or 3 (C)
local function shape(sc, which, a2, a3, a4)
  if which == "A" then return sc(uint64(ba), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0)) end
  if which == "B" then return sc(uint64(0), uint64(ba), uint64(0x100), uint64(0), uint64(0), uint64(0)) end
  return sc(uint64(0), uint64(0), uint64(ba), uint64(0x100), uint64(0), uint64(0))
end
local TESTS = {
  {"638A", 638, "A"}, {"638B", 638, "B"}, {"638C", 638, "C"},
  {"639A", 639, "A"}, {"639B", 639, "B"}, {"639C", 639, "C"},
  {"592A", 592, "A"}, {"592B", 592, "B"}, {"592C", 592, "C"},
  {"659A", 659, "A"}, {"659B", 659, "B"}, {"659C", 659, "C"},
  {"598A", 598, "A"}, {"615B", 615, "B"}, {"601B", 601, "B"}, {"602C", 602, "C"},
}

for pass = 1, 3 do
  print(string.format("-- pass %d", pass))
  for _, t in ipairs(TESTS) do
    fill()
    local sc = make_syscall(t[2])
    local rv
    local ok, r = pcall(function() return shape(sc, t[3]) end)
    rv = ok and to_num(r) or -999
    print(string.format("  %s rv=%d written=%d", t[1], rv, count()))
    if count() > 0 then dump(t[1], 16) end
  end
end

print(string.format("[Z] alive pid=%d", pid))
