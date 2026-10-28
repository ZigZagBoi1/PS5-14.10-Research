-- CRASH_CLASS: MODERATE
-- PROBE 500b: does a create ever submit work?
-- The create body calls a gate (13.60 0x8b4c78d0) that returns 1 only when a global is
-- 3 or 4; when it returns 0 the submit call is skipped entirely. A real submitted read
-- with a bad fd or an absurd length must fail differently from a skipped one, which
-- always completes with status 3. Sweep mode, fd and length.
print("=== PROBE 500b: aio submit gate ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
local desc, out, st, ids = memory.alloc(0x40), memory.alloc(0x40), memory.alloc(0x40), memory.alloc(0x40)
local buf = memory.alloc(0x400)
local function zero(p, n) for o = 0, n - 1, 4 do pcall(function() memory.write_dword(p + o, 0) end) end end
local fd = 0
do local ok, v = pcall(function() return syscall.open("/savedata0/thread.lua", 0) end); if ok then fd = to_num(v) end end
print("fd " .. fd)
local bufa = to_num(buf) or 0
local cases = {
  { m = 1, f = fd,   len = 64 },
  { m = 2, f = fd,   len = 64 },
  { m = 3, f = fd,   len = 64 },
  { m = 1, f = 9999, len = 64 },
  { m = 2, f = 9999, len = 64 },
  { m = 3, f = 9999, len = 64 },
  { m = 1, f = fd,   len = 0x40000000 },
  { m = 2, f = fd,   len = 0x40000000 },
  { m = 3, f = fd,   len = 0x40000000 },
}
for i, c in ipairs(cases) do
  zero(desc, 0x40); zero(out, 0x40); zero(st, 0x40); zero(buf, 0x400); zero(ids, 0x40)
  pcall(function() memory.write_dword(desc + 0, 1) end)
  pcall(function() memory.write_dword(desc + 4, c.f) end)
  pcall(function() memory.write_qword(desc + 8, uint64(0)) end)
  pcall(function() memory.write_qword(desc + 0x10, uint64(string.format("0x%X", bufa))) end)
  pcall(function() memory.write_qword(desc + 0x18, uint64(c.len)) end)
  local okc, ret = pcall(function() return sc669(uint64(1), uint64(desc), uint64(1), uint64(c.m), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  local line = string.format("[%d] mode=%d fd=%d len=%x ret=%s id=%d", i, c.m, c.f, c.len, tostring(ret), id)
  if id > 0 then
    pcall(function() memory.write_dword(ids, id) end)
    local last, hist = 0, ""
    for k = 1, 500 do
      zero(st, 0x40)
      pcall(function() return sc664(uint64(ids), uint64(1), uint64(st)) end)
      last = to_num(memory.read_dword(st))
      if k <= 3 then hist = hist .. string.format("%x,", last) end
      if last == 3 then break end
    end
    local nz = 0
    for o = 0, 63 do if (to_num(memory.read_byte(buf + o)) or 0) ~= 0 then nz = nz + 1 end end
    line = line .. string.format(" poll=%x hist=%s nonzero=%d", last, hist, nz)
    zero(st, 0x40)
    pcall(function() return sc662(uint64(ids), uint64(1), uint64(st)) end)
    line = line .. string.format(" del=%x", to_num(memory.read_dword(st)))
  end
  print(line)
end
print("=== PROBE 500b COMPLETE ===")
