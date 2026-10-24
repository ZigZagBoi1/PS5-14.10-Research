-- CRASH_CLASS: HIGH
-- PROBE 489b: poll / cancel against a live created object, then delete
-- 13.60 wrappers: 664 (poll) and 666 (cancel) take
--   uap+0x00 ids array, uap+0x08 count, uap+0x10 out array.
-- 669 create works on 14.10 and 662 finds the object (status 0x80020010 = state
-- gate). Poll and cancel are the two non-blocking members that could move a
-- request into the state the delete path accepts, so run both, each followed by
-- a delete of the same id.
print("=== PROBE 489b: poll/cancel then delete ===")
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
local sc669 = make_syscall(669)
local sc662 = make_syscall(662)
local sc664 = make_syscall(664)
local sc666 = make_syscall(666)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create(count, mode)
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(count), uint64(mode), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end
local function del(id)
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() memory.write_dword(res, 0x42424242) end)
  local ok, rv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
  return ok, ok and to_num(rv) or -999, ok and to_num(memory.read_dword(res)) or -1
end
local function call2(sc, id, label, extra)
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() memory.write_dword(res, 0x42424242) end)
  local fn = function() return sc(uint64(ids), uint64(1), uint64(res), uint64(extra or 0)) end
  local ok, rv = pcall(fn)
  print(string.format("    %s id=%d ok=%s ret=%s res0=%#x", label, id, tostring(ok),
        ok and tostring(to_num(rv)) or "-", to_num(memory.read_dword(res))))
  return ok
end

print("[A] poll then delete")
local idA = create(1, 1)
if idA then
  call2(sc664, idA, "664 poll", 0)
  local ok, rv, st = del(idA)
  print(string.format("    662 delete ok=%s ret=%d status=%#x", tostring(ok), rv, st))
end

print("[B] cancel then delete")
local idB = create(1, 1)
if idB then
  call2(sc666, idB, "666 cancel", 0)
  local ok, rv, st = del(idB)
  print(string.format("    662 delete ok=%s ret=%d status=%#x", tostring(ok), rv, st))
end

print("[C] cancel with a 4-byte out array then delete")
local idC = create(4, 2)
if idC then
  call2(sc666, idC, "666 cancel(mode2)", 0)
  local ok, rv, st = del(idC)
  print(string.format("    662 delete ok=%s ret=%d status=%#x", tostring(ok), rv, st))
end
print("=== PROBE 489b COMPLETE ===")
