-- CRASH_CLASS: HIGH
-- PROBE 488e: does the create "mode" argument select the object type delete wants?
-- 488d: create(flags=1,mode=1) then delete -> status 0x80020010. In the delete
-- body 0x3afd76 checks [obj+8]-3 < 2 (type 3 or 4) and writes 0x80020010 when
-- it does not match. The create guard accepts mode 1..3, so try each mode.
print("=== PROBE 488e: 669 mode -> deletable type ===")
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
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local sc669 = make_syscall(669)
local sc662 = make_syscall(662)
local function create(mode, flags)
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(flags), uint64(data), uint64(4), uint64(mode), uint64(out)) end)
  if not ok then return nil, -999 end
  return to_num(memory.read_dword(out)), to_num(rv)
end
local function del(id)
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() memory.write_dword(res, 0x42424242) end)
  local ok, rv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
  local st = to_num(memory.read_dword(res))
  return ok, ok and to_num(rv) or -999, st
end
for _, mode in ipairs({1, 2, 3}) do
  local id, rv = create(mode, 1)
  if not id then print(string.format("mode=%d create failed", mode))
  else
    local ok, drv, st = del(id)
    print(string.format("mode=%d create ret=%d id=%d delete ok=%s ret=%d status=%#x", mode, rv, id, tostring(ok), drv, st))
  end
end
print("=== PROBE 488e COMPLETE ===")
