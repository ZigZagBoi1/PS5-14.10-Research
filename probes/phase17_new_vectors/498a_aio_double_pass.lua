-- CRASH_CLASS: LOW
-- PROBE 498a: delete the same 64-id list twice in a row, no thread
-- 497f reported two clean deletes for ids 40..63 with a helper thread in the loop.
-- This removes the thread: one caller, one list, two passes. Any id that reports 0
-- twice here is a sequential double delete, not a race.
print("=== PROBE 498a: two sequential passes over one list ===")
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
local N = 64
local data, out = memory.alloc(0x2000), memory.alloc(0x100)
local ids, res = memory.alloc(N * 4), memory.alloc(N * 4)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local made = 0
for i = 0, N - 1 do
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if ok and id > 0 then
    pcall(function() memory.write_dword(ids + i * 4, id) end)
    pcall(function() return sc664(uint64(ids + i * 4), uint64(1), uint64(res)) end)
    made = made + 1
  end
end
print(string.format("prepared %d objects", made))
for pass = 0, 1 do
  for off = 0, N * 4 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x77777777) end) end
  local ret = pcall(function() return sc662(uint64(ids), uint64(N), uint64(res)) end)
  local z, s = {}, ""
  for i = 0, N - 1 do
    local st = to_num(memory.read_dword(res + i * 4))
    if st == 0 then z[#z + 1] = i end
    if i < 6 then s = s .. string.format(" %x", st) end
  end
  print(string.format("pass %d ret=%s zeros=%d first6:%s", pass, tostring(ret), #z, s))
  local t = ""
  for _, i in ipairs(z) do t = t .. i .. " " end
  print("  zero indices: " .. t)
end
print("=== PROBE 498a COMPLETE ===")
