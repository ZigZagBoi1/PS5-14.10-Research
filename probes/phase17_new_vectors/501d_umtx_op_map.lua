-- CRASH_CLASS: MODERATE
-- PROBE 501d: map _umtx_op op codes on 14.10
-- The repo has behaviour for ops 5, 21, 25, 26 only. Sweep 0..26 on a zeroed mutex
-- word with a non-matching id, so wait-shaped ops return EWOULDBLOCK instead of
-- blocking. Print ret and the word after each call, resetting the word first.
print("=== PROBE 501d: umtx op map ===")
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
local function hx(a) return string.format("0x%X", a) end
local sc = make_syscall(454)
local m = memory.alloc(0x100)
for o = 0, 0xFC, 4 do pcall(function() memory.write_dword(m + o, 0) end) end
local mid = hx(to_num(m))
for op = 0, 26 do
  for o = 0, 0xFC, 4 do pcall(function() memory.write_dword(m + o, 0) end) end
  local ok, ret = pcall(function()
    return sc(uint64(mid), uint64(op), uint64(0xDEADBEEF), uint64(0), uint64(0), uint64(0))
  end)
  local w = {}
  for o = 0, 0x1C, 4 do w[#w + 1] = string.format("%08X", to_num(memory.read_dword(m + o))) end
  print(string.format("op %2d ret=%s word=%s", op, tostring(ret), table.concat(w, " ")))
end
print("=== PROBE 501d COMPLETE ===")
