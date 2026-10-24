-- CRASH_CLASS: HIGH
-- PROBE 488b: 669 argument-shape matrix
-- 13.60 669 wants {flags(1|2), buf, count(1..0x80), mode(1..3), extra}.
-- 488a with (1,data,4,1,0) returned -1 without crashing, so try the nearby
-- shapes to find which check 14.10 applies.
print("=== PROBE 488b: 669 shape matrix ===")
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
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local sc669 = make_syscall(669)
local shapes = {
  {"1,d,1,1,0",   1, data, 1, 1, 0},
  {"1,d,1,2,0",   1, data, 1, 2, 0},
  {"1,d,1,3,0",   1, data, 1, 3, 0},
  {"2,d,1,1,0",   2, data, 1, 1, 0},
  {"1,d,4,1,d",   1, data, 4, 1, data},
  {"1,0,4,1,0",   1, 0,    4, 1, 0},
  {"1,d,4,1,0",   1, data, 4, 1, 0},
  {"0,d,4,1,0",   0, data, 4, 1, 0},
  {"1,d,4,0,0",   1, data, 4, 0, 0},
  {"1,d,4,4,0",   1, data, 4, 4, 0},
}
for i, s in ipairs(shapes) do
  local ok, rv = pcall(function() return sc669(uint64(s[2]), uint64(s[3]), uint64(s[4]), uint64(s[5]), uint64(s[6])) end)
  print(string.format("[%2d] %-12s ok=%s ret=%s", i, s[1], tostring(ok), ok and tostring(to_num(rv)) or "-"))
end
print("=== PROBE 488b COMPLETE ===")
