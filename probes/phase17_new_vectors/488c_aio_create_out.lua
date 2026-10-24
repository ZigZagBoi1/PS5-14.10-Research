-- CRASH_CLASS: MODERATE
-- PROBE 488c: 669 with a mapped 5th argument succeeds; where does the id go?
-- 488b shape 5 (1, data, 4, 1, data) returned 0 where every shape with a NULL
-- 5th argument returned -1. 13.60 hands r9 = uap[0x20] into the body, so this
-- is almost certainly the out-parameter for the allocated id. Dump it.
print("=== PROBE 488c: 669 out parameter ===")
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
local function hex(buf, n)
    local out = {}
    for i = 0, n - 1 do
        local ok, b = pcall(function() return to_num(memory.read_byte(buf + i)) end)
        if not ok then out[#out + 1] = "??"; break end
        out[#out + 1] = string.format("%02x", b)
    end
    return table.concat(out, " ")
end
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0x100 - 1, 4  do pcall(function() memory.write_dword(out + off, 0xA5A5A5A5) end) end
local sc669 = make_syscall(669)
for c = 1, 3 do
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0xA5A5A5A5) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(4), uint64(1), uint64(out)) end)
  print(string.format("[%d] 669(1,d,4,1,out) ok=%s ret=%s", c, tostring(ok), ok and tostring(to_num(rv)) or "-"))
  print("    out = " .. hex(out, 0x20))
end
print("=== PROBE 488c COMPLETE ===")
