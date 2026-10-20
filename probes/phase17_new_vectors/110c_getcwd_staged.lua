-- CRASH_CLASS: MODERATE
-- Stage the previous getcwd failure to separate allocation from syscall entry.
print("=== PROBE 110c: GETCWD STAGED ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local t = {}
for k, v in pairs(syscall.pipe) do t[k] = v end
t.syscall_no = 326
setmetatable(t, getmetatable(syscall.pipe))
print("before alloc")
local buf = memory.alloc(0x200)
print("after alloc")
for off = 0, 0x1FC, 4 do memory.write_dword(buf + off, 0xA5A5A5A5) end
print("after fill; before __getcwd(326)")
local ok, ret = pcall(function() return t(uint64(buf), uint64(0x200)) end)
print("after call ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
for off = 0, 28, 4 do
    print(string.format("+%02X=%08X", off, num(memory.read_dword(buf + off))))
end
print("=== PROBE 110c COMPLETE ===")
