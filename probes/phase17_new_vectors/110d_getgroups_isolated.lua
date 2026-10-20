-- CRASH_CLASS: LOW
-- Isolate getgroups copyout from the failed 110b getcwd interval.
print("=== PROBE 110d: GETGROUPS ISOLATED ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local t = {}
for k, v in pairs(syscall.pipe) do t[k] = v end
t.syscall_no = 79
setmetatable(t, getmetatable(syscall.pipe))
local buf = memory.alloc(0x100)
for off = 0, 0xFC, 4 do memory.write_dword(buf + off, 0xA5A5A5A5) end
print("before getgroups(79)")
local ok, ret = pcall(function() return t(uint64(32), uint64(buf)) end)
print("after call ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok then
    local count = num(ret)
    if count >= 0 and count <= 32 then
        for i = 0, count - 1 do
            print(string.format("group[%d]=%d", i, num(memory.read_dword(buf + i * 4))))
        end
        for off = count * 4, math.min(count * 4 + 28, 0xFC), 4 do
            print(string.format("tail+%02X=%08X", off, num(memory.read_dword(buf + off))))
        end
    end
end
print("=== PROBE 110d COMPLETE ===")
