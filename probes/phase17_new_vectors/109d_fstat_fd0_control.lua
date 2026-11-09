-- CRASH_CLASS: LOW
-- Control for 109c: same syscall 189 and buffer handling, on known fd 0.
print("=== PROBE 109d: FSTAT FD0 CONTROL ===")
local t = {}
for k, v in pairs(syscall.pipe) do t[k] = v end
t.syscall_no = 189
setmetatable(t, getmetatable(syscall.pipe))
local b = memory.alloc(0x100)
for o = 0, 0xFC, 4 do memory.write_dword(b + o, 0xA5A5A5A5) end
print("before_189")
local ok, ret = pcall(function() return t(uint64(0), uint64(b)) end)
print("call_ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
for _, off in ipairs({0, 4, 8, 0x70, 0x74, 0x78, 0x7C}) do
    local read_ok, val = pcall(function() return memory.read_dword(b + off) end)
    print(string.format("+%02X=%s", off, read_ok and tostring(val) or "READERR"))
end
print("=== PROBE 109d COMPLETE ===")
