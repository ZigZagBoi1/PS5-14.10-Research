-- CRASH_CLASS: MODERATE
-- Isolate one syscall 189 copyout on a kqueue fd. Deliberately omit close.
print("=== PROBE 109c: FSTAT ONLY NO CLOSE ===")
local function n(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(no)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = no
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local ok, fd = pcall(function() return n(sc(362)()) end)
print("kqueue_ok=" .. tostring(ok) .. " fd=" .. tostring(fd))
if not ok or fd < 0 then
    print("=== PROBE 109c COMPLETE ===")
    return
end
local buf = memory.alloc(0x100)
for off = 0, 0xFC, 4 do memory.write_dword(buf + off, 0xA5A5A5A5) end
print("before_189")
local call_ok, ret = pcall(function() return sc(189)(uint64(fd), uint64(buf)) end)
print("call_ok=" .. tostring(call_ok) .. " ret=" .. tostring(ret))
for off = 0, 0x7C, 4 do
    local rd_ok, value = pcall(function() return n(memory.read_dword(buf + off)) end)
    print(string.format("+%02X=%s", off, rd_ok and string.format("%08X", value) or "READERR"))
end
print("=== PROBE 109c COMPLETE ===")
