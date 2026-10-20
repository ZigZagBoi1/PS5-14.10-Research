-- CRASH_CLASS: MODERATE
-- One read-only kldsym candidate call; record exact buffer mutation.
print("=== PROBE 53e: KLDSYM SINGLE ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local t = {}
for k, v in pairs(syscall.pipe) do t[k] = v end
t.syscall_no = 337
setmetatable(t, getmetatable(syscall.pipe))
local name = "allproc"
local namebuf = memory.alloc(16)
for i = 1, #name do memory.write_byte(namebuf + i - 1, string.byte(name, i)) end
memory.write_byte(namebuf + #name, 0)
local req = memory.alloc(64)
for i = 0, 60, 4 do memory.write_dword(req + i, 0xA5A5A5A5) end
memory.write_dword(req, 32)
memory.write_qword(req + 8, uint64(namebuf))
print("before kldsym fileid=0 cmd=1 name=allproc")
local ok, ret = pcall(function() return t(uint64(0), uint64(1), uint64(req)) end)
print("call_ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
for off = 0, 60, 4 do
    print(string.format("+%02X=%08X", off, num(memory.read_dword(req + off))))
end
print("=== PROBE 53e COMPLETE ===")
