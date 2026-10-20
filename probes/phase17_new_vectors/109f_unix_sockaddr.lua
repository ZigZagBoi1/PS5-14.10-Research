-- CRASH_CLASS: LOW
-- Sentinel comparison of unnamed AF_LOCAL socketpair address copyout.
print("=== PROBE 109f: UNIX SOCKADDR ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sv = memory.alloc(8)
memory.write_dword(sv, 0xDEAD); memory.write_dword(sv + 4, 0xDEAD)
local ok, rv = pcall(function() return sc(135)(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local a, b = num(memory.read_dword(sv)), num(memory.read_dword(sv + 4))
print("socketpair ok=" .. tostring(ok) .. " ret=" .. tostring(rv) .. " fds=" .. a .. "," .. b)
if not ok or num(rv) ~= 0 or a < 3 or b < 3 or a == b then
    print("=== PROBE 109f COMPLETE ===")
    return
end
for _, item in ipairs({{32, "self"}, {31, "peer"}}) do
    for _, fill in ipairs({0xA5A5A5A5, 0x5A5A5A5A}) do
        local buf = memory.alloc(0x80)
        local lenp = memory.alloc(8)
        for i = 0, 0x7C, 4 do memory.write_dword(buf + i, fill) end
        memory.write_dword(lenp, 0x80)
        local call_ok, ret = pcall(function()
            return sc(item[1])(uint64(a), uint64(buf), uint64(lenp))
        end)
        local len = num(memory.read_dword(lenp))
        print(string.format("%s fill=%08X ok=%s ret=%s len=%d", item[2], fill, tostring(call_ok), tostring(ret), len))
        for off = 0, 0x1C, 4 do
            print(string.format("+%02X=%08X", off, num(memory.read_dword(buf + off))))
        end
    end
end
sc(6)(uint64(a)); sc(6)(uint64(b))
print("=== PROBE 109f COMPLETE ===")
