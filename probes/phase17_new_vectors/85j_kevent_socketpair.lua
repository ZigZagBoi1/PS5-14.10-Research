-- CRASH_CLASS: LOW
-- Focused EVFILT_READ copyout on a verified AF_LOCAL socketpair.
print("=== PROBE 85j: KEVENT SOCKETPAIR ===")
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
local function dump(tag, p)
    local s = {}
    for off = 0, 28, 4 do
        s[#s + 1] = string.format("%02X:%08X", off, num(memory.read_dword(p + off)))
    end
    print(tag .. " " .. table.concat(s, " "))
end
local sv = memory.alloc(8)
memory.write_dword(sv, 0xDEAD)
memory.write_dword(sv + 4, 0xDEAD)
local ok_s, rv_s = pcall(function() return sc(135)(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local a, b = num(memory.read_dword(sv)), num(memory.read_dword(sv + 4))
print("socketpair ok=" .. tostring(ok_s) .. " ret=" .. tostring(rv_s) .. " fds=" .. a .. "," .. b)
if not ok_s or num(rv_s) ~= 0 or a == b or a < 3 or b < 3 then
    print("socketpair failed; no kevent attempted")
    print("=== PROBE 85j COMPLETE ===")
    return
end
local kq = num(sc(362)())
print("kqueue=" .. kq)
if kq < 3 then
    sc(6)(uint64(a)); sc(6)(uint64(b))
    print("=== PROBE 85j COMPLETE ===")
    return
end
local byte = memory.alloc(8)
memory.write_dword(byte, 0x41424344)
local ok_w, rv_w = pcall(function() return sc(4)(uint64(b), uint64(byte), uint64(4)) end)
print("write ok=" .. tostring(ok_w) .. " ret=" .. tostring(rv_w))
local change = memory.alloc(32)
for i = 0, 28, 4 do memory.write_dword(change + i, 0) end
memory.write_qword(change, uint64(a))
memory.write_dword(change + 8, 0x0001FFFF) -- EV_ADD / EVFILT_READ
memory.write_qword(change + 24, uint64(0x12345678))
local events = memory.alloc(64)
for i = 0, 60, 4 do memory.write_dword(events + i, 0xA5A5A5A5) end
local timeout = memory.alloc(16)
for i = 0, 12, 4 do memory.write_dword(timeout + i, 0) end
local ok_k, rv_k = pcall(function()
    return sc(363)(uint64(kq), uint64(change), uint64(1), uint64(events), uint64(2), uint64(timeout))
end)
print("kevent ok=" .. tostring(ok_k) .. " ret=" .. tostring(rv_k))
if ok_k and num(rv_k) > 0 and num(rv_k) <= 2 then
    for i = 0, num(rv_k) - 1 do dump("event" .. i, events + i * 32) end
else
    dump("unchanged-or-error", events)
end
sc(6)(uint64(kq)); sc(6)(uint64(a)); sc(6)(uint64(b))
print("=== PROBE 85j COMPLETE ===")
