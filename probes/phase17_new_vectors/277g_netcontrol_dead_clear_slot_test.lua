-- CRASH_CLASS: LOW
-- Distinguish a failed CLEAR_QUEUE on a closed fd from queue-slot exhaustion.
-- One registration is orphaned at most; no loop or spray.

print("=== PROBE 277g: dead-fd CLEAR and slot reuse ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u64(v)
    if type(v) == "number" then
        if v < 0 then v = 0x100000000 + v end
        return uint64(string.format("0x%08X", v))
    end
    return v or uint64("0x00000000")
end
local function call(n, ...)
    local a = {...}
    local ok, rv = pcall(function()
        return sc(n)(u64(a[1]), u64(a[2]), u64(a[3]), u64(a[4]), u64(a[5]), u64(a[6]))
    end)
    if not ok then print("syscall_error n=" .. tostring(n) .. " err=" .. tostring(rv)); return nil end
    return num(rv)
end
local function wd(p, v) memory.write_dword(p, v) end
local sv = memory.alloc(8)
local opt = memory.alloc(8)
local data = memory.alloc(8)
local function pair()
    wd(sv, 0); wd(sv + 4, 0)
    if call(135, 1, 1, 0, sv) ~= 0 then return nil, nil end
    return num(memory.read_dword(sv)), num(memory.read_dword(sv + 4))
end
local function net(idx, cmd, fd)
    wd(opt, fd); wd(opt + 4, 0)
    return call(99, idx, cmd, opt, 8)
end
local SET, CLEAR = 0x20000003, 0x20000007
local function peer(fd)
    return call(29, fd, data, 1, 0x80, 0, 0)
end
local function close(fd) return call(6, fd) end

print("pid=" .. tostring(call(20)))
local idx
for i = 1, 4 do
    local a, b = pair()
    if not a then print("ABORT pair in scan"); return end
    local s = net(i, SET, a)
    local c = s == 0 and net(i, CLEAR, a) or nil
    print("scan idx=" .. i .. " set=" .. tostring(s) .. " clear=" .. tostring(c))
    close(a); close(b)
    if s == 0 and c == 0 then idx = i; break end
end
if not idx then print("ABORT no clean slot"); return end

local a, b = pair()
if not a then print("ABORT pair"); return end
print("target idx=" .. idx .. " a=" .. a .. " b=" .. b)
local sr = net(idx, SET, a)
print("set_original=" .. tostring(sr))
if sr ~= 0 then close(a); close(b); return end
print("close_original=" .. tostring(close(a)))
print("peer_before_clear=" .. tostring(peer(b)))
local dead_clear = net(idx, CLEAR, a) -- no fd allocated between close and this call
print("clear_dead_fd=" .. tostring(dead_clear))
print("peer_after_clear=" .. tostring(peer(b)))

local c, d = pair()
if not c then close(b); print("ABORT replacement pair"); return end
print("replacement c=" .. c .. " d=" .. d)
local replace = net(idx, SET, c)
print("set_after_dead_clear=" .. tostring(replace))
print("old_peer_after_replacement=" .. tostring(peer(b)))
if replace == 0 then print("clear_replacement=" .. tostring(net(idx, CLEAR, c))) end
print("close_replacement=" .. tostring(close(c)) .. " close_peer=" .. tostring(close(d)))
print("old_peer_final=" .. tostring(peer(b)))
close(b)
print("canary_pid=" .. tostring(call(20)))
print("=== PROBE 277g COMPLETE ===")
