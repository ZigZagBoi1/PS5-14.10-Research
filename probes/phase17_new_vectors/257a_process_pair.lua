-- CRASH_CLASS: HIGH
-- PROBE 257a: 560 debug_init, 561 suspend_process, 562 resume_process
--
-- None of these three has been called on 14.10. suspend_process and
-- resume_process are the only pair in the Sony range that names another process,
-- so they are the only calls that could act outside this one without a handle.
-- Self-suspend is deliberately not attempted: it parks the loader and cannot be
-- undone from inside the same Lua thread.
--
--   A  560 debug_init with a few shapes
--   B  561/562 on pid 0, 1, a large invalid pid, and this pid's neighbour
--   C  canary that this process still runs afterwards

print("=== PROBE 257a: debug_init and the process pair ===")
print("")

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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end

local me = pid()
print("[0] pid=" .. tostring(me))

print("")
print("[A] 560 debug_init")
local shapes = { { 0 }, { 1 }, { 0x10 }, { 0, 0x10 }, { 0x1000, 0x1000 } }
for i = 1, #shapes do
    local s = shapes[i]
    print(string.format("    560(%s) -> %-24s pid=%s",
        tostring(s[1]) .. (s[2] and (" ," .. tostring(s[2])) or ""),
        q(call(560, uint64(s[1]), s[2] and uint64(s[2]) or nil, nil, nil)),
        tostring(pid())))
end

print("")
print("[B] 561 suspend_process / 562 resume_process")
local targets = { 0, 1, 2, 0xFFFF, 0x7FFFFFFF }
for i = 1, #targets do
    local t = targets[i]
    local a = call(561, uint64(t), uint64(0), uint64(0))
    print(string.format("    561(%d) -> %-24s pid=%s", t, q(a), tostring(pid())))
    local b = call(562, uint64(t), uint64(0), uint64(0))
    print(string.format("    562(%d) -> %-24s pid=%s", t, q(b), tostring(pid())))
end
if me ~= nil then
    print("    562(self) -> " .. q(call(562, uint64(me), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
    print("    561(self) NOT attempted")
end

print("")
print("[C] canary")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 257a COMPLETE ===")
