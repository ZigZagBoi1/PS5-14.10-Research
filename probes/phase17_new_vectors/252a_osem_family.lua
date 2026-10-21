-- CRASH_CLASS: HIGH
-- PROBE 252a: the osem family, the one object set shaped exactly like evf
--
-- 549 osem_create .. 556 osem_cancel is a second handle-based object family
-- with its own create/delete/wait/post/cancel, and none of it has been called
-- on 14.10. The evf family turned out to hold one waiter and to check the object
-- class, so the interesting question here is whether this one is built the same
-- way or is the older, less careful implementation.
--
-- The create ABI is unknown, so section A sweeps argument shapes and reports
-- every return. A return in the handle range (a small non-zero value below
-- 0x100000) is taken as an object and section B runs the lifecycle on it.
--
--   A  549(shapes) - find the create shape that yields a handle
--   B  555 post, 554 trywait, 553 wait, 556 cancel, 550 delete on that handle
--   C  controls: delete twice, wait on a deleted handle, wait on 0xDEAD

print("=== PROBE 252a: osem family ===")
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
local function num(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return n
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
print("[0] canary pid=" .. tostring(pid()))

print("")
print("[A] 549 osem_create")
local H = nil
local shapes = {
    { "549(0)",        { 0 } },
    { "549(1)",        { 1 } },
    { "549(2)",        { 2 } },
    { "549(0x10)",     { 0x10 } },
    { "549(0,0)",      { 0, 0 } },
    { "549(1,0)",      { 1, 0 } },
    { "549(0,1)",      { 0, 1 } },
    { "549(0x10,0,0)", { 0x10, 0, 0 } },
}
for i = 1, #shapes do
    local a = shapes[i][2]
    local rv = call(549, a[1] and uint64(a[1]) or nil, a[2] and uint64(a[2]) or nil, a[3] and uint64(a[3]) or nil)
    local n = rv ~= nil and num(rv) or 0
    print(string.format("    %-16s -> %-22s pid=%s", shapes[i][1], q(rv), tostring(pid())))
    if H == nil and rv ~= nil and n > 0 and n < 0x100000 then H = n end
end

print("")
if H == nil then
    print("[B] no handle from any shape; the family is refused or needs a name")
else
    print("[B] lifecycle on handle " .. string.format("0x%X", H))
    print("    555 post(H)      -> " .. q(call(555, uint64(H), uint64(0), uint64(0))))
    print("    554 trywait(H)   -> " .. q(call(554, uint64(H), uint64(0), uint64(0))))
    print("    553 wait(H,0)    -> " .. q(call(553, uint64(H), uint64(0), uint64(0))))
    print("    556 cancel(H)    -> " .. q(call(556, uint64(H), uint64(0), uint64(0))))
    print("    550 delete(H)    -> " .. q(call(550, uint64(H), uint64(0), uint64(0))))
    print("    pid -> " .. tostring(pid()))
    print("")
    print("[C] controls")
    print("    550 delete(H) again -> " .. q(call(550, uint64(H), uint64(0), uint64(0))))
    print("    553 wait(deleted H) -> " .. q(call(553, uint64(H), uint64(0), uint64(0))))
    print("    553 wait(0xDEAD)    -> " .. q(call(553, uint64(0xDEAD), uint64(0), uint64(0))))
    print("    549 fresh           -> " .. q(call(549, uint64(0), uint64(0), uint64(0))))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 252a COMPLETE ===")
