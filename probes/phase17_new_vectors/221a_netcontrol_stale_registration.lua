-- CRASH_CLASS: LOW
-- PROBE 221a: netcontrol, what a failed unregister leaves behind
--
-- Context: 219a registered fd 28, closed it while registered, reclaimed 28
-- with a new socket, and its unregister returned -1. 220a then ran in the same
-- process (pid 232) and found that a *plain* register on a freshly opened fd 28
-- also returns -1, in all three sections, while the control in 218a and 219a had
-- returned 0 for the same shape.
--
-- So the failed unregister left something behind that keeps fd 28 from being
-- registered again. Two readings:
--
--   a) the queue is keyed by descriptor number and the entry was never removed,
--      so a later register on the same number reports EEXIST
--   b) the queue was globally full, or some earlier register never came out
--
-- This probe separates them without closing anything while it is registered:
-- it registers three other numbers, unregisters them, then walks fd 28 back.
-- A number that is not 28 answering 0 rules out (b) for a full queue.

print("=== PROBE 221a: netcontrol stale registration ===")
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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function sgn(v)
    if v == nil then return "killed" end
    if v >= 0x80000000 then return tostring(v - 0x100000000) end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local BUF = memory.alloc(0x20)
local function zero(addr, n)
    for i = 0, n - 1, 4 do
        pcall(function() memory.write_dword(addr + i, 0) end)
    end
end
local function wd(addr, v)
    return (pcall(function() memory.write_dword(addr, v) end))
end

local SET_QUEUE = 0x20000003
local CLEAR_QUEUE = 0x20000007
local RETIRED = 0xFFFFFFFF

local function pid()
    local _, v = call(20)
    return sgn(v)
end

local function reg(fd, cmd)
    zero(BUF, 0x10)
    wd(BUF, fd)
    local _, v = call(99, RETIRED, cmd, BUF, 8)
    return v
end

print("[A] pid " .. pid() .. ", three fresh descriptors")
local fd = {}
for i = 1, 3 do
    local _, s = call(97, 1, 1, 0)
    fd[i] = s
    print(string.format("    socket %d -> %s", i, sgn(s)))
end
for i = 1, 3 do
    if not dead and fd[i] ~= nil and fd[i] >= 0 then
        local r = reg(fd[i], SET_QUEUE)
        print(string.format("    register %s -> %s", sgn(fd[i]), sgn(r)))
    end
end
print("")

print("[B] unregister them, then register again")
for i = 1, 3 do
    if not dead and fd[i] ~= nil and fd[i] >= 0 then
        local r = reg(fd[i], CLEAR_QUEUE)
        print(string.format("    unregister %s -> %s", sgn(fd[i]), sgn(r)))
    end
end
for i = 1, 3 do
    if not dead and fd[i] ~= nil and fd[i] >= 0 then
        local r = reg(fd[i], SET_QUEUE)
        print(string.format("    register %s again -> %s", sgn(fd[i]), sgn(r)))
        if r == 0 then reg(fd[i], CLEAR_QUEUE) end
    end
end
print("")

print("[C] walk fd 28, the number that failed in 220a")
local _, s28 = call(97, 1, 1, 0)
print("    fresh socket -> " .. sgn(s28))
if s28 ~= nil and s28 >= 0 then
    print("    register -> " .. sgn(reg(s28, SET_QUEUE)))
    print("    unregister -> " .. sgn(reg(s28, CLEAR_QUEUE)))
    print("    unregister again -> " .. sgn(reg(s28, CLEAR_QUEUE)))
    print("    register again -> " .. sgn(reg(s28, SET_QUEUE)))
    print("    pid -> " .. pid())
    local _, c = call(6, s28)
    print("    close -> " .. sgn(c))
end
print("")

print("[D] does a closed descriptor number come back registrable")
local _, d1 = call(97, 1, 1, 0)
if d1 ~= nil and d1 >= 0 then
    print("    socket " .. sgn(d1) .. " register -> " .. sgn(reg(d1, SET_QUEUE)))
    local _, dc = call(6, d1)
    print("    close -> " .. sgn(dc))
    local _, d2 = call(97, 1, 1, 0)
    print("    socket " .. sgn(d2) .. " (same number: " ..
        tostring(d2 == d1) .. ") register -> " .. sgn(reg(d2, SET_QUEUE)))
    if d2 ~= nil and d2 >= 0 then
        print("    unregister -> " .. sgn(reg(d2, CLEAR_QUEUE)))
        call(6, d2)
    end
end
print("")
print("=== PROBE 221a COMPLETE ===")
