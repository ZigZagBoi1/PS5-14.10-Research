-- CRASH_CLASS: LOW
-- PROBE 231a: does a rejected register poison the socket it was called on
--
-- Context, clean boot, pid 80. Index -1 is refusing every register since 227a
-- closed a socket that was still registered on it, while indexes 1, 2 and 3
-- answer 0/0 - including right after a type-A orphan on index 3 (230a). So an
-- ordinary index survives the exact sequence that took -1 down.
--
-- But one earlier observation does not fit "only -1 breaks": in pid 239, 227a
-- called register on -1 with one socket, got -1, then called register on index 1
-- with the *same* socket and also got -1, one probe after index 1 had answered
-- 0. And 228a then got -1 on index 6 with a fresh socket.
--
-- This probe asks whether the failure sticks to the descriptor:
--
--   [A] index 2, socket A: register and clear. Expected 0/0.
--   [B] socket B: register on -1 (expected -1, it is the dead one), then
--       register on index 2. If the second call refuses, the socket is poisoned
--       by the first failure.
--   [C] socket C: register on index 2, then on -1, then on index 2 again.

print("=== PROBE 231a: does a rejected register poison the socket ===")
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
    if type(v) == "number" then
        if v < 0 then v = 0x100000000 + v end
        return uint64(string.format("0x%08X", v))
    end
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

local function pid()
    local _, v = call(20)
    return sgn(v)
end
local function reg(ifindex, fd, cmd)
    zero(BUF, 0x10)
    wd(BUF, fd)
    local _, v = call(99, ifindex, cmd, BUF, 8)
    return v
end
local function sock()
    local _, s = call(97, 1, 1, 0)
    return s
end

print("    pid " .. pid())
print("")

print("[A] control, index 2")
local a = sock()
if a ~= nil and a >= 0 and not dead then
    print(string.format("    fd %s register 2 -> %s", sgn(a), sgn(reg(2, a, SET_QUEUE))))
    print(string.format("    fd %s clear    2 -> %s", sgn(a), sgn(reg(2, a, CLEAR_QUEUE))))
end
print("")

print("[B] a socket that first fails on -1")
local b = sock()
if b ~= nil and b >= 0 and not dead then
    print(string.format("    fd %s register -1 -> %s", sgn(b), sgn(reg(-1, b, SET_QUEUE))))
    print(string.format("    fd %s register  2 -> %s", sgn(b), sgn(reg(2, b, SET_QUEUE))))
    print(string.format("    fd %s clear     2 -> %s", sgn(b), sgn(reg(2, b, CLEAR_QUEUE))))
    print(string.format("    fd %s register  2 again -> %s", sgn(b), sgn(reg(2, b, SET_QUEUE))))
    print(string.format("    fd %s clear     2 -> %s", sgn(b), sgn(reg(2, b, CLEAR_QUEUE))))
end
print("")

print("[C] a socket that succeeds first, then fails on -1")
local c = sock()
if c ~= nil and c >= 0 and not dead then
    print(string.format("    fd %s register 2 -> %s", sgn(c), sgn(reg(2, c, SET_QUEUE))))
    print(string.format("    fd %s register -1 while registered -> %s", sgn(c), sgn(reg(-1, c, SET_QUEUE))))
    print(string.format("    fd %s clear 2 -> %s", sgn(c), sgn(reg(2, c, CLEAR_QUEUE))))
    print(string.format("    fd %s register 2 again -> %s", sgn(c), sgn(reg(2, c, SET_QUEUE))))
end
print("    pid -> " .. pid())
print("")
print("=== PROBE 231a COMPLETE ===")
