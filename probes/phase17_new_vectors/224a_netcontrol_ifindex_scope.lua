-- CRASH_CLASS: LOW
-- PROBE 224a: netcontrol, is a specific interface poisoned
--
-- Context: pid 232 registered fd 28, closed it while registered, and unregister
-- returned -1. Every later netevent call in that process failed (221a), the
-- process was killed, and in the fresh loader pid 239 every register on every
-- descriptor - AF_UNIX 22..25, AF_INET 26, and 32 more in a scan - still
-- returns -1 (222a, 223a).
--
-- Every one of those calls used ifindex = -1, because that is what the public
-- ABI uses. If the failure is an interface-scoped state rather than a global
-- one, another index would still work. This probe walks the index and stops at
-- the first one that accepts a register, then clears it, so at most one
-- interface is left registered per run.

print("=== PROBE 224a: is one interface poisoned ===")
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

print("    pid " .. pid())
print("")

local _, sock = call(97, 1, 1, 0)
print("    socket -> " .. sgn(sock))
print("")

print("[A] ifindex -1, then 0 through 10: does any accept a register")
local accepted = nil
local indices = { -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }
for _, idx in ipairs(indices) do
    if dead then break end
    local r = reg(idx, sock, SET_QUEUE)
    print(string.format("    ifindex %3d register -> %s", idx, sgn(r)))
    if r == 0 then accepted = idx break end
end
print("")

print("[B] if one was accepted, clear it and leave the queue as we found it")
if accepted ~= nil then
    print(string.format("    ifindex %d unregister -> %s", accepted, sgn(reg(accepted, sock, CLEAR_QUEUE))))
else
    print("    none accepted")
end
print("    pid -> " .. pid())
print("")
print("=== PROBE 224a COMPLETE ===")
