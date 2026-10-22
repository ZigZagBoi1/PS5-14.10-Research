-- CRASH_CLASS: LOW
-- PROBE 223a: netcontrol, is the queue per process or global
--
-- Context: 219a registered fd 28, closed it while registered and unregistered
-- -> -1. From then on every netcontrol call in that process (pid 232) returned
-- -1 (221a). That process was then killed with an absent syscall and the game
-- went down; after a relaunch the loader runs as pid 239.
--
-- 222a ran first on pid 239 and its *control* register on a freshly opened
-- descriptor already returned -1, which a per-process queue cannot explain.
-- Either the queue is global to the kernel (the entry outlived the process that
-- created it) or something about that descriptor made it unacceptable.
--
-- This probe separates those without ever closing a registered descriptor:
--
--   [A] the same call on a fresh descriptor, repeated on several numbers
--   [B] the same call on an AF_INET socket, in case the domain matters
--   [C] a scan over many descriptor numbers, looking for any that is accepted
--
-- Nothing here closes a descriptor that registered, so it cannot create a new
-- orphan; a queue that is already wedged by 219a stays wedged.

print("=== PROBE 223a: is the netevent queue per process or global ===")
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

print("    pid " .. pid())
print("")

print("[A] AF_UNIX sockets, register each open one")
local fds = {}
for i = 1, 4 do
    local _, s = call(97, 1, 1, 0)
    fds[i] = s
    if s ~= nil and s >= 0 and not dead then
        print(string.format("    fd %s register -> %s", sgn(s), sgn(reg(s, SET_QUEUE))))
    end
end
print("")

print("[B] AF_INET socket")
local _, inet = call(97, 2, 1, 0)
if inet ~= nil and inet >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(inet), sgn(reg(inet, SET_QUEUE))))
end
print("")

print("[C] scan: 32 sockets, register the first one that is accepted")
local hits = 0
for i = 1, 32 do
    if dead then break end
    local _, s = call(97, 1, 1, 0)
    if s ~= nil and s >= 0 then
        local r = reg(s, SET_QUEUE)
        if r == 0 then
            hits = hits + 1
            print(string.format("    fd %s accepted", sgn(s)))
            -- leave it registered: no close, no clear
        end
    end
end
print("    accepted descriptors: " .. hits)
print("    pid -> " .. pid())
print("")
print("=== PROBE 223a COMPLETE ===")
