-- CRASH_CLASS: LOW
-- PROBE 234a: does a registration hold the socket, and does the unregister release it
--
-- Context: 233a took a connected socketpair, registered one end on `ifindex 1`,
-- closed that end, and read the other end without blocking. The control pair
-- with no registration read 0 - an immediate EOF - while the registered pair
-- read -1, the non-blocking "nothing to read" answer, which is only possible if
-- the peer connection is still open. So closing a registered descriptor does
-- not destroy the socket: the netevent queue is holding a reference to it.
--
-- That explains every earlier result. The queue has one owner, the owner cannot
-- be released once its descriptor is gone, and so `ifindex -1` - the queue the
-- public ABI uses - refuses every later register for the rest of the boot, in
-- every process, which is what 219a/221a/227a measured.
--
-- What is left is whether that is the shape of every registration or only of
-- the ones that were never unregistered:
--
--   [A] register, close, read the peer          - reproduces 233a (-1)
--   [B] register, unregister, close, read peer  - 0 means the unregister did
--       drop the reference, so a clean register is a clean release
--   [C] register, close, unregister the dead number, read the peer - shows
--       whether the failed unregister in the trigger order releases anything

print("=== PROBE 234a: does the unregister release the socket ===")
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
local RBUF = memory.alloc(0x20)
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
local MSG_DONTWAIT = 0x80
local INDEX = 3

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
local function pair()
    local sv = memory.alloc(16)
    wd(sv, 0)
    wd(sv + 4, 0)
    local _, r = call(135, 1, 1, 0, sv)
    if r ~= 0 then return nil, nil end
    return to_num(memory.read_dword(sv)), to_num(memory.read_dword(sv + 4))
end
local function recv_now(fd)
    zero(RBUF, 0x10)
    local _, r = call(29, fd, RBUF, 1, MSG_DONTWAIT)
    return r
end
local function peer_state(fd, label)
    print(string.format("    %-28s read -> %s", label, sgn(recv_now(fd))))
end

print("    pid " .. pid())
print("")

print("[A] register, close, read the peer")
local a1, a2 = pair()
if a1 then
    print(string.format("    register -> %s", sgn(reg(INDEX, a1, SET_QUEUE))))
    local _, ac = call(6, a1)
    print("    close -> " .. sgn(ac))
    peer_state(a2, "peer of closed end")
    call(6, a2)
end
print("")

print("[B] register, unregister, close, read the peer")
local b1, b2 = pair()
if b1 then
    print(string.format("    register -> %s  unregister -> %s",
        sgn(reg(INDEX, b1, SET_QUEUE)), sgn(reg(INDEX, b1, CLEAR_QUEUE))))
    local _, bc = call(6, b1)
    print("    close -> " .. sgn(bc))
    peer_state(b2, "peer of closed end")
    call(6, b2)
end
print("")

print("[C] register, close, unregister the dead number, read the peer")
local c1, c2 = pair()
if c1 then
    print(string.format("    register -> %s", sgn(reg(INDEX, c1, SET_QUEUE))))
    local _, cc = call(6, c1)
    print("    close -> " .. sgn(cc))
    print(string.format("    unregister -> %s", sgn(reg(INDEX, c1, CLEAR_QUEUE))))
    peer_state(c2, "peer of closed end")
    call(6, c2)
end
print("")
print("    pid -> " .. pid())
print("")
print("=== PROBE 234a COMPLETE ===")
