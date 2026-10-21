-- CRASH_CLASS: MODERATE
-- PROBE 218a: netcontrol (99) accepts the netevent commands?
--
-- Context: syscall 99 is `netcontrol` in the 13.60 name table (handler
-- 0x265950) and the presence sweep recorded it present, returning -1 for six
-- zero arguments. That is the only check ever made against it, although
-- netcontrol is where the scene's only public PS5 kernel exploit lives: Poops
-- (Gezine/egycnq) drives __sys_netcontrol's netevent queue to free a file and
-- its ucred, then reclaims the fd. The public ABI, from TheFlow's
-- ExploitNetControlImpl, is
--
--     __sys_netcontrol(ifindex, cmd, buf, size)
--     ifindex = -1 for the netevent commands
--     cmd 0x20000003 registers the socket in buf[0]
--     cmd 0x20000007 unregisters the socket in buf[0]
--
-- and both take an 8-byte buffer with the fd as an int at +0.
--
-- This probe only asks whether 14.10 still accepts those two commands and
-- what it returns. It never closes a socket before unregistering it, so the
-- use-after-free the public chain relies on is not touched: every register is
-- followed by an unregister on the same open descriptor.

print("=== PROBE 218a: netcontrol ABI ===")
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

local BUF = memory.alloc(0x40)
local function zero(addr, n)
    for i = 0, n - 1, 4 do
        pcall(function() memory.write_dword(addr + i, 0) end)
    end
end
local function wd(addr, v)
    local ok = pcall(function() memory.write_dword(addr, v) end)
    return ok
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return nil
end

local SET_QUEUE = 0x20000003
local CLEAR_QUEUE = 0x20000007
local RETIRED = 0xFFFFFFFF

print("[A] baseline, six zero arguments and the documented ifindex")
zero(BUF, 0x40)
local _, a1 = call(99)
print("    (0,0,0,0,0,0)                       -> " .. sgn(a1))
local _, a2 = call(99, RETIRED, SET_QUEUE, BUF, 8)
print("    (-1, SET_QUEUE, buf, 8) zeroed buf   -> " .. sgn(a2))
print("")

print("[B] one register/unregister pair on an open AF_UNIX socket")
local _, sfd = call(97, 1, 1, 0)
print("    socket(AF_UNIX, SOCK_STREAM) -> " .. sgn(sfd))
if sfd ~= nil and sfd >= 0 then
    wd(BUF, sfd)
    print("    buf[0] = " .. tostring(rd(BUF)))
    local _, b1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
    print("    register   -> " .. sgn(b1))
    if not dead then
        local _, b2 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print("    unregister -> " .. sgn(b2))
    end
    if not dead then
        local _, b3 = call(99, RETIRED, SET_QUEUE, BUF, 8)
        print("    register again -> " .. sgn(b3))
        local _, b4 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print("    unregister again -> " .. sgn(b4))
    end
    local _, bc = call(6, sfd)
    print("    close(" .. tostring(sfd) .. ") -> " .. sgn(bc))
end
print("")

print("[C] three fresh sockets, register then unregister each")
for i = 1, 3 do
    if dead then break end
    local _, fd = call(97, 1, 1, 0)
    if fd == nil or fd < 0 then
        print(string.format("    round %d: socket -> %s", i, sgn(fd)))
    else
        zero(BUF, 0x10)
        wd(BUF, fd)
        local _, r1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
        local _, r2 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print(string.format("    round %d: fd %s  register %s  unregister %s",
            i, sgn(fd), sgn(r1), sgn(r2)))
        call(6, fd)
    end
end
print("")

print("[D] the same commands with descriptors that cannot be registered")
zero(BUF, 0x10)
wd(BUF, 0xFFFF)
local _, d1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
print("    fd 0xFFFF register   -> " .. sgn(d1))
local _, d2 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
print("    fd 0xFFFF unregister -> " .. sgn(d2))
wd(BUF, 0)
local _, d3 = call(99, RETIRED, SET_QUEUE, BUF, 8)
print("    fd 0 register        -> " .. sgn(d3))
local _, d4 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
print("    fd 0 unregister      -> " .. sgn(d4))
print("")

print("[E] the command space around the two documented values")
local _, efd = call(97, 1, 1, 0)
if efd ~= nil and efd >= 0 then
    zero(BUF, 0x10)
    wd(BUF, efd)
    print("    holding fd " .. sgn(efd))
    for cmd = 0x20000000, 0x2000000F do
        if dead then break end
        local _, r = call(99, RETIRED, cmd, BUF, 8)
        print(string.format("    cmd 0x%08X -> %s", cmd, sgn(r)))
    end
    call(6, efd)
else
    print("    no socket: " .. sgn(efd))
end
print("")

print("[F] size and buffer variations on SET_QUEUE")
local _, ffd = call(97, 1, 1, 0)
if ffd ~= nil and ffd >= 0 then
    zero(BUF, 0x20)
    wd(BUF, ffd)
    for _, size in ipairs({ 0, 4, 8, 16, 0x40 }) do
        if dead then break end
        local _, r = call(99, RETIRED, SET_QUEUE, BUF, size)
        print(string.format("    size %-3d -> %s", size, sgn(r)))
        if not dead then call(99, RETIRED, CLEAR_QUEUE, BUF, size) end
    end
    if not dead then
        local _, r = call(99, RETIRED, SET_QUEUE, 0, 8)
        print("    buf NULL, size 8 -> " .. sgn(r))
    end
    call(6, ffd)
end
print("")
print("=== PROBE 218a COMPLETE ===")
