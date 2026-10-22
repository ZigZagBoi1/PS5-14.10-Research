-- CRASH_CLASS: LOW
-- PROBE 233a: does a registered socket still exist after its descriptor closes
--
-- Context: 232a registered a socket on `ifindex -1`, closed it, and every later
-- register on -1 returned -1 - before and after 96 sockets plus 64 handle
-- objects refilled the slabs, with no fault. That does not separate "the queue
-- holds a reference to the socket" from "the queue holds a pointer into freed
-- memory": a socket reclaimed by another socket looks the same when it is read.
--
-- The connection state does separate them. Take a connected pair, register one
-- end, close that end, then read the other end without blocking:
--
--   peer reads 0 (EOF)  -> the registered end was destroyed by close, so the
--                          queue is holding a pointer to freed memory
--   peer reads EAGAIN   -> the registered end is still alive, so the queue is
--                          holding a reference and the whole line is a leak
--
--   [A] control: a pair with no registration, closed at one end. Must read 0.
--   [B] a pair whose registered end is closed, on index 1.
--   [C] the same on index 2.
--
-- -1 was taken down by 232a on this boot, so it cannot be measured until the
-- next one; if 1 and 2 both keep the socket alive, then a registration is a
-- reference and -1's behaviour is a leak rather than a dangling pointer.

print("=== PROBE 233a: reference or dangling, from the peer's side ===")
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
local RETLEN = memory.alloc(8)
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
local EAGAIN = 35

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
    -- socketpair(AF_UNIX, SOCK_STREAM, 0, sv)
    local sv = memory.alloc(16)
    wd(sv, 0)
    wd(sv + 4, 0)
    local _, r = call(135, 1, 1, 0, sv)
    if r ~= 0 then return nil, nil, sgn(r) end
    local a = to_num(memory.read_dword(sv))
    local b = to_num(memory.read_dword(sv + 4))
    return a, b
end
local function recv_now(fd)
    zero(RBUF, 0x10)
    zero(RETLEN, 8)
    local _, r = call(29, fd, RBUF, 1, MSG_DONTWAIT)
    local len = r
    return r, len
end

print("    pid " .. pid())
print("")

print("[A] control pair: close one end, read the other")
local ca, cb, err = pair()
if ca == nil then
    print("    socketpair failed: " .. tostring(err))
else
    print(string.format("    fds %s %s", sgn(ca), sgn(cb)))
    local _, cclose = call(6, ca)
    print("    close -> " .. sgn(cclose))
    local r, len = recv_now(cb)
    print(string.format("    read -> %s (EOF means 0)", sgn(r)))
    call(6, cb)
end
print("")

for _, idx in ipairs({ 1, 2 }) do
    if dead then break end
    print(string.format("[%s] pair, register one end on index %d, close it, read the other",
        idx == 1 and "B" or "C", idx))
    local a, b = pair()
    if a == nil then
        print("    socketpair failed")
    else
        print(string.format("    fds %s %s register -> %s", sgn(a), sgn(b), sgn(reg(idx, a, SET_QUEUE))))
        local _, pclose = call(6, a)
        print("    close -> " .. sgn(pclose))
        local r, len = recv_now(b)
        print(string.format("    read -> %s   (0 = refused, %d = still connected)",
            sgn(r), EAGAIN))
        call(6, b)
    end
    print("")
end

print("    pid -> " .. pid())
print("")
print("=== PROBE 233a COMPLETE ===")
