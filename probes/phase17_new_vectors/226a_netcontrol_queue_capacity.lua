-- CRASH_CLASS: LOW
-- PROBE 226a: netcontrol, one entry per queue or many
--
-- Context: 225a on a clean interface index 1: register an open fd -> 0, close
-- it, unregister the closed number -> -1, and afterwards the same index still
-- accepted a register on the *same* descriptor number, and index 2 accepted one
-- too. 219a instead closed fd 28 and let a new socket reclaim 28 *before* the
-- unregister; from then on index -1 refused every register, in that process and
-- in the next one (222a, 223a, 224a).
--
-- So two different sequences both end in `-1`, with different aftermaths. The
-- difference is whether the descriptor number was reused before the unregister.
-- This probe asks the two questions that separate a leak from a lookup failure:
--
--   [A] can one interface hold two registrations at once?
--   [B] does closing a registered descriptor remove its entry, with no reclaim
--       and no unregister in between?
--   [C] is index -1 still refusing every register?

print("=== PROBE 226a: netcontrol queue capacity ===")
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

print("[A] index 3: two open descriptors registered at once")
local a = sock()
local b = sock()
print(string.format("    fds %s %s", sgn(a), sgn(b)))
if a ~= nil and b ~= nil and not dead then
    print(string.format("    register %s -> %s", sgn(a), sgn(reg(3, a, SET_QUEUE))))
    print(string.format("    register %s -> %s", sgn(b), sgn(reg(3, b, SET_QUEUE))))
    print(string.format("    unregister %s -> %s", sgn(a), sgn(reg(3, a, CLEAR_QUEUE))))
    print(string.format("    unregister %s -> %s", sgn(b), sgn(reg(3, b, CLEAR_QUEUE))))
end
print("")

print("[B] index 4: register, close, and register again with no unregister")
local c = sock()
if c ~= nil and c >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(c), sgn(reg(4, c, SET_QUEUE))))
    local _, cc = call(6, c)
    print("    close -> " .. sgn(cc))
    local d = sock()
    print(string.format("    new fd %s register -> %s", sgn(d), sgn(reg(4, d, SET_QUEUE))))
    if d ~= nil and d >= 0 then
        print(string.format("    unregister %s -> %s", sgn(d), sgn(reg(4, d, CLEAR_QUEUE))))
    end
end
print("")

print("[C] index -1, the one 219a wedged")
local e = sock()
if e ~= nil and e >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(e), sgn(reg(-1, e, SET_QUEUE))))
end
print("    pid -> " .. pid())
print("")
print("=== PROBE 226a COMPLETE ===")
