-- CRASH_CLASS: LOW
-- PROBE 227a: does the wedged default queue follow the process
--
-- Context: index -1 accepted netevent registrations in pid 232 (218a) and has
-- refused every one since 219a closed a registered descriptor and let another
-- socket reclaim the number: still -1 in pid 232 (221a), and still -1 in the
-- fresh loader pid 239 (222a, 223a, 224a, 226a [C]) while indexes 1, 2, 3 and 4
-- all work. That already suggests the state is not per process.
--
-- This probe is the measurement of that: register on -1, register on 1, in
-- whatever process this runs in. Run it before and after a kill, and the pair
-- says whether the wedge travels with the process or lives in the kernel.

print("=== PROBE 227a: is the -1 queue wedged across processes ===")
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

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then return nil, nil end
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
local _, s = call(97, 1, 1, 0)
if s ~= nil and s >= 0 then
    print(string.format("    fd %s index -1 register -> %s", sgn(s), sgn(reg(-1, s, SET_QUEUE))))
    print(string.format("    fd %s index  1 register -> %s", sgn(s), sgn(reg(1, s, SET_QUEUE))))
    print(string.format("    fd %s index  1 unregister -> %s", sgn(s), sgn(reg(1, s, CLEAR_QUEUE))))
    call(6, s)
end
print("=== PROBE 227a COMPLETE ===")
