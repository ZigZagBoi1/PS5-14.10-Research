-- CRASH_CLASS: LOW
-- PROBE 177d: do the opmc handlers keep state?
--
-- 177c showed the value surface: 563 (enable) and 564 (disable) return 0 for
-- every second argument including 0xFFFFFFFF, and 565/566 accept the small set
-- {0,1,2,3,4} (566 also accepts 0xFFFFFFFF). That is either an enum check in a
-- handler that does real work, or a stub that only checks argument one.
--
-- The difference is observable without touching an MSR: a handler that keeps
-- state answers differently the second time. This probe calls each in a fixed
-- order and prints every return value, so a transition (enable twice, disable
-- twice, interleaved) shows up as a changed return rather than as an absence of
-- evidence. Return values are the whole signal here - nothing is written to a
-- buffer and nothing here can be read any other way.

print("=== PROBE 177d: OPMC STATE ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local S = {enable = make_syscall(563), disable = make_syscall(564),
           set_ctl = make_syscall(565), set_ctr = make_syscall(566),
           get_ctr = make_syscall(567), getpid = make_syscall(20)}

local function call(label, name, a1, a2)
    local ok, rv = pcall(function()
        return S[name](uint64(a1 or 0), uint64(a2 or 0), uint64(0),
                       uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    print(string.format("  %-28s ret=0x%08X%08X", label, hi, lo))
    return lo
end

print("[0] canary pid=" .. tostring(to_num(S.getpid())))

print("[1] enable twice, then disable twice")
call("enable(0,0) #1", "enable", 0, 0)
call("enable(0,0) #2", "enable", 0, 0)
call("enable(0,0) #3", "enable", 0, 0)
call("get_ctr(0,0)", "get_ctr", 0, 0)
call("disable(0,0) #1", "disable", 0, 0)
call("disable(0,0) #2", "disable", 0, 0)
call("enable(0,0) #4", "enable", 0, 0)

print("[2] control after enable")
call("set_ctl(0,1)", "set_ctl", 0, 1)
call("set_ctr(0,1)", "set_ctr", 0, 1)
call("get_ctr(0,0)", "get_ctr", 0, 0)
call("disable(0,0) #3", "disable", 0, 0)

print("[3] does an argument-one value other than 0 ever work?")
for _, v in ipairs({0x10000, 0x100000, 0x400000, 0x800000}) do
    call(string.format("set_ctr(0x%X,1)", v), "set_ctr", v, 1)
end
call("get_ctr(0x10000,0)", "get_ctr", 0x10000, 0)

print("[3] canary pid=" .. tostring(to_num(S.getpid())))
print("=== PROBE 177d DONE ===")
