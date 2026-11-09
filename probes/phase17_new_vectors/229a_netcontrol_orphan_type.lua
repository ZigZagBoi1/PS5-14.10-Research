-- CRASH_CLASS: MODERATE
-- PROBE 229a: which orphan kills the queue, and how long it takes
--
-- Context, all from one boot before the power cycle: index -1 accepted
-- registrations in pid 232, then refused them from 219a onwards, and it was
-- still refusing in a later loader pid 239 while indexes 1-4 still worked. Two
-- probes later every index refused, with 227a and 228a both dead on arrival.
-- The power cycle cleared it: pid 80 answers 0 on index -1 again (227a).
--
-- Two different orphan sequences were used on that boot and only one of them
-- preceded the collapse by more than a few calls:
--
--   type A (219a, 225a):  register, close, clear the dead descriptor number
--   type B (226a):        register, close, re-register the reclaimed number,
--                         then clear it - so a clear succeeds on a number whose
--                         earlier entry was orphaned
--
-- Type B is the suspect: a clear that succeeds on a reused descriptor may be
-- unlinking the orphaned entry's memory. This probe runs one of each on
-- separate indexes on a clean boot and then samples both, plus an untouched
-- control index, every 4 seconds.
--
-- No sample closes a registered descriptor, so the probe cannot create an
-- orphan while it measures.

print("=== PROBE 229a: which orphan kills the queue ===")
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
local A_IDX, B_IDX, C_IDX = -1, 1, 2

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
local function sleep1()
    local ts = memory.alloc(16)
    wd(ts, 1)
    wd(ts + 8, 0)
    call(240, ts, 0)
end

print("    pid " .. pid())
print("")

print("[A] baseline on the three indexes")
local base = {}
for _, idx in ipairs({ A_IDX, B_IDX, C_IDX }) do
    local s = sock()
    local r = s and reg(idx, s, SET_QUEUE)
    local c = (r == 0) and reg(idx, s, CLEAR_QUEUE) or nil
    print(string.format("    index %2d register %s%s", idx, sgn(r),
        c ~= nil and (" clear " .. sgn(c)) or ""))
    base[idx] = (r == 0 and c == 0)
    if s then call(6, s) end
end
print("")

print("[B] index -1, type A: register, close, clear the dead number")
local a = sock()
if a ~= nil and a >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(a), sgn(reg(A_IDX, a, SET_QUEUE))))
    local _, ac = call(6, a)
    print("    close -> " .. sgn(ac))
    print("    clear  -> " .. sgn(reg(A_IDX, a, CLEAR_QUEUE)))
end
print("")

print("[C] index 1, type B: register, close, re-register the reclaimed number, clear it")
local b = sock()
if b ~= nil and b >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(b), sgn(reg(B_IDX, b, SET_QUEUE))))
    local _, bc = call(6, b)
    print("    close -> " .. sgn(bc))
    local b2 = sock()
    print(string.format("    reclaimed fd %s (same number: %s)", sgn(b2), tostring(b2 == b)))
    if b2 ~= nil and b2 >= 0 then
        print("    register -> " .. sgn(reg(B_IDX, b2, SET_QUEUE)))
        print("    clear    -> " .. sgn(reg(B_IDX, b2, CLEAR_QUEUE)))
    end
end
print("")

print("[D] sample the three indexes every 4 seconds")
local probes = {}
for _, idx in ipairs({ A_IDX, B_IDX, C_IDX }) do probes[idx] = sock() end
for i = 1, 12 do
    if dead then break end
    local out = {}
    for _, idx in ipairs({ A_IDX, B_IDX, C_IDX }) do
        local s = probes[idx]
        local r = (s ~= nil and s >= 0) and reg(idx, s, SET_QUEUE) or nil
        local c = nil
        if r == 0 then c = reg(idx, s, CLEAR_QUEUE) end
        out[#out + 1] = string.format("%2d %s%s", idx, sgn(r),
            c ~= nil and ("/" .. sgn(c)) or "")
    end
    print(string.format("    t=%2ds  %s", (i - 1) * 4, table.concat(out, "   ")))
    if i < 12 then sleep1() sleep1() sleep1() sleep1() end
end
print("")
print("    pid -> " .. pid())
print("")
print("=== PROBE 229a COMPLETE ===")
