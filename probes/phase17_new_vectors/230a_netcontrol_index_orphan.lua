-- CRASH_CLASS: MODERATE
-- PROBE 230a: does one orphan kill an ordinary index
--
-- Context, clean boot, pid 80:
--   227a registered fd 22 on index -1 -> 0, registered and cleared it on
--        index 1 -> 0/0, then closed fd 22 while it was still registered on -1.
--   229a then found index -1 refusing every register (-1) while indexes 1 and 2
--        kept returning 0/0 for the next 44 seconds, and a type-B orphan on
--        index 1 (register, close, re-register the reclaimed number, clear it)
--        changed nothing.
--
-- So one orphan on -1 took -1 down immediately, and an index-1 orphan of the
-- other shape did not take index 1 down. What is missing is the ordinary case:
-- a type-A orphan on a normal interface index.
--
--   [A] index 3: register a socket, close it, no clear.
--   [B] immediately register a *second* socket on index 3. A -1 here means the
--       orphan took the queue itself, not just the dead entry.
--   [C] sample index 3 against index 2 every 4 seconds for half a minute.
--
-- One orphan is created, on index 3 only; indexes 1 and 2 are left alone.

print("=== PROBE 230a: does one orphan kill an ordinary index ===")
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
local T_IDX, C_IDX = 3, 2

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

print("[A] index 3, orphan: register a socket, close it, no clear")
local a = sock()
if a ~= nil and a >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(a), sgn(reg(T_IDX, a, SET_QUEUE))))
    local _, ac = call(6, a)
    print("    close -> " .. sgn(ac))
end
print("")

print("[B] index 3, a second socket right away")
local b = sock()
local b1, b2
if b ~= nil and b >= 0 and not dead then
    b1 = reg(T_IDX, b, SET_QUEUE)
    print(string.format("    fd %s register -> %s", sgn(b), sgn(b1)))
    if b1 == 0 then
        b2 = reg(T_IDX, b, CLEAR_QUEUE)
        print("    clear -> " .. sgn(b2))
    end
end
print("")

print("[C] sample index 3 against index 2")
local probes = {}
for _, idx in ipairs({ T_IDX, C_IDX }) do probes[idx] = sock() end
for i = 1, 9 do
    if dead then break end
    local out = {}
    for _, idx in ipairs({ T_IDX, C_IDX }) do
        local s = probes[idx]
        local r = (s ~= nil and s >= 0) and reg(idx, s, SET_QUEUE) or nil
        local c = nil
        if r == 0 then c = reg(idx, s, CLEAR_QUEUE) end
        out[#out + 1] = string.format("%d %s%s", idx, sgn(r), c ~= nil and ("/" .. sgn(c)) or "")
    end
    print(string.format("    t=%2ds  %s", (i - 1) * 4, table.concat(out, "   ")))
    if i < 9 then sleep1() sleep1() sleep1() sleep1() end
end
print("")
print("    pid -> " .. pid())
print("")
print("=== PROBE 230a COMPLETE ===")
