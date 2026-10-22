-- CRASH_CLASS: MODERATE
-- PROBE 228a: how long after the orphan does the queue stop accepting registers
--
-- Context: 225a [B] on interface index 1 registered fd 60, closed it and got
-- -1 from the unregister. Immediately afterwards 225a [C] registered another
-- socket on the *same* index and it returned 0. Two probes later, 227a found
-- index 1 refusing every register with -1, minutes after the orphan was made and
-- with no netcontrol call in between.
--
-- So the refusal is not the orphan being noticed at register time; it arrives
-- later. This probe measures when:
--
--   [A] index 6 control, so the run starts on a queue that works.
--   [B] index 6: register a socket, close it, and never clear it - the orphan.
--   [C] then every 4 seconds for about a minute, register and clear a second
--       socket on index 6, printing the first sample that refuses.
--   [D] index 7, untouched, to show whether the effect is per index.
--
-- The samples never close a registered socket, so this probe creates at most
-- one orphan and cannot re-trigger the fault on the queue it is measuring.

print("=== PROBE 228a: when the queue starts refusing ===")
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
local function sleep1()
    -- struct timespec: tv_sec at +0, tv_nsec at +8
    local ts = memory.alloc(16)
    wd(ts, 1)
    wd(ts + 8, 0)
    call(240, ts, 0)
end

local INDEX = 6
print("    pid " .. pid())
print("")

print("[A] control on index 6")
local a = sock()
if a ~= nil and a >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(a), sgn(reg(INDEX, a, SET_QUEUE))))
    print(string.format("    fd %s unregister -> %s", sgn(a), sgn(reg(INDEX, a, CLEAR_QUEUE))))
    call(6, a)
end
print("")

print("[B] orphan: register, close, never clear")
local b = sock()
if b ~= nil and b >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(b), sgn(reg(INDEX, b, SET_QUEUE))))
    local _, bc = call(6, b)
    print("    close -> " .. sgn(bc))
end
print("")

print("[C] register and clear a second socket every 4 seconds")
local s = sock()
local first_refusal = nil
if s ~= nil and s >= 0 then
    for i = 1, 15 do
        if dead then break end
        local r = reg(INDEX, s, SET_QUEUE)
        local c = nil
        if r == 0 then c = reg(INDEX, s, CLEAR_QUEUE) end
        print(string.format("    t=%2ds register %s%s", (i - 1) * 4, sgn(r),
            c ~= nil and (" clear " .. sgn(c)) or ""))
        if r ~= 0 and first_refusal == nil then first_refusal = (i - 1) * 4 end
        if i < 15 then sleep1() sleep1() sleep1() sleep1() end
    end
end
print("    first refusal at " .. (first_refusal and (first_refusal .. "s") or "none"))
print("")

print("[D] index 7, untouched")
local d = sock()
if d ~= nil and d >= 0 and not dead then
    print(string.format("    fd %s register -> %s", sgn(d), sgn(reg(7, d, SET_QUEUE))))
    print(string.format("    fd %s unregister -> %s", sgn(d), sgn(reg(7, d, CLEAR_QUEUE))))
end
print("    pid -> " .. pid())
print("")
print("=== PROBE 228a COMPLETE ===")
