-- CRASH_CLASS: MODERATE
-- PROBE 195a: evf mask/mode matrix and the wait signature
--
-- Context: 194a found exactly one shape that 543 accepts: (handle, 1, 1) -> 0,
-- on a flag created with init=1 and again after set(handle,1). Every other
-- combination of the second and third argument failed. 542 (wait) rejected all
-- four orderings tried, including ones carrying a 50 ms timespec.
--
-- This probe separates mask from mode with a 3x3 matrix on a flag created with
-- init=0, repeats it after a set, then calls the accepted shape twice in a row
-- to see whether polling consumes the bit. Section D walks 542 over five
-- argument layouts with the bit known to be set, so a wrong layout cannot park
-- the thread on an unset flag.

print("=== PROBE 195a: evf mask/mode ===")
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
local function show(v)
    if v == nil then return "killed" end
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

local NAME = memory.alloc(0x40)
local OUT = memory.alloc(0x40)
local TS = memory.alloc(0x10)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end
local function zero(addr, n)
    for off = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + off, u64(0)) end) end
end
put_str(NAME, "evf_195a")
zero(OUT, 0x40)
zero(TS, 0x10)
pcall(function() memory.write_qword(TS, uint64(0)) end)
pcall(function() memory.write_qword(TS + 8, uint64(50000000)) end)

local _, pid = call(20)
print("[0] getpid " .. show(pid))
print("")

local _, H = call(538, NAME, 0, 0)
print("[A] create(NAME,0,0) -> " .. show(H))
if dead or H == nil or H < 0 then
    print("=== PROBE 195a COMPLETE ===")
    return
end
print("")

local function matrix(title)
    print(title)
    for m = 0, 2 do
        for b = 0, 2 do
            if dead then break end
            local _, rv = call(543, H, m, b)
            print(string.format("    543(H,%d,%d) -> %s", m, b, show(rv)))
        end
    end
    print("")
end

matrix("[B] flag created with init=0, untouched")
call(544, H, 1)
matrix("[C] after set(H,1)")
local _, r1 = call(543, H, 1, 1)
local _, r2 = call(543, H, 1, 1)
print(string.format("[D] accepted shape twice: %s then %s (0 then -1 means the poll consumed the bit)",
    show(r1), show(r2)))
print("")

print("[E] set(H,1) again, then 542 layouts")
call(544, H, 1)
local waits = {
    { "542(H,1,1,OUT,TS)", H, 1, 1, OUT, TS },
    { "542(H,1,1,TS,OUT)", H, 1, 1, TS, OUT },
    { "542(H,1,1,0,OUT)", H, 1, 1, 0, OUT },
    { "542(H,1,1,OUT,0)", H, 1, 1, OUT, 0 },
    { "542(H,1,1,TS,0)", H, 1, 1, TS, 0 },
}
for _, w in ipairs(waits) do
    if dead then break end
    local _, rv = call(542, w[2], w[3], w[4], w[5], w[6])
    print(string.format("    %-22s -> %s", w[1], show(rv)))
end
print("")

print("[F] delete")
print("    delete(H) -> " .. show((call(539, H))))
print("")

print("=== PROBE 195a COMPLETE ===")
