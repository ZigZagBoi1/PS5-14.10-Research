-- CRASH_CLASS: LOW
-- PROBE 194a: argument order for the evf calls
--
-- Context: 193a created a handle (541) and set a bit on it (544 returns 0), but
-- trywait never saw the bit: 543(A, 0x1) returned -1 before and after the set.
-- If 543 were (handle, bits) that could not happen. The likely shape is
-- (handle, mode, bits) or (handle, bits, out_ptr), which the zero in the third
-- slot would explain: a mode of 0 is "wait for all", a bits value of 0 matches
-- nothing.
--
-- This probe walks the argument order of 543 and 542 with the bit known to be
-- set, and tries open/close with a handle and with a name. Waits are placed
-- last and carry a 50 ms timespec, because a shape we get wrong could block.

print("=== PROBE 194a: evf argument order ===")
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
put_str(NAME, "evf_194a")
zero(OUT, 0x40)
zero(TS, 0x10)
pcall(function() memory.write_qword(TS, uint64(0)) end)          -- tv_sec
pcall(function() memory.write_qword(TS + 8, uint64(50000000)) end) -- tv_nsec = 50 ms

local _, pid = call(20)
print("[0] getpid " .. show(pid))
print("")

print("[A] create with an initial count")
local _, A = call(538, NAME, 0, 1)
print("    create(NAME,0,1)            -> " .. show(A))
if dead or A == nil or A < 0 then
    print("=== PROBE 194a COMPLETE ===")
    return
end
print("")

print("[B] argument order of 543 against a flag created with init=1")
local shapes = {
    { "543(A,0,1)", A, 0, 1 },
    { "543(A,1,0)", A, 1, 0 },
    { "543(A,1,1)", A, 1, 1 },
    { "543(A,2,1)", A, 2, 1 },
    { "543(A,3,1)", A, 3, 1 },
    { "543(A,1,0x1F)", A, 1, 0x1F },
    { "543(A,0x1F,1)", A, 0x1F, 1 },
    { "543(A,OUT,1)", A, OUT, 1 },
    { "543(A,1,OUT)", A, 1, OUT },
}
for _, s in ipairs(shapes) do
    if dead then break end
    local _, rv = call(543, s[2], s[3], s[4])
    print(string.format("    %-27s -> %s", s[1], show(rv)))
end
print("")

print("[C] set the bit, then the same shapes again")
local _, sr = call(544, A, 1)
print("    set(A,1)                    -> " .. show(sr))
for _, s in ipairs(shapes) do
    if dead then break end
    local _, rv = call(543, s[2], s[3], s[4])
    print(string.format("    %-27s -> %s", s[1], show(rv)))
end
print("")

print("[D] open and close")
local opens = {
    { "540(NAME)", NAME },
    { "540(NAME,0,0)", NAME, 0, 0 },
    { "540(NAME,1,0)", NAME, 1, 0 },
    { "540(A)", A },
    { "540(A,0,0)", A, 0, 0 },
}
local opened = nil
for _, s in ipairs(opens) do
    if dead then break end
    local _, rv = call(540, s[2], s[3], s[4])
    print(string.format("    %-27s -> %s", s[1], show(rv)))
    if rv and rv >= 0 and not opened then opened = rv end
end
local _, cr = call(541, opened or A)
print(string.format("    close(%s)                    -> %s", tostring(opened or A), show(cr)))
print("")

print("[E] 542 wait with a 50 ms timespec, bit already set")
local waits = {
    { "542(A,1,0,TS)", A, 1, 0, TS },
    { "542(A,0,1,TS)", A, 0, 1, TS },
    { "542(A,1,OUT,TS)", A, 1, OUT, TS },
    { "542(A,1,TS,0)", A, 1, TS, 0 },
}
for _, s in ipairs(waits) do
    if dead then break end
    local _, rv = call(542, s[2], s[3], s[4], s[5])
    print(string.format("    %-27s -> %s", s[1], show(rv)))
end
print("")

print("[F] delete")
print("    delete(A)                   -> " .. show((call(539, A))))
print("")

print("=== PROBE 194a COMPLETE ===")
