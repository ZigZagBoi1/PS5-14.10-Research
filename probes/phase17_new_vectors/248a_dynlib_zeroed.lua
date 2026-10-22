-- CRASH_CLASS: LOW
-- PROBE 248a: the dynlib family with zeroed structs
--
-- Context: 247a filled the buffer with a canary and put the size at +0, and
-- 593 - the control that works elsewhere in this repository - returned -1. The
-- difference from the working calls is everything after the size: the canary
-- leaves 0xA5A5A5A5 in the fields the call reads as version or flags, and the
-- handler refuses it. So canary-filling is the wrong instrument for a struct
-- API: it makes the call reject the request instead of filling it.
--
-- This probe zeroes the struct, writes only the size field, and counts the
-- dwords the call writes on top of zero. A zero written by the handler is not
-- detectable this way, which is the price of a request the handler accepts.
--
--   A  593 control, handles 0 and 1, size 0x160 - must return 0
--   B  656 with the same shape
--   C  659 and 660 in both argument orders

print("=== PROBE 248a: dynlib family with zeroed structs ===")
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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok and val ~= nil then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function nonzero(buf, n, skip)
    local count, first, firstval = 0, nil, nil
    for off = 0, n - 4, 4 do
        if off ~= skip then
            local v = rd(buf + off)
            if v ~= nil and v ~= 0 then
                count = count + 1
                if first == nil then first = off; firstval = v end
            end
        end
    end
    return count, first, firstval
end
local function kern(buf, n)
    local hits, sample = 0, nil
    for off = 0, n - 8, 8 do
        local hi = rd(buf + off + 4)
        if hi ~= nil and hi >= 0xFFFF8000 then
            hits = hits + 1
            if sample == nil then sample = off end
        end
    end
    return hits, sample
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end

local BUF = memory.alloc(0x1000)
local function trial(label, num, a, b, c, size)
    local sc = make_syscall(num)
    zero(BUF, 0x1000)
    if size ~= nil then wd(BUF, size) end
    local ok, rv = pcall(function() return sc(a, b, c) end)
    local ret = ok and rv or nil
    local count, first, firstval = nonzero(BUF, 0x1000, 0)
    local hits, sample = kern(BUF, 0x1000)
    print(string.format("  %-30s ret=%-14s wrote=%-4d first=%s val=%s kern=%d%s  pid=%s",
        label, q(ret), count,
        first == nil and "-" or string.format("+0x%03X", first),
        first == nil and "-" or q(firstval),
        hits, sample == nil and "" or (" @+" .. string.format("0x%03X", sample)),
        tostring(pid())))
end

local B = uint64(BUF)
local Z = uint64(0)
local H1 = uint64(1)

print("[0] canary pid=" .. tostring(pid()))

print("")
print("[A] control: 593")
trial("593(0, BUF{s=0x160})", 593, Z, B, Z, 0x160)
trial("593(1, BUF{s=0x160})", 593, H1, B, Z, 0x160)

print("")
print("[B] 656 dynlib_get_info_for_libdbg")
trial("656(0, BUF{s=0x160})", 656, Z, B, Z, 0x160)
trial("656(1, BUF{s=0x160})", 656, H1, B, Z, 0x160)
trial("656(0, BUF{s=0x1000})", 656, Z, B, Z, 0x1000)
trial("656(BUF{s=0x160}, 0)", 656, B, Z, Z, 0x160)

print("")
print("[C] 659 dynlib_get_list2 and 660 dynlib_get_info2")
trial("659(BUF{s=0x160}, 0)", 659, B, Z, Z, 0x160)
trial("659(BUF{s=0x160}, 64)", 659, B, uint64(64), Z, 0x160)
trial("659(0, BUF{s=0x160})", 659, Z, B, Z, 0x160)
trial("660(BUF{s=0x160}, 0)", 660, B, Z, Z, 0x160)
trial("660(0, BUF{s=0x160})", 660, Z, B, Z, 0x160)

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 248a COMPLETE ===")
