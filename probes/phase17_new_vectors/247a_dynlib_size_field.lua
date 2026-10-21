-- CRASH_CLASS: LOW
-- PROBE 247a: the dynlib family with the size field 593 actually wants
--
-- Context: 246a called 656, 659 and 660 with bare buffers and got -1 everywhere
-- - and its own control, 593, also returned -1, which is the tell: 593 is
-- called in this repository as (handle, struct) where struct[0] is a size
-- (0x160), and a bare buffer is refused. So 246a measured the missing field,
-- not the three calls.
--
-- This probe gives every call the same struct-with-size shape and keeps 593 as
-- a live control that must return 0.
--
--   A  593(handle, struct{size=0x160}) for handles 0, 1, 0xFFFF - control
--   B  656 same shape, sizes 0x160 and 0x1000, handles 0 and 1
--   C  659 and 660 with the struct first and with the count first
--
-- Every buffer is canary-filled; changed dwords and kernel-shaped qwords are
-- counted per call.

print("=== PROBE 247a: dynlib family with a size field ===")
print("")

local CANARY = 0xA5A5A5A5
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
local function fill(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, CANARY) end
end
local function scan(buf, n)
    local changed, first, firstval = 0, nil, nil
    for off = 0, n - 4, 4 do
        local v = rd(buf + off)
        if v ~= nil and v ~= CANARY then
            changed = changed + 1
            if first == nil then first = off; firstval = v end
        end
    end
    return changed, first, firstval
end
local function kern(buf, n)
    local hits = 0
    for off = 0, n - 8, 8 do
        local hi = rd(buf + off + 4)
        if hi ~= nil and hi >= 0xFFFF8000 then hits = hits + 1 end
    end
    return hits
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end

local BUF = memory.alloc(0x1000)

local function trial(label, num, a, b, c, size)
    local sc = make_syscall(num)
    fill(BUF, 0x1000)
    if size ~= nil then wd(BUF, size) end
    local ok, rv = pcall(function() return sc(a, b, c) end)
    local ret = ok and rv or nil
    local changed, first, firstval = scan(BUF, 0x1000)
    local hits = kern(BUF, 0x1000)
    print(string.format("  %-30s ret=%-14s changed=%-4d first=%s val=%s kern=%d  pid=%s",
        label, q(ret), changed,
        first == nil and "-" or string.format("+0x%03X", first),
        first == nil and "-" or q(firstval),
        hits, tostring(pid())))
end

local B = uint64(BUF)
local Z = uint64(0)
local H1 = uint64(1)
local HFF = uint64(0xFFFF)

print("[0] canary pid=" .. tostring(pid()))

print("")
print("[A] control: 593 with a size field")
trial("593(0, BUF{s=0x160})", 593, Z, B, Z, 0x160)
trial("593(1, BUF{s=0x160})", 593, H1, B, Z, 0x160)
trial("593(0xFFFF, BUF{s=0x160})", 593, HFF, B, Z, 0x160)
trial("593(0, BUF{s=0x1000})", 593, Z, B, Z, 0x1000)

print("")
print("[B] 656 dynlib_get_info_for_libdbg")
trial("656(0, BUF{s=0x160})", 656, Z, B, Z, 0x160)
trial("656(0, BUF{s=0x1000})", 656, Z, B, Z, 0x1000)
trial("656(1, BUF{s=0x160})", 656, H1, B, Z, 0x160)
trial("656(1, BUF{s=0x1000})", 656, H1, B, Z, 0x1000)
trial("656(0, BUF{s=0x160}, 0x160)", 656, Z, B, uint64(0x160), 0x160)
trial("656(BUF{s=0x160}, 0)", 656, B, Z, Z, 0x160)

print("")
print("[C] 659 dynlib_get_list2 and 660 dynlib_get_info2")
trial("659(BUF{s=0x160}, 0)", 659, B, Z, Z, 0x160)
trial("659(BUF{s=0x1000}, 0)", 659, B, Z, Z, 0x1000)
trial("659(0, BUF{s=0x160})", 659, Z, B, Z, 0x160)
trial("660(BUF{s=0x160}, 0)", 660, B, Z, Z, 0x160)
trial("660(0, BUF{s=0x160})", 660, Z, B, Z, 0x160)
trial("660(1, BUF{s=0x160})", 660, H1, B, Z, 0x160)

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 247a COMPLETE ===")
