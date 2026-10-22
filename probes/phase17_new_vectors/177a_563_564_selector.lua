-- CRASH_CLASS: LOW
-- PROBE 177a: selectors for 563 and 564
--
-- 176b found a layout sensitivity worth chasing: with the buffer in RDI both
-- 563 and 564 return -1, and with the buffer in RSI both return 0. Neither
-- writes a dword. A handler that answers success to (NULL, buffer, size) and
-- writes nothing is the classic shape of a query whose selector lives in the
-- first argument and whose default selector (0) has nothing to report.
--
-- This probe holds the buffer in RSI and the size in RDX, fills 0x400 bytes with
-- a canary, and walks the first argument through 0..31 for both numbers. It
-- reports, per selector, the return value, how many dwords changed, and the
-- first changed offset with its value. A selector that changes the buffer is
-- the first data out of this range; a selector that changes the return without
-- touching the buffer narrows the argument decoding.
--
-- Also tries the same selectors with the size 0x10 and 0x4000, in case the
-- handler writes only when the caller's size expression matches what it wants.

print("=== PROBE 177a: SELECTORS FOR 563 AND 564 ===")

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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end

local sc20 = make_syscall(20)
local sc477 = make_syscall(477)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local buf = sc477(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("[0] buf=" .. string.format("0x%X", to_num(buf)))

local MARK = 0xA5A5A5A5
local function fill() for off = 0, 0xFFC, 4 do wd(buf + off, MARK) end end
local function scan(n)
    local changed, first, fval = 0, -1, 0
    for off = 0, n - 4, 4 do
        local v = rd(buf + off)
        if v ~= MARK then
            changed = changed + 1
            if first < 0 then first, fval = off, v end
        end
    end
    return changed, first, fval
end

local function call(num, sel, size)
    local sc = make_syscall(num)
    fill()
    local ok, rv = pcall(function()
        return sc(uint64(sel), uint64(buf), uint64(size), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local changed, first, fval = scan(size)
    if changed > 0 or lo ~= 0 then
        print(string.format("  sys %d sel=%-2d size=0x%X ret=0x%08X%08X changed=%d first=%d:0x%08X",
            num, sel, size, hi, lo, changed, first, fval))
    end
    return lo
end

for _, num in ipairs({563, 564}) do
    print("[*] sys " .. num .. ", size 0x400")
    local quiet = 0
    for sel = 0, 31 do
        local lo = call(num, sel, 0x400)
        if lo == 0 then quiet = quiet + 1 end
    end
    print("    selectors returning 0: " .. quiet .. "/32")
    local lo10 = call(num, 1, 0x10)
    local lo4096 = call(num, 1, 0x4000)
    print(string.format("    sel=1 size=0x10 ret=%d, size=0x4000 ret=%d", lo10, lo4096))
    print("    canary pid=" .. tostring(to_num(sc20())))
end

print("=== PROBE 177a DONE ===")
