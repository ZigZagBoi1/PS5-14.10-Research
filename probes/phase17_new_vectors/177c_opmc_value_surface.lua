-- CRASH_CLASS: MODERATE
-- PROBE 177c: which values does the opmc block accept, and can get_ctr write?
--
-- 177b left two questions. First, set_ctr accepted the value 1 and rejected
-- 0x5EA1, which says the second argument is an enum or bitmask rather than a
-- counter value - so which values are accepted tells us what the field means.
-- Second, opmc_get_ctr rejected five layouts, including a buffer pointer in the
-- second and third position, so its read path has not been found yet.
--
-- This probe sweeps a small set of power-of-two and packed values through 563
-- (enable), 564 (disable), 565 (set_ctl) and 566 (set_ctr), then tries get_ctr
-- with a buffer that carries the size-and-version header other Sony calls use.
-- A value that turns a -1 into a 0 is a validated field, and a get_ctr layout
-- that writes anything at all is the first kernel-sourced data from this block.

print("=== PROBE 177c: OPMC VALUE SURFACE ===")

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

local page = sc477(uint64(0), uint64(0x8000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("[0] page=" .. string.format("0x%X", to_num(page)))

local MARK = 0xA5A5A5A5
local function fill(n) for off = 0, n - 4, 4 do wd(page + off, MARK) end end
local function scan(n)
    local changed, first, fval = 0, -1, 0
    for off = 0, n - 4, 4 do
        local v = rd(page + off)
        if v ~= MARK then
            changed = changed + 1
            if first < 0 then first, fval = off, v end
        end
    end
    return changed, first, fval
end

local function call(label, num, a1, a2, a3, scan_len)
    local sc = make_syscall(num)
    fill(scan_len or 0x1000)
    local ok, rv = pcall(function()
        return sc(uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local changed, off, val = scan(scan_len or 0x1000)
    local line = string.format("  %-26s sys=%d a=(%s,%s,%s) ret=0x%08X%08X",
        label, num, tostring(a1), tostring(a2), tostring(a3), hi, lo)
    if changed > 0 then
        line = line .. string.format(" chg=%d@%d:0x%08X", changed, off, val)
    end
    print(line)
    return lo
end

local VALUES = {0, 1, 2, 3, 4, 7, 8, 0x10, 0x100, 0x1000, 0xFFFFFFFF}

for _, num in ipairs({563, 564, 565, 566}) do
    print("[*] sys " .. num .. " value surface")
    local accepted = 0
    for _, v in ipairs(VALUES) do
        local lo = call("v=0x" .. string.format("%X", v), num, 0, v, 0)
        if lo == 0 then accepted = accepted + 1 end
    end
    print("    accepted values: " .. accepted .. "/" .. #VALUES)
    print("    canary pid=" .. tostring(to_num(sc20())))
end

print("[*] get_ctr layouts")
call("(page,0x400)", 567, page, 0x400, 0)
call("(page+0x800,0x40)", 567, page + 0x800, 0x40, 0)
-- size-and-version header, the shape other Sony calls use
wd(page + 0x1000, 0x40)
wd(page + 0x1004, 1)
call("hdr v1 (page+0x1000,0x40)", 567, page + 0x1000, 0x40, 0)
wd(page + 0x1000, 0x40)
wd(page + 0x1004, 0)
call("hdr v0 (page+0x1000,0x40)", 567, page + 0x1000, 0x40, 0)
call("(0,page,0x20)", 567, 0, page, 0x20)
call("(0,page,0x400)", 567, 0, page, 0x400)
call("(page,0)", 567, page, 0, 0)
print("[*] canary final pid=" .. tostring(to_num(sc20())))
print("=== PROBE 177c DONE ===")
