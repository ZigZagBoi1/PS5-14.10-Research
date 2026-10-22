-- CRASH_CLASS: MODERATE
-- PROBE 335a: the remaining "-1" population called with real pointers
--
-- Same method as 334a, over the handlers that are present but have only ever
-- been called with six zeros: 598, 606, 612, 616, 618, 619, 623, 625-627, 630,
-- 636, 637, 641, 642, 644-649, 652, 655, 656, 658-660, 662-664, 666, 667, 669,
-- 672, 673, 676. Known lethal numbers (621, 622, 631, 650, 651, 661, 665, 668)
-- and the numbers already measured this week are excluded. A marker line is
-- printed before each syscall so a kill is attributable to one number.

print("=== PROBE 335a: REMAINING -1 POPULATION ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local PAGE = memory.alloc(0x1000)
local Z = uint64(0)
local P = uint64(PAGE)

local NUMBERS = {
    598, 606, 612, 616, 618, 619, 623, 625, 626, 627, 630,
    636, 637, 641, 642, 644, 645, 646, 647, 648, 649,
    652, 655, 656, 658, 659, 660,
    662, 663, 664, 666, 667, 669, 672, 673, 676,
}

local SHAPES = {
    { "000000", Z, Z, Z, Z, Z, Z },
    { "P00000", P, Z, Z, Z, Z, Z },
    { "0P0000", Z, P, Z, Z, Z, Z },
    { "00P000", Z, Z, P, Z, Z, Z },
    { "PP1P00", P, P, uint64(0x100), P, Z, Z },
    { "P1P100", P, uint64(0x100), P, uint64(0x100), Z, Z },
}

for _, n in ipairs(NUMBERS) do
    print("> sys " .. n)
    local sc = make_syscall(n)
    for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
    local line = {}
    for _, sh in ipairs(SHAPES) do
        local ok, rv = pcall(function() return sc(sh[2], sh[3], sh[4], sh[5], sh[6], sh[7]) end)
        local tag
        if ok then
            local v = sgn(lo_of(rv))
            tag = tostring(v)
            if v == 0 then tag = "0*" end
        else
            tag = "EXC"
        end
        line[#line + 1] = sh[1] .. "=" .. tag
    end
    print(string.format("sys %3d  %s", n, table.concat(line, " ")))
end

print("")
print("=== 335a DONE ===")
