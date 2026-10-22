-- CRASH_CLASS: MODERATE
-- PROBE 334a: the object families called with real pointers instead of six zeros
--
-- Every "-1" row in docs/SYSENT_PRESENCE_14_10.md comes from a six-zero sweep.
-- Sys 622, 532 and 654 all returned -1 that way and all answered once called
-- with the shape their handler reads, so a -1 row is an untested contract, not
-- a dead entry. This walks the object families (evf 538-546, osem 549-556,
-- namedobj 557-558, vm container 559, debug_init 560, virtual_query 572-573,
-- obs 574-584) with six argument shapes and prints only the ones that stop
-- returning -1, plus a marker before each syscall so a kill is attributable.

print("=== PROBE 334a: OBJECT FAMILIES ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
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
    538, 539, 540, 541, 542, 543, 544, 545, 546,
    549, 550, 551, 552, 553, 554, 555, 556,
    557, 558, 559, 560, 572, 573,
    574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584,
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
    local sc = make_syscall(n)
    for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
    safe_wd(PAGE + 0, 0)
    local line = {}
    for _, sh in ipairs(SHAPES) do
        IO = sh[2]
        local ok, rv = pcall(function() return sc(sh[2], sh[3], sh[4], sh[5], sh[6], sh[7]) end)
        local tag
        if ok then
            local v = sgn(lo_of(rv))
            tag = tostring(v)
            if v == 0 then
                tag = "0*"
            end
        else
            tag = "EXC"
        end
        line[#line + 1] = sh[1] .. "=" .. tag
    end
    print(string.format("sys %3d  %s", n, table.concat(line, " ")))
end

print("")
print("=== 334a DONE ===")
