-- CRASH_CLASS: RISKY
-- PROBE 331a: sys 628 across descriptor, protection, flag and hint shapes
--
-- 328a (descriptor -1) and 330a (descriptor = /dev/dmem0 fd) both returned -1
-- for every physical offset, so one of the other five slots is wrong for a
-- game process. This walks the small matrix: which descriptor values pass the
-- 0x8ad833e0 check, whether a nonzero address hint matters, whether flag 0x40
-- and a one-page length behave differently, and whether PROT_READ alone is
-- accepted. Every call uses 16 KiB aligned address/length/offset.

print("=== PROBE 331a: MMAP_DMEM MATRIX ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function ptr(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local sc = make_syscall(628)
local sc_open = make_syscall(5)
local PATHBUF = memory.alloc(0x100)
local function do_open(path, mode)
    for i = 1, #path do
        pcall(function() memory.write_byte(PATHBUF + (i - 1), string.byte(path, i)) end)
    end
    pcall(function() memory.write_byte(PATHBUF + #path, 0) end)
    local ok, rv = pcall(function() return sc_open(uint64(PATHBUF), uint64(mode), uint64(0)) end)
    if not ok then return -1 end
    return sgn(lo_of(rv))
end

local dmem = do_open("/dev/dmem0", 2)
local zero = do_open("/dev/zero", 2)
print(string.format("[A] dmem0 fd=%d zero fd=%d", dmem, zero))

local SHAPES = {
    { "plain",      0,          0x4000,  3, 0,    0 },
    { "flag40",     0,          0x4000,  3, 0x40, 0 },
    { "readonly",   0,          0x4000,  1, 0,    0 },
    { "hint",       0x40000000, 0x4000,  3, 0,    0 },
    { "len 0x10000",0,          0x10000, 3, 0,    0 },
    { "off 0x4000", 0,          0x4000,  3, 0,    0x4000 },
}

local DESCS = { -1, dmem, zero, 0 }

for _, d in ipairs(DESCS) do
    for _, s in ipairs(SHAPES) do
        local ok, rv = pcall(function()
            return sc(ptr(0, s[2]), ptr(0, s[3]), uint64(d),
                      ptr(0, s[4]), ptr(0, s[5]), ptr(0, s[6]))
        end)
        if not ok then
            print(string.format("  desc=%-3d %-10s RAISED", d, s[1]))
        else
            local lo, hi = lo_of(rv)
            print(string.format("  desc=%-3d %-10s ret=0x%08X%08X (%d)", d, s[1], hi, lo, sgn(lo)))
        end
    end
end

print("")
print("=== 331a DONE ===")
