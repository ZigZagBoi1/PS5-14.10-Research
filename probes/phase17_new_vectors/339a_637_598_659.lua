-- CRASH_CLASS: MODERATE
-- PROBE 339a: the three handlers that answered with a real pointer
--
-- 335a found exactly three non-uniform rows among the "-1" population:
--   598 dynlib_get_proc_param  0 for (page, page, 0x100, page)
--   659 dynlib_get_list2       0 for (page, 0x100, page, 0x100)
--   637 set_phys_fmem_limit    0 for (0, page)
-- 637's dossier describes a caller-controlled u64 stored into a kernel child
-- object at +0x280 with no capability check when the target id is zero, which
-- is the first handler measured here that writes a chosen qword into a kernel
-- structure. This sweeps its value and id, then tests whether the store has an
-- observable effect on mmap, and dumps what 598 and 659 write.

print("=== PROBE 339a: 637 / 598 / 659 ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
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
local function call(sc, a, b, c, d, e, f)
    local ok, rv = pcall(function() return sc(a, b, c, d, e, f) end)
    if not ok then return nil end
    return sgn(lo_of(rv))
end
local function fmt(v)
    if v == nil then return "EXC" end
    return tostring(v)
end

local PAGE = memory.alloc(0x1000)
local Z = uint64(0)
local sc637 = make_syscall(637)
local sc598 = make_syscall(598)
local sc659 = make_syscall(659)
local sc_mmap = make_syscall(477)
local P = uint64(PAGE)

print("[A] 637 value sweep with id = 0")
local VALS = { 16, 17, 0x1000, 0x10000, 0x100000, 0x1000000, 0x10000000,
               0x40000000, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF }
for _, v in ipairs(VALS) do
    print(string.format("  637(0, 0x%X) = %s", v,
        fmt(call(sc637, Z, uint64(v), Z, Z, Z, Z))))
end

print("[B] 637 id sweep with value 0x10000000")
local IDS = { 0, 1, 2, 5, 16, 30, 0x7FFFFFFF, 0xFFFFFFFF }
for _, id in ipairs(IDS) do
    print(string.format("  637(0x%X, 0x10000000) = %s", id,
        fmt(call(sc637, uint64(id), uint64(0x10000000), Z, Z, Z, Z))))
end

print("[C] observable effect: 637 then a 256 MiB mmap")
local function big_mmap()
    local ok, rv = pcall(function()
        return sc_mmap(Z, uint64(256 * 0x100000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    if not ok then return nil end
    local h, l = get_hi_lo(rv)
    local lo = to_num(l)
    if lo >= 0x80000000 and to_num(h) == 0xFFFFFFFF then return -1 end
    return lo
end
print(string.format("  baseline mmap       = %s", fmt(big_mmap())))
print(string.format("  637(0, 17)          = %s", fmt(call(sc637, Z, uint64(17), Z, Z, Z, Z))))
print(string.format("  mmap after limit 17 = %s", fmt(big_mmap())))
print(string.format("  637(0, 0xFFFFFFFF)  = %s", fmt(call(sc637, Z, uint64(0xFFFFFFFF), Z, Z, Z, Z))))
print(string.format("  mmap after huge     = %s", fmt(big_mmap())))

print("[D] 598 dynlib_get_proc_param, dumped")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
print(string.format("  598(P,P,0x100,P) = %s",
    fmt(call(sc598, P, P, uint64(0x100), P, Z, Z))))
local shown = 0
for i = 0, 0x100 - 8, 8 do
    local lo = safe_rd(PAGE + i)
    local hi = safe_rd(PAGE + i + 4)
    if lo and hi and (lo ~= 0 or hi ~= 0) then
        if shown < 16 then
            print(string.format("    +0x%03X = 0x%08X_%08X", i, hi, lo))
            shown = shown + 1
        end
    end
end
if shown == 0 then print("    (all zero)") end

print("[E] 659 dynlib_get_list2, dumped")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
print(string.format("  659(P,0x100,P,0x100) = %s",
    fmt(call(sc659, P, uint64(0x100), P, uint64(0x100), Z, Z))))
shown = 0
for i = 0, 0x100 - 8, 8 do
    local lo = safe_rd(PAGE + i)
    local hi = safe_rd(PAGE + i + 4)
    if lo and hi and (lo ~= 0 or hi ~= 0) then
        if shown < 16 then
            print(string.format("    +0x%03X = 0x%08X_%08X", i, hi, lo))
            shown = shown + 1
        end
    end
end
if shown == 0 then print("    (all zero)") end

print("")
print("=== 339a DONE ===")
