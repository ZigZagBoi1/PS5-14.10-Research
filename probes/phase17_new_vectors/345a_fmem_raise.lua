-- CRASH_CLASS: MODERATE
-- PROBE 345a: raise the physical-memory budget in a fresh process
--
-- 344a lowered the limit first (0x10000000), and every later raise failed to
-- restore the 256 MiB mapping, so that run never answered the other question:
-- if the very first write RAISES the budget, does a mapping that the default
-- refused now succeed? The baseline in 344a refused 1024 MiB. This calls
-- nothing before the baseline, then raises once, then retries. If the large
-- mapping starts working, the budget is a lever we can open and close instead of
-- a one-way valve.

print("=== PROBE 345a: RAISING THE FMEM BUDGET ===")
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
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function addr_str(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", to_num(h), to_num(l))
end

local Z = uint64(0)
local sc637 = make_syscall(637)
local sc477 = make_syscall(477)

local function gpu_mmap(mb)
    local ok, rv = pcall(function()
        return sc477(Z, uint64(mb * 0x100000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    if not ok then return "EXC" end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    if hi == 0xFFFFFFFF and lo == 0xFFFFFFFF then return "-1" end
    return addr_str(rv)
end

print("[A] baseline, nothing called before this")
for _, mb in ipairs({ 64, 256, 512, 1024 }) do
    print(string.format("  %5d MiB = %s", mb, gpu_mmap(mb)))
end

print("[B] raise to 4 GiB as the first 637 call")
local ok, rv = pcall(function() return sc637(Z, uint64(0xFFFFFFFF), Z, Z, Z, Z) end)
print(string.format("  637(0, 0xFFFFFFFF) = %s", ok and tostring(sgn(lo_of(rv))) or "EXC"))

print("[C] retry the same sizes, then larger")
for _, mb in ipairs({ 64, 256, 512, 1024, 2048 }) do
    print(string.format("  %5d MiB = %s", mb, gpu_mmap(mb)))
end

print("[D] raise again to 8 GiB and retry 2048")
ok, rv = pcall(function() return sc637(Z, uint64(0x200000000), Z, Z, Z, Z) end)
print(string.format("  637(0, 0x200000000) = %s", ok and tostring(sgn(lo_of(rv))) or "EXC"))
print(string.format("  2048 MiB = %s", gpu_mmap(2048)))

print("")
print("=== 345a DONE ===")
