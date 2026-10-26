-- CRASH_CLASS: MODERATE
-- PROBE 343a: does the qword 637 stores have an observable effect?
--
-- 637 set_phys_fmem_limit stores the caller's 64-bit value at parent+0x200 ->
-- child+0x280 with no capability check when the target id is 0. The dossier
-- guesses the field is a physical-memory limit with unknown units, and the
-- blocking behaviour seen in 339a (a small value never returns) fits an
-- accounting limit being waited on. If the field gates the GPU-visible pool,
-- then raising it should change what a large GPU mmap does, and that would prove
-- the store lands where the analysis says.
--
-- Only values above any plausible current usage are used, because a value below
-- it parks the caller. The baseline runs first so the comparison is within one
-- process and one connection.

print("=== PROBE 343a: FMEM LIMIT EFFECT ===")
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
local function show(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", to_num(h), to_num(l))
end

local Z = uint64(0)
local sc637 = make_syscall(637)
local sc_mmap = make_syscall(477)

local function gpu_mmap(size, prot, flags)
    local ok, rv = pcall(function()
        return sc_mmap(Z, uint64(size), uint64(prot), uint64(flags),
            uint64(0x1002), Z)
    end)
    if not ok then return nil end
    local h, l = get_hi_lo(rv)
    local lo = to_num(l)
    local hi = to_num(h)
    if hi == 0xFFFFFFFF or (hi == 0 and lo >= 0x80000000) then
        return -1
    end
    return to_num(l)
end

print("[A] baseline: GPU mmap 256 MiB, 1 GiB, 2 GiB (flags 0x33 prot 3)")
for _, mb in ipairs({ 256, 1024, 2048 }) do
    local r = gpu_mmap(mb * 0x100000, 3, 0x33)
    if r == -1 then
        print(string.format("  %5d MiB = -1", mb))
    elseif r == nil then
        print(string.format("  %5d MiB = EXC", mb))
    else
        print(string.format("  %5d MiB = 0x%08X", mb, r))
    end
end

print("[B] raise the limit to 2 GiB and 4 GiB, then retry")
for _, v in ipairs({ 0x80000000, 0xFFFFFFFF }) do
    local ok, rv = pcall(function() return sc637(Z, uint64(v), Z, Z, Z, Z) end)
    local r = ok and sgn(lo_of(rv)) or nil
    print(string.format("  637(0, 0x%X) = %s", v, tostring(r)))
    for _, mb in ipairs({ 256, 1024, 2048 }) do
        local m = gpu_mmap(mb * 0x100000, 3, 0x33)
        if m == -1 then
            print(string.format("    %5d MiB = -1", mb))
        elseif m == nil then
            print(string.format("    %5d MiB = EXC", mb))
        else
            print(string.format("    %5d MiB = 0x%08X", mb, m))
        end
    end
end

print("[C] system memory via the plain path, as a control")
local ok, rv = pcall(function()
    return sc_mmap(Z, uint64(512 * 0x100000), uint64(3), uint64(0x2),
        uint64(0xFFFFFFFF), Z)
end)
print(string.format("  anonymous 512 MiB = %s", ok and tostring(sgn(lo_of(rv))) or "EXC"))

print("")
print("=== 343a DONE ===")
