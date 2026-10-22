-- CRASH_CLASS: MODERATE
-- PROBE 344a: 637's stored value against the GPU-visible pool
--
-- 343a passed the GPU mmap arguments in the wrong order (protection and flags
-- swapped), so every mapping failed and nothing was learned. The documented
-- GPU mmap is mmap(0, size, 0x33, 0x1002, 0xFFFFFFFF, 0) - protection 0x33,
-- flags 0x1002. This measures the same question with the right call: does
-- raising the value 637 stores change what a large GPU mapping does? Values are
-- kept above any plausible usage because a smaller one parks the caller.

print("=== PROBE 344a: FMEM LIMIT AND THE GPU POOL ===")
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
    if hi == 0 and lo == 0 then return "0" end
    return addr_str(rv)
end

print("[A] baseline GPU mmap with the documented arguments")
for _, mb in ipairs({ 8, 64, 256, 1024 }) do
    print(string.format("  %5d MiB = %s", mb, gpu_mmap(mb)))
end

print("[B] raise the stored limit, then repeat")
for _, v in ipairs({ 0x10000000, 0x80000000, 0xFFFFFFFF }) do
    local ok, rv = pcall(function() return sc637(Z, uint64(v), Z, Z, Z, Z) end)
    print(string.format("  637(0, 0x%X) = %s", v,
        ok and tostring(sgn(lo_of(rv))) or "EXC"))
    for _, mb in ipairs({ 8, 256, 1024 }) do
        print(string.format("    %5d MiB = %s", mb, gpu_mmap(mb)))
    end
end

print("")
print("=== 344a DONE ===")
