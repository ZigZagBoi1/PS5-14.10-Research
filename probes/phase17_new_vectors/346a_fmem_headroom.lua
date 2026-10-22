-- CRASH_CLASS: MODERATE
-- PROBE 346a: does raising the budget add headroom? An A/B inside one process
--
-- 344a lowered the value to 256 MiB and the next 256 MiB mapping failed, which
-- looked like the write taking effect. 345a shows that reading is unsafe: in the
-- same process, with the value already at 4 GiB, a 256 MiB mapping still failed,
-- because the earlier mappings had consumed the pool. So the failure in 344a is
-- explained by consumption alone.
--
-- This measures it properly. Allocate 64 MiB chunks until one fails and report
-- the total, raise the stored value, then try again. If more chunks succeed
-- after the raise than before it, the write adds headroom; if the next chunk
-- fails exactly where it did, the write has no effect on this pool at all. Run
-- on a fresh process so the first phase is not polluted.

print("=== PROBE 346a: FMEM HEADROOM A/B ===")
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

local Z = uint64(0)
local sc637 = make_syscall(637)
local sc477 = make_syscall(477)
local CHUNK = 64

local function chunk()
    local ok, rv = pcall(function()
        return sc477(Z, uint64(CHUNK * 0x100000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    if not ok then return false end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    -- A refused mmap reports (0, -1), not the 0xFFFF...FFFF pair: judge the
    -- rebuilt address. The first revision of this probe tested for the pair, so
    -- every refusal counted as a success and 64 "chunks" was this loop's cap.
    local probe = hi * 4294967296 + lo
    if probe <= 0 or probe >= 0x800000000000 then
        print(string.format("      refused (hi=0x%X lo=0x%X)", hi, lo))
        return false
    end
    print(string.format("      chunk at 0x%X", probe))
    return true
end

local function fill(label)
    local n = 0
    while n < 128 do
        if not chunk() then break end
        n = n + 1
    end
    print(string.format("  %s: %d chunks of %d MiB = %d MiB total", label, n, CHUNK, n * CHUNK))
    return n
end

print("[A] allocate until refused")
local first = fill("before raise")

print("[B] raise to 4 GiB")
local ok, rv = pcall(function() return sc637(Z, uint64(0xFFFFFFFF), Z, Z, Z, Z) end)
print(string.format("  637(0, 0xFFFFFFFF) = %s", ok and tostring(sgn(lo_of(rv))) or "EXC"))

print("[C] try again")
local after = fill("after raise")

print(string.format("  verdict: %d -> %d chunks", first, after))

print("")
print("=== 346a DONE ===")
