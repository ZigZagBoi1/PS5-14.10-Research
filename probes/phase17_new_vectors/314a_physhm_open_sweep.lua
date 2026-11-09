-- CRASH_CLASS: MODERATE
-- PROBE 314a: which (arg1, arg2, arg3) shapes does physhm_open accept?
--
-- 313a found exactly one: 629(1, 0x2, 0, 0) returned 26, a descriptor-shaped
-- positive value, while every other shape in that probe returned -1. The
-- sentinel arg0=1 goes straight to the delegate with subcommand 1, so arg1 is
-- the only knob that reached it there.
--
-- This sweeps arg1 over the plausible sizes and flags, then arg2 and arg3 for
-- the values that worked. Each open is closed again so descriptors are not
-- exhausted; a returned descriptor is reported with its value.

print("=== PROBE 314a: SYS 629 physhm_open SWEEP ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end

local sc629 = make_syscall(629)
local sc_close = make_syscall(6)
local function U32(v) return uint64(v) end

-- [A] arg1 sweep with arg2 = arg3 = 0
print("")
print("[A] arg1 0..0x120")
local hits = {}
for a = 0, 0x120 do
    local ok, rv = pcall(function() return sc629(uint64(1), U32(a), U32(0), U32(0)) end)
    if not ok then print(string.format("  arg1=0x%X DIED: %s", a, tostring(rv))) break end
    local r = sgn(rv)
    if r ~= -1 then
        print(string.format("  arg1=0x%X -> %d", a, r))
        hits[#hits + 1] = a
        if r >= 0 and r < 0x10000 then sc_close(U32(r)) end
    end
end
print(string.format("  accepted arg1 values: %d", #hits))

-- [B] larger arg1 values, powers of two and page multiples
print("")
print("[B] arg1 page multiples and powers of two")
for _, a in ipairs({0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x80000,
                    0x200000, 0x1000000, 0x10000000, 0x40000000, 0x80000000}) do
    local ok, rv = pcall(function() return sc629(uint64(1), U32(a), U32(0), U32(0)) end)
    if not ok then print(string.format("  arg1=0x%X DIED", a)) break end
    local r = sgn(rv)
    print(string.format("  arg1=0x%X -> %d", a, r))
    if r >= 0 and r < 0x10000 then sc_close(U32(r)) end
end

-- [C] arg2 (u16) and arg3 (u32) around the one accepted shape
print("")
print("[C] arg2/arg3 around arg1=2")
for _, a2 in ipairs({0, 1, 2, 3, 4, 0x10, 0x100, 0xFFFF}) do
    local rv = sc629(uint64(1), U32(2), U32(a2), U32(0))
    local r = sgn(rv)
    print(string.format("  629(1,2,0x%X,0) -> %d", a2, r))
    if r >= 0 and r < 0x10000 then sc_close(U32(r)) end
end
for _, a3 in ipairs({0, 1, 2, 3, 0x1000, 0xFFFFFFFF}) do
    local rv = sc629(uint64(1), U32(2), U32(0), U32(a3))
    local r = sgn(rv)
    print(string.format("  629(1,2,0,0x%X) -> %d", a3, r))
    if r >= 0 and r < 0x10000 then sc_close(U32(r)) end
end

print("")
print("=== PROBE 314a COMPLETE ===")
