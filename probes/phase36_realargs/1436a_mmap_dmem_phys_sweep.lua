-- CRASH_CLASS: MODERATE
-- PROBE 1436a: sys 628 mmap_dmem -- physical address, container index, state byte
--
-- 1409a measured 628(phys, 0x4000) for phys = 0x100000000 / 0x200000000 /
-- 0x1000000000 and got EBUSY(16) where earlier probes recorded EINVAL.  EBUSY is
-- not a shape rejection: per docs/DMEM_628_AND_SYSCALL_585_14_10.md the worker
-- looks for a descriptor of the named container whose state byte 0x69 == 0xfe and
-- whose [base, base+len) covers the request, so EBUSY means the lookup ran and
-- found something in the wrong state.  That is the first sign of life on this call.
--
-- This probe sweeps the physical address and the container index separately so the
-- refusal can be attributed.  If any shape returns a mapped VA, reading it is a
-- window on physical memory outside our own container.
--
-- SAFETY: container index 0xFFFFFFFF is never passed.  The document records that
-- idx = 0xFFFFFFFF skips the lookup entirely and makes the worker store curthread
-- at container_table-0xE8, which panics the console (a fixed-address kernel write).
--
-- Prior art:
--   1409a results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152941.txt
--   1397d results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt
--   docs/DMEM_628_AND_SYSCALL_585_14_10.md
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1436a: 628 mmap_dmem PHYSICAL SWEEP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(p) return to_num(memory.read_dword(p)) end

local m628 = sc(628)
local m477 = sc(477)

-- the syscall returns -1 with errno; EBUSY is errno 16, never the return value
local function is_busy(rv)
    if rv ~= -1 then return false end
    local e = es()
    return string.find(e, "busy", 1, true) ~= nil
end
local function call628(phys, len, idx, flags)
    local rv = -999
    local ok, r = pcall(function()
        return m628(uint64(phys), uint64(len), uint64(idx),
            uint64(flags or 0), uint64(0), uint64(0))
    end)
    if not ok then return "EXC", nil end
    return to_num(r), nil
end

local function looks_like_va(v)
    return type(v) == "number" and v >= 0x10000 and v <= 0x8000000000
end

-- read four dwords out of a returned mapping, tolerating a fault
local function peek(va)
    local ok, a, b, c, d = pcall(function()
        return to_num(memory.read_dword(va)), to_num(memory.read_dword(va + 4)),
               to_num(memory.read_dword(va + 8)), to_num(memory.read_dword(va + 12))
    end)
    if not ok then return "READ-EXC" end
    return string.format("%08X %08X %08X %08X", a, b, c, d)
end

print("[A] control: does 628 reject a nonsense shape at all?")
print(string.format("  628(0, 0)              -> %s  (%s)", tostring((call628(0, 0, 0))), es()))
print(string.format("  628(0, 0x4000, 0)      -> %s  (%s)", tostring((call628(0, 0x4000, 0))), es()))
print(string.format("  628(0, 0x4000, 0, 0x40)-> %s  (%s)", tostring((call628(0, 0x4000, 0, 0x40))), es()))
print("")

print("[B] physical address sweep, container 0, len 0x4000, flags 0")
local phys = {0, 0x1000, 0x4000, 0x100000, 0x1000000, 0x10000000,
              0x80000000, 0xC0000000, 0xF0000000, 0x100000000,
              0x200000000, 0x380000000, 0x400000000}
local seen = {}
for _, p in ipairs(phys) do
    local rv = call628(p, 0x4000, 0, 0)
    local e = es()
    print(string.format("  phys=%#012x -> %-6s (%s)", p, tostring(rv), e))
    if looks_like_va(rv) then
        seen[#seen + 1] = { p = p, va = rv }
        print(string.format("       MAPPED at %#x: %s", rv, peek(rv)))
    end
end
print("")

print("[C] container index sweep at the first physical address that answered EBUSY")
-- EBUSY(16) was the interesting answer; find one
local busy = nil
for _, p in ipairs(phys) do
    local rv = call628(p, 0x4000, 0, 0)
    if is_busy(rv) then busy = p; break end
end
if busy then
    print(string.format("  physical candidate: %#x", busy))
    for _, ix in ipairs({0, 1, 2, 3, 4, 8, 0x10, 0x14, 0x15}) do
        local rv = call628(busy, 0x4000, ix, 0)
        local e = es()
        print(string.format("    idx=%-3d -> %-6s (%s)", ix, tostring(rv), e))
        if looks_like_va(rv) then
            print(string.format("         MAPPED at %#x: %s", rv, peek(rv)))
            seen[#seen + 1] = { p = busy, va = rv }
        end
    end
else
    print("  no EBUSY in [B] -- index sweep skipped")
end
print("")

print("[D] flag sweep at the same physical address, container 0")
if busy then
    for _, f in ipairs({0, 1, 2, 4, 0x10, 0x20, 0x40, 0x100, 0x200, 0x3f3}) do
        local rv = call628(busy, 0x4000, 0, f)
        print(string.format("    flags=%#05x -> %-6s (%s)", f, tostring(rv), es()))
    end
else
    print("  skipped")
end
print("")

print(string.format("[E] summary: %d mapping(s) returned", #seen))
for _, s in ipairs(seen) do
    print(string.format("  phys %#x -> va %#x", s.p, s.va))
end

print("")
print("=== PROBE 1436a COMPLETE ===")
