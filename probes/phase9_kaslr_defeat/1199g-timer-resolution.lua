-- CRASH_CLASS: LOW
-- PROBE 1199g: Measure clock_gettime resolution + cache timing feasibility
--
-- Without a clean rdtsc;ret gadget, we need clock_gettime as Spectre timer.
-- This probe measures:
-- A) clock_gettime minimum delta (raw syscall overhead)
-- B) Whether we can distinguish cached vs evicted memory access
-- C) Tests CLOCK_MONOTONIC(4), CLOCK_MONOTONIC_FAST(12), CLOCK_REALTIME(0)

print("=== PROBE 1199g: Timer resolution + cache timing ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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

local sc_clock = make_syscall(232) -- clock_gettime
local sc_mmap = make_syscall(477) -- mmap

-- timespec: {tv_sec (8 bytes), tv_nsec (8 bytes)} = 16 bytes
local ts1 = memory.alloc(16)
local ts2 = memory.alloc(16)

local function read_ns(ts_addr)
    local sec_lo = safe_rd(ts_addr)
    local sec_hi = safe_rd(ts_addr + 4)
    local nsec_lo = safe_rd(ts_addr + 8)
    local nsec_hi = safe_rd(ts_addr + 12)
    -- Return nanoseconds only (seconds * 1e9 overflows Lua numbers)
    -- Just return nsec part for delta measurement (same second)
    return (sec_lo or 0) * 1000000000 + (nsec_lo or 0)
end

local function read_nsec_only(ts_addr)
    return safe_rd(ts_addr + 8) or 0
end

local function read_sec(ts_addr)
    return safe_rd(ts_addr) or 0
end

-- ==========================================
-- SECTION A: Raw clock_gettime resolution
-- ==========================================
print("--- [A] clock_gettime resolution ---")

local clocks = {
    {id = 0, name = "CLOCK_REALTIME"},
    {id = 4, name = "CLOCK_MONOTONIC"},
    {id = 12, name = "CLOCK_MONOTONIC_FAST"},
}

for _, clk in ipairs(clocks) do
    -- Measure minimum delta over 200 consecutive calls
    local min_delta = 999999999
    local max_delta = 0
    local sum_delta = 0
    local count = 0
    local zeros = 0

    for i = 1, 200 do
        safe_wd(ts1, 0)
        safe_wd(ts1 + 4, 0)
        safe_wd(ts1 + 8, 0)
        safe_wd(ts1 + 12, 0)
        safe_wd(ts2, 0)
        safe_wd(ts2 + 4, 0)
        safe_wd(ts2 + 8, 0)
        safe_wd(ts2 + 12, 0)

        pcall(function() sc_clock(uint64(clk.id), uint64(ts1)) end)
        pcall(function() sc_clock(uint64(clk.id), uint64(ts2)) end)

        local s1 = read_sec(ts1)
        local s2 = read_sec(ts2)
        local ns1 = read_nsec_only(ts1)
        local ns2 = read_nsec_only(ts2)

        local delta
        if s1 == s2 then
            delta = ns2 - ns1
        else
            delta = (1000000000 - ns1) + ns2
        end

        if delta == 0 then
            zeros = zeros + 1
        elseif delta > 0 and delta < 999999999 then
            if delta < min_delta then min_delta = delta end
            if delta > max_delta then max_delta = delta end
            sum_delta = sum_delta + delta
            count = count + 1
        end
    end

    local avg = count > 0 and math.floor(sum_delta / count) or 0
    if min_delta == 999999999 then min_delta = 0 end
    print(string.format("  %s (id=%d):", clk.name, clk.id))
    print(string.format("    min=%d ns  avg=%d ns  max=%d ns  zeros=%d/200",
        min_delta, avg, max_delta, zeros))
end

-- ==========================================
-- SECTION B: Tight loop — 50 back-to-back calls
-- ==========================================
print("")
print("--- [B] 50 consecutive timestamps (CLOCK_MONOTONIC) ---")

local timestamps = {}
for i = 1, 50 do
    safe_wd(ts1, 0)
    safe_wd(ts1 + 4, 0)
    safe_wd(ts1 + 8, 0)
    safe_wd(ts1 + 12, 0)
    pcall(function() sc_clock(uint64(4), uint64(ts1)) end)
    timestamps[i] = {sec = read_sec(ts1), nsec = read_nsec_only(ts1)}
end

-- Print deltas
local deltas = {}
for i = 2, #timestamps do
    local d
    if timestamps[i].sec == timestamps[i-1].sec then
        d = timestamps[i].nsec - timestamps[i-1].nsec
    else
        d = (1000000000 - timestamps[i-1].nsec) + timestamps[i].nsec
    end
    table.insert(deltas, d)
end

-- Sort and show distribution
table.sort(deltas)
print(string.format("  min=%d ns  median=%d ns  max=%d ns",
    deltas[1], deltas[math.floor(#deltas/2)], deltas[#deltas]))

-- Show first 20 deltas
local first20 = {}
for i = 1, math.min(20, #deltas) do
    table.insert(first20, tostring(deltas[i]))
end
print("  sorted deltas (first 20): " .. table.concat(first20, ", "))

-- ==========================================
-- SECTION C: Cache timing test
-- ==========================================
print("")
print("--- [C] Cache vs eviction timing ---")

-- Allocate target page (one 16KB page)
local target = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local target_h, target_l = get_hi_lo(target)
if target_h >= 0xFFFF0000 then
    print("  FATAL: mmap failed for target")
else
    print(string.format("  target page: 0x%X%08X", target_h, target_l))

    -- Write known value to target
    safe_wd(target, 0xDEADBEEF)

    -- Allocate eviction buffer: 16 MB to flush L1+L2+L3
    -- Zen 2 has 8MB L3, 512KB L2, 32KB L1D per core
    -- 16MB should evict everything
    local evict_size = 16 * 1024 * 1024
    local evict = sc_mmap(uint64(0), uint64(evict_size), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local ev_h, ev_l = get_hi_lo(evict)
    if ev_h >= 0xFFFF0000 then
        print("  FATAL: mmap failed for eviction buffer")
    else
        print(string.format("  eviction buffer: 0x%X%08X (%d MB)", ev_h, ev_l, evict_size / 1048576))

        -- Test 1: Read target (should be cached from write above)
        local cached_times = {}
        for trial = 1, 20 do
            -- Warm: read target to ensure cached
            safe_rd(target)
            safe_rd(target)

            -- Time the read
            pcall(function() sc_clock(uint64(4), uint64(ts1)) end)
            safe_rd(target)
            pcall(function() sc_clock(uint64(4), uint64(ts2)) end)

            local d
            local s1, s2 = read_sec(ts1), read_sec(ts2)
            local n1, n2 = read_nsec_only(ts1), read_nsec_only(ts2)
            if s1 == s2 then d = n2 - n1 else d = (1000000000 - n1) + n2 end
            table.insert(cached_times, d)
        end

        -- Test 2: Evict then read target
        local evicted_times = {}
        for trial = 1, 20 do
            -- Evict: touch every cache line (64B) in 16MB
            -- To avoid being optimized out, actually read values
            local dummy = 0
            for off = 0, evict_size - 64, 4096 do
                -- Read one dword per page (enough to bring page into cache)
                local v = safe_rd(evict + uint64(off))
                if v then dummy = dummy + v end
            end

            -- Now time the (hopefully evicted) target read
            pcall(function() sc_clock(uint64(4), uint64(ts1)) end)
            safe_rd(target)
            pcall(function() sc_clock(uint64(4), uint64(ts2)) end)

            local d
            local s1, s2 = read_sec(ts1), read_sec(ts2)
            local n1, n2 = read_nsec_only(ts1), read_nsec_only(ts2)
            if s1 == s2 then d = n2 - n1 else d = (1000000000 - n1) + n2 end
            table.insert(evicted_times, d)
        end

        -- Results
        table.sort(cached_times)
        table.sort(evicted_times)

        local function stats(arr)
            local sum = 0
            for _, v in ipairs(arr) do sum = sum + v end
            return arr[1], math.floor(sum / #arr), arr[#arr]
        end

        local c_min, c_avg, c_max = stats(cached_times)
        local e_min, e_avg, e_max = stats(evicted_times)

        print(string.format("  CACHED:  min=%d  avg=%d  max=%d ns", c_min, c_avg, c_max))
        print(string.format("  EVICTED: min=%d  avg=%d  max=%d ns", e_min, e_avg, e_max))
        print(string.format("  RATIO: evicted/cached avg = %.1fx", e_avg / math.max(c_avg, 1)))

        -- Dump all values
        local c_str = {}
        for _, v in ipairs(cached_times) do table.insert(c_str, tostring(v)) end
        local e_str = {}
        for _, v in ipairs(evicted_times) do table.insert(e_str, tostring(v)) end
        print("  cached:  " .. table.concat(c_str, ","))
        print("  evicted: " .. table.concat(e_str, ","))

        if e_avg > c_avg * 2 then
            print("  ** DISTINGUISHABLE — clock_gettime can see cache effects **")
        elseif e_avg > c_avg * 1.3 then
            print("  ** MARGINAL — some signal but noisy **")
        else
            print("  ** NOT DISTINGUISHABLE — clock_gettime too coarse **")
        end
    end
end

-- ==========================================
-- SECTION D: Eviction with stride=64 (cache line)
-- ==========================================
print("")
print("--- [D] Heavy eviction (stride=64, 16MB) ---")

-- Same test but with finer eviction stride
local evict2 = sc_mmap(uint64(0), uint64(16 * 1024 * 1024), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ev2_h, ev2_l = get_hi_lo(evict2)
if ev2_h < 0xFFFF0000 then
    local evict2_times = {}
    for trial = 1, 10 do
        -- Heavy eviction: every 256 bytes across 16MB (65536 accesses)
        local dummy = 0
        for off = 0, 16 * 1024 * 1024 - 256, 256 do
            local v = safe_rd(evict2 + uint64(off))
            if v then dummy = dummy + v end
        end

        pcall(function() sc_clock(uint64(4), uint64(ts1)) end)
        safe_rd(target)
        pcall(function() sc_clock(uint64(4), uint64(ts2)) end)

        local s1, s2 = read_sec(ts1), read_sec(ts2)
        local n1, n2 = read_nsec_only(ts1), read_nsec_only(ts2)
        local d = (s1 == s2) and (n2 - n1) or ((1000000000 - n1) + n2)
        table.insert(evict2_times, d)
    end
    table.sort(evict2_times)
    local vals = {}
    for _, v in ipairs(evict2_times) do table.insert(vals, tostring(v)) end
    print(string.format("  min=%d  max=%d ns", evict2_times[1], evict2_times[#evict2_times]))
    print("  values: " .. table.concat(vals, ","))
end

print("")
print("=== PROBE 1199g COMPLETE ===")
