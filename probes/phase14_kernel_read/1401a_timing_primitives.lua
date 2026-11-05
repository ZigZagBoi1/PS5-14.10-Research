-- CRASH_CLASS: LOW
-- PROBE 1401a: Spectre timing primitives — clock_gettime + cache flush
--
-- Tests:
-- [A] clock_gettime resolution (CLOCK_MONOTONIC, CLOCK_REALTIME)
-- [B] rdtsc gadget test via fcall_with_rax (eboot+0x6A109, eboot+0x19BBD0)
-- [C] madvise(MADV_DONTNEED) as cache flush alternative
-- [D] Cache hit vs miss timing discrimination

print("=== 1401a: timing primitives ===")

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

-- Get eboot
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo then print("FAIL: no eboot") return end
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi or 0, text_lo))

-- ============================================================
-- [A] clock_gettime resolution
-- syscall 232: clock_gettime(clockid, timespec*)
-- CLOCK_REALTIME=0, CLOCK_MONOTONIC=4, CLOCK_MONOTONIC_FAST=12
-- timespec: { tv_sec(8), tv_nsec(8) }
-- ============================================================
print("")
print("=== [A] clock_gettime ===")

local sc_clock = make_syscall(232)
local ts_buf = memory.alloc(16)

local function read_ns(buf)
    local sec_lo = safe_rd(buf)
    local sec_hi = safe_rd(buf + 4)
    local ns_lo = safe_rd(buf + 8)
    return sec_lo, ns_lo
end

for _, clk in ipairs({0, 4, 12}) do
    local name = ({[0]="REALTIME", [4]="MONOTONIC", [12]="MONO_FAST"})[clk]
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(0))
    local ok, ret = pcall(function() return sc_clock(uint64(clk), uint64(ts_buf)) end)
    if ok then
        local _, rv = get_hi_lo(ret)
        local s, ns = read_ns(ts_buf)
        print(string.format("  %s: ret=%d sec=%d ns=%d", name, rv, s or 0, ns or 0))
    else
        print(string.format("  %s: FAIL", name))
    end
end

-- Resolution test: minimum delta between consecutive calls
print("")
print("  resolution test (100 deltas):")
local deltas = {}
for i = 1, 101 do
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(0))
    pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
    local _, ns = read_ns(ts_buf)
    if ns then deltas[#deltas + 1] = ns end
end

local min_delta = 999999999
local max_delta = 0
local nonzero = 0
for i = 2, #deltas do
    local d = deltas[i] - deltas[i-1]
    if d < 0 then d = d + 1000000000 end
    if d > 0 and d < min_delta then min_delta = d end
    if d > max_delta then max_delta = d end
    if d > 0 then nonzero = nonzero + 1 end
end

print(string.format("  min_delta=%d ns  max=%d ns  nonzero=%d/%d",
    min_delta, max_delta, nonzero, #deltas - 1))

-- Check if sub-microsecond resolution exists
local sub_us = 0
for i = 2, #deltas do
    local d = deltas[i] - deltas[i-1]
    if d < 0 then d = d + 1000000000 end
    if d > 0 and d < 1000 then sub_us = sub_us + 1 end
end
print(string.format("  sub_microsecond=%d/%d", sub_us, #deltas - 1))

-- ============================================================
-- [B] rdtsc gadget test
-- ============================================================
print("")
print("=== [B] rdtsc gadgets ===")

if type(native) ~= "table" or type(native.fcall_with_rax) ~= "function" then
    print("no native.fcall_with_rax — skip")
else
    -- Gadget 1: eboot+0x6A109 (0F 31 C0 C3)
    -- After rdtsc: C0 C3 = rol bl, imm8 (harmless register op)
    -- Question: does it eventually ret?
    local addr1 = eboot + uint64(0x6A109)
    print("  testing +0x6A109:")
    local ok1, v1 = pcall(function() return native.fcall_with_rax(addr1) end)
    if ok1 and v1 then
        local h, l = get_hi_lo(v1)
        print(string.format("  RET ok: 0x%X%08X", h, l))
        -- Second call to check if values differ (TSC should increment)
        local ok2, v2 = pcall(function() return native.fcall_with_rax(addr1) end)
        if ok2 and v2 then
            local h2, l2 = get_hi_lo(v2)
            print(string.format("  RET ok: 0x%X%08X", h2, l2))
            local d = l2 - l
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  delta=%d (TSC-like=%s)", d, d > 100 and d < 10000000 and "YES" or "NO"))
        end
    else
        print("  CRASH or -999")
    end

    -- Gadget 2: eboot+0x19BBD0 (0F 31 C0 48 83 C4 20 5B ... C3)
    -- After rdtsc: C0 48 83 C4 = ror [rax-0x7d], 0xC4 → memory access with TSC as addr → likely crash
    local addr2 = eboot + uint64(0x19BBD0)
    print("  testing +0x19BBD0:")
    local ok3, v3 = pcall(function() return native.fcall_with_rax(addr2) end)
    if ok3 and v3 then
        local h, l = get_hi_lo(v3)
        print(string.format("  RET ok: 0x%X%08X", h, l))
    else
        print("  CRASH (expected — C0 dereferences TSC as address)")
    end

    -- Gadget 3: try eboot+0x6A10A = 31 C0 C3 = xor eax,eax; ret
    -- Not rdtsc, but confirms fcall_with_rax works
    local addr3 = eboot + uint64(0x6A10A)
    print("  testing +0x6A10A (xor eax,eax; ret):")
    local ok4, v4 = pcall(function() return native.fcall_with_rax(addr3) end)
    if ok4 and v4 then
        local h, l = get_hi_lo(v4)
        print(string.format("  RET ok: 0x%X%08X (expect 0)", h, l))
    else
        print("  CRASH")
    end
end

-- ============================================================
-- [C] madvise as cache flush
-- madvise = syscall 75
-- MADV_DONTNEED = 4, MADV_FREE = 5
-- ============================================================
print("")
print("=== [C] madvise ===")

local sc_mmap = make_syscall(477)
local sc_madvise = make_syscall(75)
local sc_munmap = make_syscall(73)

-- Map 256 pages (256 * 16KB = 4MB) for probe array
local PAGE = 0x4000  -- 16KB pages on PS5
local probe_pages = 256
local probe_size = probe_pages * PAGE
local probe = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(probe_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then probe = v end
    end
end

if probe then
    local ph, pl = get_hi_lo(probe)
    print(string.format("  probe array: 0x%X%08X (%d pages)", ph, pl, probe_pages))

    -- Touch each page (write a marker)
    for i = 0, probe_pages - 1 do
        safe_wd(probe + uint64(i * PAGE), i)
    end
    print("  pages touched")

    -- madvise MADV_DONTNEED on the whole range
    local ok, ret = pcall(function()
        return sc_madvise(uint64(probe), uint64(probe_size), uint64(4))
    end)
    if ok then
        local _, rv = get_hi_lo(ret)
        print(string.format("  MADV_DONTNEED ret=%d", rv))

        -- After DONTNEED: pages should be zeroed on next access
        local z = 0
        for i = 0, math.min(15, probe_pages - 1) do
            local v = safe_rd(probe + uint64(i * PAGE))
            if v == 0 then z = z + 1 end
        end
        print(string.format("  zeroed pages after DONTNEED: %d/16", z))
    else
        print("  MADV_DONTNEED: FAIL")
    end

    -- Also test MADV_FREE (5)
    for i = 0, probe_pages - 1 do
        safe_wd(probe + uint64(i * PAGE), i + 1000)
    end
    local ok2, ret2 = pcall(function()
        return sc_madvise(uint64(probe), uint64(probe_size), uint64(5))
    end)
    if ok2 then
        local _, rv = get_hi_lo(ret2)
        print(string.format("  MADV_FREE ret=%d", rv))
    else
        print("  MADV_FREE: FAIL")
    end

    -- Cleanup
    pcall(function() sc_munmap(uint64(probe), uint64(probe_size)) end)
else
    print("  mmap FAIL")
end

-- ============================================================
-- [D] Cache timing discrimination
-- If clock_gettime has enough resolution, measure access time
-- to recently-accessed vs evicted pages
-- ============================================================
print("")
print("=== [D] cache timing ===")

-- Re-map a smaller probe (16 pages)
local small_pages = 16
local small_size = small_pages * PAGE
local small = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(small_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then small = v end
    end
end

if small and min_delta < 10000 then
    -- Timing test: access page, time it, evict, time again
    local hot_times = {}
    local cold_times = {}

    for trial = 1, 20 do
        -- Touch page 0
        safe_wd(small, 0xBEEF)

        -- Time HOT access
        safe_wq(ts_buf, uint64(0))
        safe_wq(ts_buf + 8, uint64(0))
        pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
        local _, ns1 = read_ns(ts_buf)

        local _ = safe_rd(small)

        safe_wq(ts_buf, uint64(0))
        safe_wq(ts_buf + 8, uint64(0))
        pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
        local _, ns2 = read_ns(ts_buf)

        if ns1 and ns2 then
            local d = ns2 - ns1
            if d < 0 then d = d + 1000000000 end
            hot_times[#hot_times + 1] = d
        end

        -- Evict via MADV_DONTNEED
        pcall(function() sc_madvise(uint64(small), uint64(small_size), uint64(4)) end)

        -- Time COLD access
        safe_wq(ts_buf, uint64(0))
        safe_wq(ts_buf + 8, uint64(0))
        pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
        local _, ns3 = read_ns(ts_buf)

        local _ = safe_rd(small)

        safe_wq(ts_buf, uint64(0))
        safe_wq(ts_buf + 8, uint64(0))
        pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
        local _, ns4 = read_ns(ts_buf)

        if ns3 and ns4 then
            local d = ns4 - ns3
            if d < 0 then d = d + 1000000000 end
            cold_times[#cold_times + 1] = d
        end
    end

    -- Stats
    local function stats(arr)
        if #arr == 0 then return 0, 0, 0 end
        table.sort(arr)
        local sum = 0
        for _, v in ipairs(arr) do sum = sum + v end
        return arr[1], arr[math.floor(#arr/2)+1], math.floor(sum/#arr)
    end

    local hmin, hmed, havg = stats(hot_times)
    local cmin, cmed, cavg = stats(cold_times)
    print(string.format("  HOT:  min=%d med=%d avg=%d ns (n=%d)", hmin, hmed, havg, #hot_times))
    print(string.format("  COLD: min=%d med=%d avg=%d ns (n=%d)", cmin, cmed, cavg, #cold_times))

    if cmed > hmed and (cmed - hmed) > 50 then
        print("  DISCRIMINATES: cold-hot=" .. (cmed - hmed) .. "ns")
    else
        print("  NO discrimination (too noisy or too fast)")
    end

    pcall(function() sc_munmap(uint64(small), uint64(small_size)) end)
else
    if not small then print("  mmap FAIL")
    else print("  clock too coarse (min_delta=" .. min_delta .. "ns)") end
end

print("")
print("=== 1401a DONE ===")
