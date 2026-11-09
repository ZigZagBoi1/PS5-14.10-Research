-- CRASH_CLASS: LOW
-- PROBE 95a: PMU cross-connection stability test
--
-- Context: Probes 92a/94a confirmed that sys 563-567 give full PMU access
-- from unprivileged code. Instruction counts per syscall are measurable
-- (~264K for getpid, ~521K for sysctl, ~271K for mmap).
--
-- For KASLR fingerprinting, we need the instruction counts to be STABLE
-- across connections (each connection = new process with fresh userland
-- ASLR but same kernel KASLR slide, which is per-boot).
--
-- This probe measures instruction counts for 7 syscalls, 5 samples each,
-- and prints a compact fingerprint line. Run it N times from the host
-- (each run = new TCP connection = new process) and compare the output.
--
-- Usage from host:
--   for i in $(seq 1 5); do
--     python3 tools/send_probe.py probes/phase17_new_vectors/95a_pmu_cross_connection_stability.lua \
--       --ip 192.168.1.35 --save --metadata --timeout 60
--     sleep 0.5
--   done
--
-- If the fingerprint lines match across runs → KASLR oracle is viable.
-- If they jitter → need averaging or different approach.

print("=== PROBE 95a: PMU CROSS-CONNECTION STABILITY ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc563 = make_syscall(563)  -- enable PMU
local sc564 = make_syscall(564)  -- disable PMU
local sc565 = make_syscall(565)  -- configure event selector
local sc566 = make_syscall(566)  -- write counter value
local sc567 = make_syscall(567)  -- read counter value
local sc432 = make_syscall(432)  -- thr_self
local sc20  = make_syscall(20)   -- getpid

-- Get TID
local tid_buf = memory.alloc(8)
safe_wq(tid_buf, uint64(0))
pcall(function() sc432(uint64(tid_buf)) end)
local our_tid = safe_rd(tid_buf) or 0

local ok, pid = pcall(function() return sc20() end)
print("PID: " .. (ok and fmt(pid) or "?") .. "  TID: " .. our_tid)
print("")

-- Output buffer for counter reads
local out = memory.alloc(16)

-- PMU setup: disable → configure retired instructions on index 0 → enable
pcall(function() sc564(uint64(0)) end)
pcall(function() sc565(uint64(0), uint64(0), uint64(0xC0)) end)
pcall(function() sc563(uint64(0)) end)

-- Verify PMU is working with a quick sanity check
pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
-- Do 10 nop syscalls
for i = 1, 10 do pcall(function() sc20() end) end
safe_wq(out, uint64(0))
pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
local sanity = safe_rq(out)
local sh, sl = get_hi_lo(sanity)
if sl == 0 and sh == 0 then
    print("ERROR: PMU counter not counting. Aborting.")
    print("=== PROBE 95a ABORTED ===")
    return
end
print("PMU sanity: " .. sl .. " instructions for 10x getpid — OK")
print("")

-- ============================================================
-- MEASUREMENT: 7 syscalls, 5 samples each
-- ============================================================
-- Strategy: for each syscall, we do:
--   1. Zero counter
--   2. Execute ONE target syscall
--   3. Read counter
-- The overhead of zero+read is constant and cancels in comparison.

local targets = {
    {20,  "getpid",     function(sc) sc(uint64(0)) end},
    {202, "sysctl",     function(sc)
        local mib = memory.alloc(8)
        memory.write_dword(mib, 1)      -- CTL_KERN
        memory.write_dword(mib + 4, 37) -- KERN_FEATURES (or similar)
        sc(uint64(mib), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0))
    end},
    {477, "mmap",       function(sc)
        sc(uint64(0), uint64(0x4000), uint64(3),
           uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end},
    {563, "pmu_enable", function(sc) sc(uint64(0)) end},
    {97,  "socket",     function(sc) sc(uint64(2), uint64(2), uint64(0)) end},
    {42,  "pipe",       function(sc)
        local pb = memory.alloc(16)
        sc(uint64(pb))
    end},
    {624, "vm_counter", function(sc) sc() end},
}

local SAMPLES = 5
local results = {}

print("--- Measuring instruction counts ---")
print(string.format("%-14s  %s", "syscall", table.concat({"s1","s2","s3","s4","s5","  median","  jitter"}, "      ")))

for _, tgt in ipairs(targets) do
    local sc_num, sc_name, sc_call = tgt[1], tgt[2], tgt[3]
    local sc_fn = make_syscall(sc_num)
    local counts = {}

    for s = 1, SAMPLES do
        -- Zero counter 0
        pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)

        -- Execute ONE target syscall
        pcall(function() sc_call(sc_fn) end)

        -- Read counter 0
        safe_wq(out, uint64(0))
        pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
        local val = safe_rq(out)
        local vh, vl = get_hi_lo(val)
        counts[s] = vl
    end

    -- Sort for median
    local sorted = {}
    for i = 1, SAMPLES do sorted[i] = counts[i] end
    table.sort(sorted)
    local median = sorted[math.ceil(SAMPLES / 2)]
    local jitter = sorted[SAMPLES] - sorted[1]
    local jitter_pct = median > 0 and (jitter / median * 100) or 0

    -- Format output
    local parts = {}
    for s = 1, SAMPLES do
        parts[s] = string.format("%8d", counts[s])
    end
    print(string.format("%-14s  %s  %8d  %5d (%.1f%%)",
        sc_name, table.concat(parts, "  "), median, jitter, jitter_pct))

    results[sc_name] = {median = median, jitter = jitter, counts = counts}
end

-- ============================================================
-- FINGERPRINT: compact line for cross-connection comparison
-- ============================================================
print("")
print("--- FINGERPRINT (compare across connections) ---")

-- Build fingerprint from medians, rounded to nearest 1000
local fp_parts = {}
for _, tgt in ipairs(targets) do
    local r = results[tgt[2]]
    if r then
        local rounded = math.floor(r.median / 1000) * 1000
        fp_parts[#fp_parts + 1] = tgt[2] .. "=" .. rounded
    end
end
local fingerprint = table.concat(fp_parts, " | ")
print("FP: " .. fingerprint)

-- Also print raw medians for precise comparison
local raw_parts = {}
for _, tgt in ipairs(targets) do
    local r = results[tgt[2]]
    if r then
        raw_parts[#raw_parts + 1] = string.format("%s=%d", tgt[2], r.median)
    end
end
print("RAW: " .. table.concat(raw_parts, " | "))

-- ============================================================
-- OVERHEAD MEASUREMENT: measure the zero+read overhead itself
-- ============================================================
print("")
print("--- Zero+read overhead ---")
local overhead_counts = {}
for s = 1, 5 do
    pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
    -- NO target syscall — just read immediately
    safe_wq(out, uint64(0))
    pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
    local val = safe_rq(out)
    local vh, vl = get_hi_lo(val)
    overhead_counts[s] = vl
end
table.sort(overhead_counts)
local oh_median = overhead_counts[3]
local oh_jitter = overhead_counts[5] - overhead_counts[1]
print(string.format("  overhead median: %d instructions, jitter: %d", oh_median, oh_jitter))
print("  (subtract this from all measurements for net kernel-only count)")

-- Cleanup
pcall(function() sc564(uint64(0)) end)

print("")
print("=== PROBE 95a COMPLETE ===")
print("Run this probe 5+ times and compare FP/RAW lines across connections.")
print("Stable fingerprint = KASLR oracle viable.")
