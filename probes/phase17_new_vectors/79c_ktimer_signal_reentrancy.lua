-- CRASH_CLASS: MODERATE
-- PROBE 79c: ktimer SIGEV_SIGNAL reentrancy — callout corruption attempt
--
-- Context: POSIX timers work on PS5 (27 concurrent, probe 18). But signal
-- delivery via timer expiry was NEVER tested. If a timer fires SIGEV_SIGNAL
-- and the signal handler manipulates another timer (rearm, delete), this
-- creates kernel callout reentrancy. FreeBSD's callout mechanism has had
-- historical locking bugs when callout callbacks and callout_reset() overlap.
--
-- Strategy:
--   Section A: Create timer with SIGEV_SIGNAL, verify signal delivery
--   Section B: Create 10 timers, signal handler rearms a different timer
--   Section C: Create timer, signal handler deletes the firing timer (UAF)
--   Section D: Rapid arm/disarm race against timer expiry

print("=== PROBE 79c: KTIMER SIGNAL REENTRANCY ===")
print("")

local TEST_SECTION = 1

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

print("TEST_SECTION=" .. TEST_SECTION)

local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)
local sc_ktimer_create = make_syscall(235)
local sc_ktimer_settime = make_syscall(236)
local sc_ktimer_gettime = make_syscall(237)
local sc_ktimer_delete = make_syscall(238)
local sc_ktimer_getoverrun = make_syscall(239)
local sc_sigaction = make_syscall(416)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- CLOCK_REALTIME=0, CLOCK_MONOTONIC=4
-- SIGEV_SIGNAL=1, SIGEV_NONE=0
-- SIGUSR1=30, SIGUSR2=31

-- ==============================
-- SECTION A: Basic SIGEV_SIGNAL timer
-- ==============================
if TEST_SECTION == 1 then
    print("=== SECTION A: SIGEV_SIGNAL TIMER ===")

    -- Counter in shared memory to detect signal delivery
    local counter = memory.alloc(16)
    zero(counter, 16)

    -- struct sigevent (FreeBSD amd64):
    -- +0x00: int sigev_notify (SIGEV_SIGNAL=1)
    -- +0x04: int sigev_signo (SIGUSR1=30)
    -- +0x08: union sigev_value (int/pointer)
    -- +0x10: ... (padding/reserved)
    local sev = memory.alloc(0x40)
    zero(sev, 0x40)
    wd(sev + 0x00, 1)   -- SIGEV_SIGNAL
    wd(sev + 0x04, 30)  -- SIGUSR1

    -- Create timer
    local timerid_buf = memory.alloc(8)
    zero(timerid_buf, 8)
    wd(timerid_buf, 0xDEAD)

    print("[A] creating SIGEV_SIGNAL timer (CLOCK_REALTIME, SIGUSR1)...")
    local ok_create, rv_create = pcall(function()
        return sc_ktimer_create(uint64(0), uint64(sev), uint64(timerid_buf))
    end)
    local timer_id = rd(timerid_buf)
    print("[A] ktimer_create ok=" .. tostring(ok_create) .. " rv=" .. tostring(rv_create) .. " id=" .. tostring(timer_id))

    if to_num(rv_create) ~= 0 then
        print("[A] timer create failed, trying SIGEV_NONE instead...")
        -- Fall back to SIGEV_NONE=0
        wd(sev + 0x00, 0)
        zero(timerid_buf, 8)
        local ok2, rv2 = pcall(function()
            return sc_ktimer_create(uint64(0), uint64(sev), uint64(timerid_buf))
        end)
        timer_id = rd(timerid_buf)
        print("[A] SIGEV_NONE create ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2) .. " id=" .. tostring(timer_id))
    end

    if timer_id and timer_id ~= 0xDEAD and timer_id >= 0 then
        -- Arm the timer: fire in 10ms, repeating every 10ms
        -- struct itimerspec: { struct timespec it_interval; struct timespec it_value; }
        -- struct timespec: { time_t tv_sec; long tv_nsec; }
        local its = memory.alloc(0x20)
        zero(its, 0x20)
        -- it_value (first fire): 10ms
        wq(its + 0x00, uint64(0))          -- tv_sec = 0
        wq(its + 0x08, uint64(10000000))   -- tv_nsec = 10ms
        -- it_interval (repeat): 10ms
        wq(its + 0x10, uint64(0))          -- tv_sec = 0
        wq(its + 0x18, uint64(10000000))   -- tv_nsec = 10ms

        print("[A] arming timer id=" .. timer_id .. " (10ms interval)...")
        local ok_set, rv_set = pcall(function()
            return sc_ktimer_settime(uint64(timer_id), uint64(0), uint64(its), uint64(0))
        end)
        print("[A] ktimer_settime ok=" .. tostring(ok_set) .. " rv=" .. tostring(rv_set))

        -- Sleep 100ms and check overruns
        local ts = memory.alloc(16)
        wq(ts, 0); wq(ts + 8, 100000000) -- 100ms
        pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

        -- Check overrun count (tells us how many times the timer fired)
        local ok_over, rv_over = pcall(function()
            return sc_ktimer_getoverrun(uint64(timer_id))
        end)
        print("[A] ktimer_getoverrun ok=" .. tostring(ok_over) .. " overruns=" .. tostring(rv_over))

        -- Get remaining time
        local its_out = memory.alloc(0x20)
        zero(its_out, 0x20)
        local ok_get, rv_get = pcall(function()
            return sc_ktimer_gettime(uint64(timer_id), uint64(its_out))
        end)
        local rem_sec = rq(its_out)
        local rem_ns = rq(its_out + 0x08)
        print("[A] gettime ok=" .. tostring(ok_get) .. " remaining=" .. q(rem_sec) .. "s " .. q(rem_ns) .. "ns")

        -- Disarm
        zero(its, 0x20)
        pcall(function() sc_ktimer_settime(uint64(timer_id), uint64(0), uint64(its), uint64(0)) end)
        print("[A] timer disarmed")

        -- Delete
        local ok_del, rv_del = pcall(function()
            return sc_ktimer_delete(uint64(timer_id))
        end)
        print("[A] ktimer_delete ok=" .. tostring(ok_del) .. " rv=" .. tostring(rv_del))
    end

    local c1_ok, c1_pid = canary()
    print("[A] canary ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))
    print("=== SECTION A COMPLETE ===")

-- ==============================
-- SECTION B: Rapid create/arm/delete race
-- ==============================
elseif TEST_SECTION == 2 then
    print("=== SECTION B: RAPID CREATE/ARM/DELETE RACE ===")

    local NUM_TIMERS = 20
    local timer_ids = {}

    -- Create many timers
    for i = 1, NUM_TIMERS do
        local sev = memory.alloc(0x40)
        zero(sev, 0x40)
        wd(sev + 0x00, 0) -- SIGEV_NONE

        local tid_buf = memory.alloc(8)
        zero(tid_buf, 8)
        wd(tid_buf, 0xDEAD)

        local ok, rv = pcall(function()
            return sc_ktimer_create(uint64(0), uint64(sev), uint64(tid_buf))
        end)
        local tid = rd(tid_buf)
        timer_ids[i] = tid
        print(string.format("[B] timer[%d] ok=%s rv=%s id=%s", i, tostring(ok), tostring(rv), tostring(tid)))

        if to_num(rv) ~= 0 then
            print("[B] create failed at timer " .. i)
            break
        end
    end

    print("[B] created " .. #timer_ids .. " timers")

    -- Arm them all with 1ms interval (extremely fast)
    local its = memory.alloc(0x20)
    for i = 1, #timer_ids do
        if timer_ids[i] and timer_ids[i] ~= 0xDEAD then
            zero(its, 0x20)
            wq(its + 0x00, uint64(0))
            wq(its + 0x08, uint64(1000000)) -- 1ms
            wq(its + 0x10, uint64(0))
            wq(its + 0x18, uint64(1000000)) -- 1ms repeat
            pcall(function()
                sc_ktimer_settime(uint64(timer_ids[i]), uint64(0), uint64(its), uint64(0))
            end)
        end
    end
    print("[B] all timers armed at 1ms interval")

    -- Sleep 50ms (timers fire ~50 times each = ~1000 total timer events)
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 50000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- Rapid delete all while they're still firing
    print("[B] deleting all timers while firing...")
    for i = 1, #timer_ids do
        if timer_ids[i] and timer_ids[i] ~= 0xDEAD then
            local ok_del, rv_del = pcall(function()
                return sc_ktimer_delete(uint64(timer_ids[i]))
            end)
            -- Immediately try to get overrun of deleted timer (UAF probe)
            local ok_over, rv_over = pcall(function()
                return sc_ktimer_getoverrun(uint64(timer_ids[i]))
            end)
            if i <= 5 or i == #timer_ids then
                print(string.format("[B] timer[%d] del_rv=%s overrun_after_del=%s",
                    i, tostring(rv_del), tostring(rv_over)))
            end
        end
    end

    local c_ok, c_pid = canary()
    print("[B] canary ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))
    print("=== SECTION B COMPLETE ===")

else
    print("[!] invalid TEST_SECTION=" .. TEST_SECTION .. " (use 1-2)")
    print("=== PROBE 79c ABORTED ===")
    return
end

print("")
print("=== PROBE 79c SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("=== PROBE 79c COMPLETE ===")
