-- CRASH_CLASS: LOW
-- PROBE 79d: ktimer lifecycle debug — isolate what kills timer operations
--
-- 79c: timers create OK but delete/getoverrun return -1 after sleep.
-- Test each operation immediately after create, without sleeping.
-- Isolate: is it settime that kills them? Or the sleep? Or the IDs wrong?

print("=== PROBE 79d: KTIMER LIFECYCLE DEBUG ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", N(v))
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local sc_getpid = mk(20)
local sc_ktimer_create = mk(235)
local sc_ktimer_settime = mk(236)
local sc_ktimer_gettime = mk(237)
local sc_ktimer_delete = mk(238)
local sc_ktimer_getoverrun = mk(239)
local sc_nanosleep = mk(240)

local pid = N(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("pid=" .. pid)

local sev = memory.alloc(0x40)
local tid_buf = memory.alloc(8)
local its = memory.alloc(0x20)
local its_out = memory.alloc(0x20)
local ts = memory.alloc(16)

local function test_timer(label, notify, do_arm, do_sleep_ms)
    -- Zero sigevent
    for i = 0, 0x3C, 4 do wd(N(sev) + i, 0) end
    wd(N(sev), notify)  -- SIGEV_NONE=0, SIGEV_SIGNAL=1
    if notify == 1 then wd(N(sev) + 4, 30) end -- SIGUSR1

    wd(N(tid_buf), 0xDEAD); wd(N(tid_buf)+4, 0)

    local ok_c, rv_c = pcall(function()
        return sc_ktimer_create(uint64(0), uint64(N(sev)), uint64(N(tid_buf)))
    end)
    local timer_id = rd(N(tid_buf)) or 0xDEAD
    local rc = ok_c and sgn(rv_c) or -999
    print(string.format("  [%s] create: rv=%d id=%d", label, rc, timer_id))

    if rc ~= 0 then return end

    -- Immediately check getoverrun (before any arm)
    local ok_o1, rv_o1 = pcall(function() return sc_ktimer_getoverrun(uint64(timer_id)) end)
    local o1 = ok_o1 and sgn(rv_o1) or -999
    print(string.format("  [%s] getoverrun(pre-arm): %d", label, o1))

    -- Immediately check gettime (before any arm)
    for i = 0, 0x1C, 4 do wd(N(its_out) + i, 0xAA) end
    local ok_g1, rv_g1 = pcall(function() return sc_ktimer_gettime(uint64(timer_id), uint64(N(its_out))) end)
    local g1 = ok_g1 and sgn(rv_g1) or -999
    print(string.format("  [%s] gettime(pre-arm): rv=%d", label, g1))

    if do_arm then
        -- Arm: fire in 100ms, no repeat
        for i = 0, 0x1C, 4 do wd(N(its) + i, 0) end
        wq(N(its) + 0x00, uint64(0))           -- it_interval.tv_sec = 0
        wq(N(its) + 0x08, uint64(0))           -- it_interval.tv_nsec = 0 (no repeat)
        wq(N(its) + 0x10, uint64(0))           -- it_value.tv_sec = 0
        wq(N(its) + 0x18, uint64(100000000))   -- it_value.tv_nsec = 100ms

        local ok_s, rv_s = pcall(function()
            return sc_ktimer_settime(uint64(timer_id), uint64(0), uint64(N(its)), uint64(0))
        end)
        local rs = ok_s and sgn(rv_s) or -999
        print(string.format("  [%s] settime(100ms): rv=%d", label, rs))

        -- Immediately check getoverrun (after arm, before expiry)
        local ok_o2, rv_o2 = pcall(function() return sc_ktimer_getoverrun(uint64(timer_id)) end)
        local o2 = ok_o2 and sgn(rv_o2) or -999
        print(string.format("  [%s] getoverrun(post-arm): %d", label, o2))

        -- Immediately check gettime (after arm, before expiry)
        for i = 0, 0x1C, 4 do wd(N(its_out) + i, 0xBB) end
        local ok_g2, rv_g2 = pcall(function() return sc_ktimer_gettime(uint64(timer_id), uint64(N(its_out))) end)
        local g2 = ok_g2 and sgn(rv_g2) or -999
        local rem_s = rq and rq(N(its_out) + 0x10) or rd(N(its_out) + 0x10)
        local rem_ns = rq and rq(N(its_out) + 0x18) or rd(N(its_out) + 0x18)
        print(string.format("  [%s] gettime(post-arm): rv=%d val_s=%s val_ns=%s",
            label, g2, tostring(rem_s), tostring(rem_ns)))
    end

    if do_sleep_ms and do_sleep_ms > 0 then
        wq(N(ts), uint64(0))
        wq(N(ts) + 8, uint64(do_sleep_ms * 1000000))
        pcall(function() sc_nanosleep(uint64(N(ts)), uint64(0)) end)
        print(string.format("  [%s] slept %dms", label, do_sleep_ms))

        -- Check after sleep
        local ok_o3, rv_o3 = pcall(function() return sc_ktimer_getoverrun(uint64(timer_id)) end)
        local o3 = ok_o3 and sgn(rv_o3) or -999
        print(string.format("  [%s] getoverrun(post-sleep): %d", label, o3))
    end

    -- Delete
    local ok_d, rv_d = pcall(function() return sc_ktimer_delete(uint64(timer_id)) end)
    local rd_v = ok_d and sgn(rv_d) or -999
    print(string.format("  [%s] delete: rv=%d", label, rd_v))
    print("")
end

-- Test A: SIGEV_NONE, no arm, no sleep — pure lifecycle
print("[A] SIGEV_NONE, no arm, no sleep")
test_timer("A", 0, false, 0)

-- Test B: SIGEV_NONE, arm 100ms, no sleep — check immediately after arm
print("[B] SIGEV_NONE, arm, no sleep")
test_timer("B", 0, true, 0)

-- Test C: SIGEV_NONE, arm 100ms, sleep 10ms — check before expiry
print("[C] SIGEV_NONE, arm, sleep 10ms (before expiry)")
test_timer("C", 0, true, 10)

-- Test D: SIGEV_NONE, arm 100ms, sleep 200ms — check after expiry
print("[D] SIGEV_NONE, arm, sleep 200ms (after expiry)")
test_timer("D", 0, true, 200)

-- Test E: SIGEV_SIGNAL, no arm — does create alone survive?
print("[E] SIGEV_SIGNAL(SIGUSR1), no arm")
test_timer("E", 1, false, 0)

-- Test F: SIGEV_SIGNAL, arm, no sleep
print("[F] SIGEV_SIGNAL(SIGUSR1), arm, no sleep")
test_timer("F", 1, true, 0)

-- Test G: try timer_create with CLOCK_MONOTONIC=4
print("[G] CLOCK_MONOTONIC + SIGEV_NONE, arm, sleep 200ms")
for i = 0, 0x3C, 4 do wd(N(sev) + i, 0) end
wd(N(tid_buf), 0xDEAD)
local ok_g, rv_g = pcall(function()
    return sc_ktimer_create(uint64(4), uint64(N(sev)), uint64(N(tid_buf)))
end)
local gid = rd(N(tid_buf)) or 0xDEAD
print(string.format("  [G] create(MONO): rv=%d id=%d", ok_g and sgn(rv_g) or -999, gid))
if ok_g and sgn(rv_g) == 0 then
    local ok_gd, rv_gd = pcall(function() return sc_ktimer_delete(uint64(gid)) end)
    print(string.format("  [G] delete: rv=%d", ok_gd and sgn(rv_gd) or -999))
end

-- Test H: What does the raw return value look like for getoverrun?
-- Maybe it's not -1 but a large positive (overrun count)
print("")
print("[H] Raw return examination")
for i = 0, 0x3C, 4 do wd(N(sev) + i, 0) end
wd(N(tid_buf), 0xDEAD)
pcall(function() sc_ktimer_create(uint64(0), uint64(N(sev)), uint64(N(tid_buf))) end)
local hid = rd(N(tid_buf)) or 0xDEAD
if hid ~= 0xDEAD then
    local ok_h, rv_h = pcall(function() return sc_ktimer_getoverrun(uint64(hid)) end)
    if ok_h then
        print(string.format("  raw overrun value: %s (dec: %s)", q(rv_h), tostring(rv_h)))
        if type(rv_h) == "table" and rv_h.h then
            print(string.format("  hi=0x%08X lo=0x%08X", rv_h.h, rv_h.l))
        end
    else
        print("  getoverrun pcall failed")
    end
    pcall(function() sc_ktimer_delete(uint64(hid)) end)
end

local ok_f, pid_f = pcall(function() return sc_getpid() end)
print("")
print("final canary=" .. tostring(pid_f and N(pid_f) or "FAIL"))
print("=== 79d COMPLETE ===")
