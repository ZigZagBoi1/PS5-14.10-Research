-- CRASH_CLASS: MODERATE (thr_create may panic if race lost)
-- PROBE 105a: EVFILT_PROC on thr_create + pipe2 + ktimer signal reentrancy
--
-- Context (GOLD_VECTORS 2026-10-19):
--   Vector 4: kevent EVFILT_PROC has NEVER been tested. EVFILT_TIMER/USER/SIGNAL
--   all work (probes 20/21). EVFILT_PROC monitors process events — thread exit,
--   fault signals, child status. The kn_data/kn_fflags in older FreeBSD could
--   contain kernel addresses (struct thread*, trap frame addr).
--
--   Vector 7: pipe2(542) via make_syscall NEVER tested. pipe via resolve() = -1,
--   but sysctl via resolve() also = -1 and works via make_syscall.
--
--   Vector 8: ktimer + SIGEV_SIGNAL reentrancy NEVER tested. 27 concurrent
--   timers work, but signal delivery from timers untested.
--
-- Section A: EVFILT_PROC on our own PID (fault/exit/fork monitoring)
-- Section B: pipe2(542) via make_syscall + SCM_RIGHTS test
-- Section C: ktimer SIGEV_SIGNAL arm + signal handler reentrancy
-- Section D: Combined: EVFILT_PROC registered + thr_create(430) + kevent poll

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 105a: EVFILT_PROC + PIPE2 + KTIMER SIGNAL ===")
print("Section: " .. TEST_SECTION)
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
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc20 = make_syscall(20)    -- getpid
local sc624 = make_syscall(624)  -- VM counter (stability)

-- Get our PID
local ok_pid, pid = pcall(function() return sc20() end)
local our_pid = ok_pid and to_num(pid) or 0
print("PID: " .. our_pid)
print("")

if TEST_SECTION == "A" then
    print("--- Section A: EVFILT_PROC on our own PID ---")
    print("  kevent works for TIMER/USER/SIGNAL/READ (probes 20/21)")
    print("  EVFILT_PROC has NEVER been tested on 14.10")
    print("")

    -- kqueue(362) + kevent(363)
    local sc362 = make_syscall(362)  -- kqueue
    local sc363 = make_syscall(363)  -- kevent

    -- Create kqueue
    print("[A1] Create kqueue:")
    local ok_kq, kq = pcall(function() return sc362() end)
    local kq_fd = ok_kq and to_num(kq) or -1
    print("  kqueue: fd=" .. kq_fd)
    if kq_fd < 0 then
        print("  kqueue failed — abort")
        return
    end
    print("")

    -- kevent structures:
    -- struct kevent {
    --   uintptr_t ident;    // +0x00 (8 bytes) — pid for EVFILT_PROC
    --   short     filter;   // +0x08 (2 bytes) — EVFILT_PROC = -5
    --   u_short   flags;    // +0x0A (2 bytes) — EV_ADD = 1
    --   u_int     fflags;   // +0x0C (4 bytes) — NOTE_EXIT=0x80000000, NOTE_FORK=0x40000000
    --   intptr_t  data;     // +0x10 (8 bytes)
    --   void     *udata;    // +0x18 (8 bytes)
    -- } -- total 0x20 bytes

    local EVFILT_PROC = -5
    -- In two's complement int16: -5 = 0xFFFB
    local EV_ADD = 1
    local EV_ENABLE = 4
    local EV_CLEAR = 0x20
    local NOTE_EXIT = 0x80000000
    local NOTE_FORK = 0x40000000
    local NOTE_EXEC = 0x20000000
    local NOTE_TRACK = 0x00000001

    -- Register EVFILT_PROC for our own PID
    print("[A2] Register EVFILT_PROC for PID=" .. our_pid .. ":")
    local changelist = memory.alloc(0x40)  -- one kevent struct
    -- ident = our PID
    safe_wq(changelist, uint64(our_pid))
    -- filter = EVFILT_PROC = -5 (0xFFFB as int16), flags = EV_ADD|EV_ENABLE|EV_CLEAR
    -- Combined: filter(2B) + flags(2B) = 0xFFFB at +8, flags at +0A
    safe_wd(changelist + 0x08, 0xFFFB)     -- filter = -5
    safe_wd(changelist + 0x0A, EV_ADD + EV_ENABLE + EV_CLEAR)  -- flags
    -- fflags = NOTE_EXIT | NOTE_FORK | NOTE_EXEC | NOTE_TRACK
    safe_wd(changelist + 0x0C, NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK)
    -- data = 0
    safe_wq(changelist + 0x10, uint64(0))
    -- udata = 0x4141414141414141 (marker)
    safe_wq(changelist + 0x18, uint64("0x4141414141414141"))

    -- kevent(kq, changelist, nchanges=1, eventlist=NULL, nevents=0, timeout=NULL)
    -- This registers the event without waiting
    local ok_ev, rv_ev = pcall(function()
        return sc363(uint64(kq_fd), uint64(changelist), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)
    print("  kevent(EV_ADD EVFILT_PROC): ret=" .. (ok_ev and fmt(rv_ev) or "PCALL-FAIL"))
    if ok_ev and to_num(rv_ev) ~= 0 then
        -- Check if there's an error event returned
        print("  Registration may have failed (ret != 0)")
    end
    print("")

    -- Now poll for any events (zero timeout)
    print("[A3] Poll for events (zero timeout):")
    local eventlist = memory.alloc(0x40)
    local timeout = memory.alloc(0x10)
    safe_wq(timeout, uint64(0))      -- tv_sec = 0
    safe_wq(timeout + 8, uint64(0))  -- tv_nsec = 0

    -- Clear eventlist
    for i = 0, 7 do safe_wq(eventlist + i * 8, uint64(0)) end

    local ok_poll, rv_poll = pcall(function()
        return sc363(uint64(kq_fd), uint64(0), uint64(0),
            uint64(eventlist), uint64(1), uint64(timeout))
    end)
    local nevents = ok_poll and to_num(rv_poll) or -1
    print("  kevent poll: ret=" .. (ok_poll and fmt(rv_poll) or "PCALL-FAIL") ..
        " events=" .. nevents)

    if nevents > 0 then
        print("  *** EVFILT_PROC EVENT RECEIVED ***")
        local ev_ident = safe_rq(eventlist)
        local ev_filter = safe_rd(eventlist + 0x08)
        local ev_flags = safe_rd(eventlist + 0x0A)
        local ev_fflags = safe_rd(eventlist + 0x0C)
        local ev_data = safe_rq(eventlist + 0x10)
        local ev_udata = safe_rq(eventlist + 0x18)
        print(string.format("    ident=%s filter=0x%X flags=0x%X fflags=0x%X",
            ev_ident and fmt(ev_ident) or "?",
            ev_filter or 0, ev_flags or 0, ev_fflags or 0))
        print(string.format("    data=%s udata=%s",
            ev_data and fmt(ev_data) or "?",
            ev_udata and fmt(ev_udata) or "?"))
        -- Check for kernel pointers in data
        if ev_data then
            local dh, dl = get_hi_lo(ev_data)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                print("    *** KERNEL POINTER IN DATA: " .. fmt(ev_data) .. " ***")
            end
        end
    end
    print("")

    -- Also test EVFILT_PROC registration as individual notes
    print("[A4] Individual note registration:")
    local notes = {
        {NOTE_EXIT, "NOTE_EXIT"},
        {NOTE_FORK, "NOTE_FORK"},
        {NOTE_EXEC, "NOTE_EXEC"},
        {NOTE_TRACK, "NOTE_TRACK"},
        {1, "NOTE_CHILD??"},
    }
    for _, note in ipairs(notes) do
        for i = 0, 7 do safe_wq(changelist + i * 8, uint64(0)) end
        safe_wq(changelist, uint64(our_pid))
        safe_wd(changelist + 0x08, 0xFFFB)
        safe_wd(changelist + 0x0A, EV_ADD + EV_ENABLE)
        safe_wd(changelist + 0x0C, note[1])
        safe_wq(changelist + 0x10, uint64(0))

        local ok_n, rv_n = pcall(function()
            return sc363(uint64(kq_fd), uint64(changelist), uint64(1),
                uint64(0), uint64(0), uint64(0))
        end)
        print(string.format("  %s (0x%X): ret=%s",
            note[2], note[1], ok_n and fmt(rv_n) or "FAIL"))
    end
    print("")

    -- Stability
    print("[A5] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: pipe2(542) via make_syscall ---")
    print("  pipe via resolve() = -1. sysctl via resolve() also -1 but works via make_syscall")
    print("  pipe2(542) has NEVER been tested via make_syscall")
    print("")

    -- pipe2(542): arg0 = int fildes[2] (output array), arg1 = flags
    local sc542 = make_syscall(542)  -- pipe2
    local sc42 = make_syscall(42)    -- pipe (legacy)

    -- Also test legacy pipe(42) again via make_syscall
    print("[B1] Legacy pipe(42) via make_syscall:")
    local pipe_fds = memory.alloc(16)
    safe_wd(pipe_fds, 0xFFFFFFFF)
    safe_wd(pipe_fds + 4, 0xFFFFFFFF)
    local ok42, rv42 = pcall(function() return sc42(uint64(pipe_fds)) end)
    local fd0_42 = safe_rd(pipe_fds)
    local fd1_42 = safe_rd(pipe_fds + 4)
    print(string.format("  pipe(42): ret=%s fd0=%d fd1=%d",
        ok42 and fmt(rv42) or "FAIL", fd0_42 or -1, fd1_42 or -1))
    print("")

    -- pipe2(542) with flags=0
    print("[B2] pipe2(542) flags=0:")
    safe_wd(pipe_fds, 0xFFFFFFFF)
    safe_wd(pipe_fds + 4, 0xFFFFFFFF)
    local ok542a, rv542a = pcall(function()
        return sc542(uint64(pipe_fds), uint64(0))
    end)
    local fd0_a = safe_rd(pipe_fds)
    local fd1_a = safe_rd(pipe_fds + 4)
    print(string.format("  pipe2(0): ret=%s fd0=%d fd1=%d",
        ok542a and fmt(rv542a) or "FAIL", fd0_a or -1, fd1_a or -1))

    if ok542a and to_num(rv542a) == 0 and (fd0_a or 0) > 0 then
        print("  *** PIPE2 WORKS! ***")
        print("  Pipe fds: " .. (fd0_a or -1) .. ", " .. (fd1_a or -1))

        -- Test write/read
        local write_buf = memory.alloc(16)
        safe_wd(write_buf, 0xDEADBEEF)
        local sc4 = make_syscall(4)   -- write
        local sc3 = make_syscall(3)   -- read
        local ok_w, rv_w = pcall(function()
            return sc4(uint64(fd1_a), uint64(write_buf), uint64(4))
        end)
        print("  write(pipe[1], 4): ret=" .. (ok_w and fmt(rv_w) or "FAIL"))

        local read_buf = memory.alloc(16)
        safe_wd(read_buf, 0)
        local ok_r, rv_r = pcall(function()
            return sc3(uint64(fd0_a), uint64(read_buf), uint64(4))
        end)
        local rd_val = safe_rd(read_buf) or 0
        print(string.format("  read(pipe[0], 4): ret=%s val=0x%X (expect 0xDEADBEEF)",
            ok_r and fmt(rv_r) or "FAIL", rd_val))
        if rd_val == 0xDEADBEEF then
            print("  *** FULL PIPE WORKING — kernel pipe objects allocated! ***")
        end
    end
    print("")

    -- pipe2 with O_CLOEXEC | O_NONBLOCK
    print("[B3] pipe2(542) flags=O_CLOEXEC|O_NONBLOCK:")
    safe_wd(pipe_fds, 0xFFFFFFFF)
    safe_wd(pipe_fds + 4, 0xFFFFFFFF)
    local O_CLOEXEC = 0x100000
    local O_NONBLOCK = 0x4
    local ok542b, rv542b = pcall(function()
        return sc542(uint64(pipe_fds), uint64(O_CLOEXEC + O_NONBLOCK))
    end)
    local fd0_b = safe_rd(pipe_fds)
    local fd1_b = safe_rd(pipe_fds + 4)
    print(string.format("  pipe2(0x%X): ret=%s fd0=%d fd1=%d",
        O_CLOEXEC + O_NONBLOCK,
        ok542b and fmt(rv542b) or "FAIL", fd0_b or -1, fd1_b or -1))
    print("")

    -- Stability
    print("[B4] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: ktimer SIGEV_SIGNAL reentrancy ---")
    print("  27 concurrent timers work. Signal delivery NEVER tested.")
    print("")

    local sc235 = make_syscall(235)  -- ktimer_create
    local sc236 = make_syscall(236)  -- ktimer_settime
    local sc237 = make_syscall(237)  -- ktimer_gettime
    local sc238 = make_syscall(238)  -- ktimer_getoverrun

    -- CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 4
    -- SIGEV_SIGNAL = 1, SIGEV_NONE = 0
    -- struct sigevent {
    --   int sigev_notify;          // +0x00 (4B)
    --   int sigev_signo;           // +0x04 (4B)
    --   union sigval sigev_value;  // +0x08 (8B)
    --   ... (padding to 0x38)
    -- }

    -- Create timer with SIGEV_NONE first (safe baseline)
    print("[C1] Timer with SIGEV_NONE (baseline):")
    local sev = memory.alloc(0x40)
    local timerid_ptr = memory.alloc(8)
    safe_wd(sev, 0)           -- SIGEV_NONE
    safe_wd(sev + 4, 0)       -- signo (irrelevant)
    safe_wq(sev + 8, uint64(0))  -- sigval

    safe_wd(timerid_ptr, 0xFFFFFFFF)
    local ok_tc, rv_tc = pcall(function()
        return sc235(uint64(0), uint64(sev), uint64(timerid_ptr))
    end)
    local timer0 = safe_rd(timerid_ptr) or -1
    print(string.format("  timer_create(NONE): ret=%s timerid=%d",
        ok_tc and fmt(rv_tc) or "FAIL", timer0))

    -- Arm it with 100ms interval
    if ok_tc and to_num(rv_tc) == 0 then
        local itimerspec = memory.alloc(0x20)
        -- it_interval (repeat)
        safe_wq(itimerspec, uint64(0))          -- tv_sec = 0
        safe_wq(itimerspec + 8, uint64(100000000))  -- tv_nsec = 100ms
        -- it_value (initial)
        safe_wq(itimerspec + 0x10, uint64(0))
        safe_wq(itimerspec + 0x18, uint64(100000000))

        local ok_st, rv_st = pcall(function()
            return sc236(uint64(timer0), uint64(0), uint64(itimerspec), uint64(0))
        end)
        print("  timer_settime: ret=" .. (ok_st and fmt(rv_st) or "FAIL"))

        -- Check overrun count
        local ok_ov, rv_ov = pcall(function()
            return sc238(uint64(timer0))
        end)
        print("  timer_getoverrun: ret=" .. (ok_ov and fmt(rv_ov) or "FAIL"))
    end
    print("")

    -- Now create timer with SIGEV_SIGNAL
    print("[C2] Timer with SIGEV_SIGNAL (SIGUSR1=30):")
    for i = 0, 15 do safe_wd(sev + i * 4, 0) end
    safe_wd(sev, 1)          -- SIGEV_SIGNAL
    safe_wd(sev + 4, 30)     -- SIGUSR1
    safe_wq(sev + 8, uint64(0x42424242))  -- sigval = marker

    safe_wd(timerid_ptr, 0xFFFFFFFF)
    local ok_tc2, rv_tc2 = pcall(function()
        return sc235(uint64(0), uint64(sev), uint64(timerid_ptr))
    end)
    local timer1 = safe_rd(timerid_ptr) or -1
    print(string.format("  timer_create(SIGNAL): ret=%s timerid=%d",
        ok_tc2 and fmt(rv_tc2) or "FAIL", timer1))

    if ok_tc2 and to_num(rv_tc2) == 0 then
        print("  *** SIGEV_SIGNAL TIMER CREATED ***")
        -- Don't arm it yet — just verify creation works
        -- Arming would deliver SIGUSR1 which might kill us if no handler

        -- Try SIGEV_THREAD_ID (delivers to specific thread)
        print("[C3] Timer with SIGEV_THREAD_ID:")
        for i = 0, 15 do safe_wd(sev + i * 4, 0) end
        safe_wd(sev, 4)          -- SIGEV_THREAD_ID (FreeBSD-specific)
        safe_wd(sev + 4, 30)     -- SIGUSR1
        safe_wq(sev + 8, uint64(0x43434343))
        -- _sigev_thread_id typically at sev+0x30 or sev+0x20
        -- FreeBSD: sev->sigev_notify_thread_id at different offset
        -- Try storing our PID at various offsets
        safe_wd(sev + 0x20, our_pid)  -- some FreeBSD versions
        safe_wd(sev + 0x30, our_pid)  -- others

        safe_wd(timerid_ptr, 0xFFFFFFFF)
        local ok_tc3, rv_tc3 = pcall(function()
            return sc235(uint64(0), uint64(sev), uint64(timerid_ptr))
        end)
        local timer2 = safe_rd(timerid_ptr) or -1
        print(string.format("  timer_create(THREAD_ID): ret=%s timerid=%d",
            ok_tc3 and fmt(rv_tc3) or "FAIL", timer2))
    end
    print("")

    -- Stability
    print("[C4] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: EVFILT_PROC + thr_create(430) + kevent poll ---")
    print("  WARNING: thr_create(430) panics the kernel (CS=0 root cause)")
    print("  This section is HIGH risk — only run if you can afford a reboot")
    print("")

    local sc362 = make_syscall(362)
    local sc363 = make_syscall(363)
    local sc430 = make_syscall(430)

    -- Step 1: Create kqueue
    print("[D1] Create kqueue:")
    local ok_kq, kq = pcall(function() return sc362() end)
    local kq_fd = ok_kq and to_num(kq) or -1
    print("  kqueue: fd=" .. kq_fd)
    if kq_fd < 0 then return end
    print("")

    -- Step 2: Register EVFILT_PROC for our PID
    print("[D2] Register EVFILT_PROC:")
    local changelist = memory.alloc(0x40)
    safe_wq(changelist, uint64(our_pid))
    safe_wd(changelist + 0x08, 0xFFFB)  -- EVFILT_PROC
    safe_wd(changelist + 0x0A, 1 + 4 + 0x20)  -- EV_ADD|EV_ENABLE|EV_CLEAR
    safe_wd(changelist + 0x0C, 0x80000000 + 0x40000000 + 0x00000001)  -- NOTE_EXIT|FORK|TRACK

    local ok_reg, rv_reg = pcall(function()
        return sc363(uint64(kq_fd), uint64(changelist), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)
    print("  register: ret=" .. (ok_reg and fmt(rv_reg) or "FAIL"))
    print("")

    -- Step 3: thr_create with CS=0x43/SS=0x3B (the fix hypothesis)
    print("[D3] thr_create(430) with CS=0x43/SS=0x3B:")
    local ctx = memory.alloc(0x200)
    for i = 0, 0x1FF do
        if i % 4 == 0 then safe_wd(ctx + i, 0) end
    end
    -- Set CS and SS per the fix hypothesis
    safe_wd(ctx + 0xC0, 0x43)    -- CS = user code segment
    safe_wd(ctx + 0x100, 0x3B)   -- SS = user stack segment
    -- Set RFLAGS to something safe
    safe_wd(ctx + 0xC8, 0x202)   -- RFLAGS: IF set
    -- RIP = 0 (will fault but should SIGSEGV, not panic)

    local tid_ptr = memory.alloc(8)
    safe_wq(tid_ptr, uint64(0xDEADDEAD))

    print("  *** CALLING thr_create — MAY PANIC ***")
    local ok_thr, rv_thr = pcall(function()
        return sc430(uint64(ctx), uint64(tid_ptr))
    end)
    local tid = safe_rq(tid_ptr)
    print(string.format("  thr_create: ret=%s tid=%s",
        ok_thr and fmt(rv_thr) or "FAIL",
        tid and fmt(tid) or "?"))

    -- If we survived, poll kevent
    print("")
    print("[D4] Poll kevent for EVFILT_PROC events:")
    local eventlist = memory.alloc(0x100)  -- room for 4 events
    local timeout = memory.alloc(0x10)
    safe_wq(timeout, uint64(0))
    safe_wq(timeout + 8, uint64(100000000))  -- 100ms timeout

    for i = 0, 15 do safe_wq(eventlist + i * 8, uint64(0)) end

    local ok_poll, rv_poll = pcall(function()
        return sc363(uint64(kq_fd), uint64(0), uint64(0),
            uint64(eventlist), uint64(4), uint64(timeout))
    end)
    local nevents = ok_poll and to_num(rv_poll) or 0
    print("  kevent poll: nevents=" .. nevents)

    for ev = 0, nevents - 1 do
        local base = eventlist + ev * 0x20
        local ident = safe_rq(base)
        local filter = safe_rd(base + 0x08)
        local flags = safe_rd(base + 0x0A)
        local fflags = safe_rd(base + 0x0C)
        local data = safe_rq(base + 0x10)
        local udata = safe_rq(base + 0x18)
        print(string.format("  Event %d: ident=%s filter=0x%X flags=0x%X fflags=0x%X",
            ev, ident and fmt(ident) or "?",
            filter or 0, flags or 0, fflags or 0))
        print(string.format("    data=%s udata=%s",
            data and fmt(data) or "?",
            udata and fmt(udata) or "?"))
        -- Kernel pointer check
        if data then
            local dh, dl = get_hi_lo(data)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                print("    *** KERNEL POINTER IN DATA ***")
            end
        end
    end
    print("")

    -- Stability
    print("[D5] Stability (if we survived):")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 105a COMPLETE ===")
