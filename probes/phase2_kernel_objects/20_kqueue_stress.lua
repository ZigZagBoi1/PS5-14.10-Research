-- 14.10 Recon Probe 20: kqueue/kevent stress test
-- kqueue is the other half of the Lapse exploit (CVE-2024-43102)
-- The bug: race between kqueue event delivery and AIO completion
-- Even without AIO, kqueue itself has had many bugs:
--   - knote use-after-free on concurrent close+kevent
--   - EVFILT_PROC reference counting bugs
--   - kevent registration/deletion races
-- Single-threaded tests: register many events, delete FDs while
-- events pending, re-register on closed FDs, test edge cases

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: KQUEUE STRESS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_kqueue = 362,
    sc_kevent = 363,
    sc_close = 6,
    sc_write = 4,
    sc_read = 3,
    sc_socketpair = 135,
    sc_getpid = 20,
    sc_open = 5,
    sc_pipe2 = 542,    -- pipe2(fds, flags) — writes to pointer
})

-- ============================================================
-- PART 1: Basic kqueue creation
-- ============================================================
log("")
log("--- PART 1: kqueue creation ---")

local kq_ok, kq_ret = pcall(function() return syscall.sc_kqueue() end)
local kq = kq_ok and kq_ret:tonumber() or -1
log("  kqueue: " .. (kq_ok and "fd=" .. kq or "FAIL"))

if kq < 0 then
    log("FATAL: kqueue unavailable")
    return table.concat(out, "\n")
end

-- ============================================================
-- PART 2: Create FDs for kevent sources
-- Use pipe2 (writes fds to pointer unlike pipe)
-- ============================================================
log("")
log("--- PART 2: create pipe FDs ---")

local pipes = {}
for i = 1, 10 do
    local fds = memory.alloc(8)
    memory.write_dword(fds, 0xFFFF)
    memory.write_dword(fds + 4, 0xFFFF)
    -- pipe2(fds, 0) — no flags
    local p_ok, p_ret = pcall(function() return syscall.sc_pipe2(fds, 1) end)
    local rv = p_ok and p_ret:tonumber() or -999
    local r = memory.read_dword(fds):tonumber()
    local w = memory.read_dword(fds + 4):tonumber()
    if r ~= 0xFFFF and r > 0 and w > 0 then
        pipes[#pipes + 1] = {rfd = r, wfd = w}
    elseif rv >= 0 and r == 0xFFFF then
        -- pipe2 might also return via rv like pipe
        log("  pipe2 rv=" .. rv .. " but didn't write fds")
    end
end
log("  pipes created: " .. #pipes)

-- If pipe2 didn't work, try socketpair
if #pipes == 0 then
    log("  falling back to socketpair...")
    for i = 1, 10 do
        local sp = memory.alloc(8)
        local sp_ok = pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
        if sp_ok then
            local s0 = memory.read_dword(sp):tonumber()
            local s1 = memory.read_dword(sp + 4):tonumber()
            if s0 > 0 and s1 > 0 then
                pipes[#pipes + 1] = {rfd = s0, wfd = s1}
            end
        end
    end
    log("  socketpairs created: " .. #pipes)
end

if #pipes < 2 then
    log("FATAL: not enough FDs")
    return table.concat(out, "\n")
end

-- ============================================================
-- PART 3: Register kevent READ filters on pipe read ends
-- struct kevent (FreeBSD amd64):
--   uintptr_t ident;    // +0  (8) — fd number
--   short     filter;   // +8  (2) — EVFILT_READ=-1
--   u_short   flags;    // +10 (2) — EV_ADD=1
--   u_int     fflags;   // +12 (4)
--   int64_t   data;     // +16 (8)
--   void*     udata;    // +24 (8)
-- Total: 32 bytes per kevent
-- ============================================================
log("")
log("--- PART 3: kevent registration ---")

local KEVENT_SIZE = 32
local EV_ADD = 0x0001
local EV_DELETE = 0x0002
local EV_ENABLE = 0x0004
local EV_DISABLE = 0x0008
local EV_ONESHOT = 0x0010
local EV_CLEAR = 0x0020
local EV_EOF = 0x8000
local EVFILT_READ = -1   -- stored as 0xFFFF in unsigned short

-- Register READ events on all pipe read ends
local changelist = memory.alloc(#pipes * KEVENT_SIZE + 64)
for i, p in ipairs(pipes) do
    local off = (i - 1) * KEVENT_SIZE
    memory.write_qword(changelist + off + 0, p.rfd)        -- ident = fd
    memory.write_word(changelist + off + 8, 0xFFFF)         -- filter = EVFILT_READ (-1 as uint16)
    memory.write_word(changelist + off + 10, EV_ADD)        -- flags = EV_ADD
    memory.write_dword(changelist + off + 12, 0)            -- fflags
    memory.write_qword(changelist + off + 16, 0)            -- data
    memory.write_qword(changelist + off + 24, i)            -- udata = index
end

-- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
-- Register only (no wait): eventlist can be valid ptr, nevents=0
-- IMPORTANT: don't pass 0 for pointers — pass valid memory
local eventlist = memory.alloc(32 * KEVENT_SIZE)
local timeout = memory.alloc(16)
memory.write_qword(timeout, 0)      -- tv_sec = 0
memory.write_qword(timeout + 8, 0)  -- tv_nsec = 0

local ke_ok, ke_ret = pcall(function()
    return syscall.sc_kevent(kq, changelist, #pipes, eventlist, 0, timeout)
end)
log("  kevent register " .. #pipes .. " READ filters: " ..
    (ke_ok and "rv=" .. ke_ret:tonumber() or "ERR: " .. tostring(ke_ret):sub(1, 50)))

-- ============================================================
-- PART 4: Write to pipes and poll for events
-- ============================================================
log("")
log("--- PART 4: trigger and poll events ---")

-- Write data to first 3 pipes
for i = 1, math.min(3, #pipes) do
    local wbuf = memory.alloc(16)
    for j = 0, 15 do memory.write_byte(wbuf + j, 0x42) end
    pcall(function() syscall.sc_write(pipes[i].wfd, wbuf, 8) end)
end

-- Poll with timeout=0 (non-blocking)
local poll_ok, poll_ret = pcall(function()
    return syscall.sc_kevent(kq, changelist, 0, eventlist, 10, timeout)
end)

if poll_ok then
    local nevents = poll_ret:tonumber()
    log("  kevent poll: " .. nevents .. " events")

    for i = 0, math.min(nevents - 1, 9) do
        local off = i * KEVENT_SIZE
        local ident = memory.read_qword(eventlist + off):tonumber()
        local filter_lo = memory.read_word(eventlist + off + 8):tonumber()
        local flags_lo = memory.read_word(eventlist + off + 10):tonumber()
        local data = memory.read_qword(eventlist + off + 16):tonumber()
        local udata = memory.read_qword(eventlist + off + 24):tonumber()
        log(string.format("    event[%d]: fd=%d filter=0x%04x flags=0x%04x data=%d udata=%d",
            i, ident, filter_lo, flags_lo, data, udata))
    end
else
    log("  kevent poll: ERR " .. tostring(poll_ret):sub(1, 50))
end

-- ============================================================
-- PART 5: Close FD while kevent is registered (knote UAF test)
-- The classic kqueue bug: close an fd that has a knote registered
-- on a kqueue. The kernel must detach the knote properly.
-- ============================================================
log("")
log("--- PART 5: close-while-registered ---")

-- Close a pipe read end that has a kevent registered
local victim_pipe = pipes[1]
log("  closing rfd=" .. victim_pipe.rfd .. " (has kevent registered)")
pcall(function() syscall.sc_close(victim_pipe.rfd) end)

-- Now poll — should get EV_EOF or the knote should be gone
local p5_ok, p5_ret = pcall(function()
    return syscall.sc_kevent(kq, changelist, 0, eventlist, 10, timeout)
end)
if p5_ok then
    local n5 = p5_ret:tonumber()
    log("  after close: " .. n5 .. " events")
    for i = 0, math.min(n5 - 1, 9) do
        local off = i * KEVENT_SIZE
        local ident = memory.read_qword(eventlist + off):tonumber()
        local flags = memory.read_word(eventlist + off + 10):tonumber()
        log(string.format("    event[%d]: fd=%d flags=0x%04x", i, ident, flags))
    end
end

-- Try to re-register on the closed fd (should fail)
local re_change = memory.alloc(KEVENT_SIZE)
memory.write_qword(re_change, victim_pipe.rfd)
memory.write_word(re_change + 8, 0xFFFF)  -- EVFILT_READ
memory.write_word(re_change + 10, EV_ADD)
memory.write_dword(re_change + 12, 0)
memory.write_qword(re_change + 16, 0)
memory.write_qword(re_change + 24, 0xDEAD)

local re_ok, re_ret = pcall(function()
    return syscall.sc_kevent(kq, re_change, 1, eventlist, 1, timeout)
end)
log("  re-register closed fd: " ..
    (re_ok and "rv=" .. re_ret:tonumber() or "ERR"))

-- ============================================================
-- PART 6: Rapid register/delete churn
-- Register and delete events rapidly to stress knote alloc/free
-- ============================================================
log("")
log("--- PART 6: register/delete churn ---")

local churn_ok = 0
local churn_err = 0
local churn_change = memory.alloc(KEVENT_SIZE)

for round = 1, 200 do
    local pidx = ((round - 1) % (#pipes - 1)) + 2  -- skip pipe[1] (closed)
    local p = pipes[pidx]

    -- Register
    memory.write_qword(churn_change, p.rfd)
    memory.write_word(churn_change + 8, 0xFFFF)
    memory.write_word(churn_change + 10, EV_ADD)
    memory.write_dword(churn_change + 12, 0)
    memory.write_qword(churn_change + 16, 0)
    memory.write_qword(churn_change + 24, round)

    local c1_ok = pcall(function()
        syscall.sc_kevent(kq, churn_change, 1, eventlist, 1, timeout)
    end)

    -- Delete
    memory.write_word(churn_change + 10, EV_DELETE)
    local c2_ok = pcall(function()
        syscall.sc_kevent(kq, churn_change, 1, eventlist, 1, timeout)
    end)

    if c1_ok and c2_ok then
        churn_ok = churn_ok + 1
    else
        churn_err = churn_err + 1
    end
end

log("  200 rounds: ok=" .. churn_ok .. " err=" .. churn_err)

-- ============================================================
-- PART 7: Multiple kqueues watching same fd
-- Register same fd on multiple kqueues, then close the fd
-- Tests reference counting of knotes across kqueues
-- ============================================================
log("")
log("--- PART 7: multi-kqueue same fd ---")

local kqs = {kq}
for i = 2, 5 do
    local k_ok, k_ret = pcall(function() return syscall.sc_kqueue() end)
    if k_ok then kqs[#kqs + 1] = k_ret:tonumber() end
end
log("  kqueues: " .. #kqs)

-- Pick a pipe that's still open
local target_pipe = pipes[2]

-- Register READ on this pipe's rfd in ALL kqueues
local mk_change = memory.alloc(KEVENT_SIZE)
memory.write_qword(mk_change, target_pipe.rfd)
memory.write_word(mk_change + 8, 0xFFFF)
memory.write_word(mk_change + 10, EV_ADD)
memory.write_dword(mk_change + 12, 0)
memory.write_qword(mk_change + 16, 0)
memory.write_qword(mk_change + 24, 0xBEEF)

for i, kqfd in ipairs(kqs) do
    local m_ok = pcall(function()
        syscall.sc_kevent(kqfd, mk_change, 1, eventlist, 1, timeout)
    end)
    log("  register on kq[" .. i .. "]=" .. kqfd .. ": " .. (m_ok and "OK" or "FAIL"))
end

-- Write data to trigger events on all kqueues
local wbuf7 = memory.alloc(16)
for i = 0, 15 do memory.write_byte(wbuf7 + i, 0x55) end
pcall(function() syscall.sc_write(target_pipe.wfd, wbuf7, 8) end)

-- Poll each kqueue
for i, kqfd in ipairs(kqs) do
    local p7_ok, p7_ret = pcall(function()
        return syscall.sc_kevent(kqfd, mk_change, 0, eventlist, 5, timeout)
    end)
    if p7_ok then
        log("  kq[" .. i .. "] poll: " .. p7_ret:tonumber() .. " events")
    end
end

-- Now close the fd — all kqueues must detach their knotes
log("  closing target rfd=" .. target_pipe.rfd)
pcall(function() syscall.sc_close(target_pipe.rfd) end)

-- Poll again — should see EV_EOF or empty
for i, kqfd in ipairs(kqs) do
    local p7b_ok, p7b_ret = pcall(function()
        return syscall.sc_kevent(kqfd, mk_change, 0, eventlist, 5, timeout)
    end)
    if p7b_ok then
        local n = p7b_ret:tonumber()
        local flags_str = ""
        if n > 0 then
            local f = memory.read_word(eventlist + 10):tonumber()
            flags_str = string.format(" flags=0x%04x", f)
        end
        log("  kq[" .. i .. "] after close: " .. n .. " events" .. flags_str)
    end
end

-- ============================================================
-- PART 8: Close kqueue while events pending
-- ============================================================
log("")
log("--- PART 8: close kqueue with pending events ---")

local kq8_ok, kq8_ret = pcall(function() return syscall.sc_kqueue() end)
if kq8_ok then
    local kq8 = kq8_ret:tonumber()

    -- Register on remaining pipes
    for i = 3, #pipes do
        memory.write_qword(mk_change, pipes[i].rfd)
        memory.write_word(mk_change + 10, EV_ADD)
        pcall(function()
            syscall.sc_kevent(kq8, mk_change, 1, eventlist, 1, timeout)
        end)
    end

    -- Write data to make events pending
    for i = 3, #pipes do
        pcall(function() syscall.sc_write(pipes[i].wfd, wbuf7, 8) end)
    end

    -- Close kqueue without draining events
    pcall(function() syscall.sc_close(kq8) end)
    log("  closed kqueue with " .. (#pipes - 2) .. " pending events")

    -- Are we alive?
    local alive8 = pcall(function() syscall.sc_getpid() end)
    log("  alive: " .. tostring(alive8))
end

-- ============================================================
-- PART 9: EVFILT_PROC on self (if allowed)
-- Register for process events on our own PID
-- ============================================================
log("")
log("--- PART 9: EVFILT_PROC ---")

local EVFILT_PROC = -5  -- 0xFFFB as uint16
local NOTE_EXIT = 0x80000000
local NOTE_FORK = 0x40000000
local NOTE_EXEC = 0x20000000

local kq9_ok, kq9_ret = pcall(function() return syscall.sc_kqueue() end)
if kq9_ok then
    local kq9 = kq9_ret:tonumber()
    local pid = syscall.sc_getpid():tonumber()

    local proc_change = memory.alloc(KEVENT_SIZE)
    memory.write_qword(proc_change, pid)             -- ident = our PID
    memory.write_word(proc_change + 8, 0xFFFB)       -- EVFILT_PROC
    memory.write_word(proc_change + 10, EV_ADD)
    memory.write_dword(proc_change + 12, 0x40000000) -- NOTE_FORK
    memory.write_qword(proc_change + 16, 0)
    memory.write_qword(proc_change + 24, 0xCAFE)

    local p9_ok, p9_ret = pcall(function()
        return syscall.sc_kevent(kq9, proc_change, 1, eventlist, 1, timeout)
    end)
    log("  EVFILT_PROC(self, NOTE_FORK): " ..
        (p9_ok and "rv=" .. p9_ret:tonumber() or "ERR"))

    -- Try watching PID 1 (init)
    memory.write_qword(proc_change, 1)
    local p9b_ok, p9b_ret = pcall(function()
        return syscall.sc_kevent(kq9, proc_change, 1, eventlist, 1, timeout)
    end)
    log("  EVFILT_PROC(pid=1, NOTE_FORK): " ..
        (p9b_ok and "rv=" .. p9b_ret:tonumber() or "ERR"))

    -- Check for error events returned
    if p9b_ok and p9b_ret:tonumber() > 0 then
        local eflags = memory.read_word(eventlist + 10):tonumber()
        local efflags = memory.read_dword(eventlist + 12):tonumber()
        local edata = memory.read_qword(eventlist + 16):tonumber()
        log(string.format("    flags=0x%04x fflags=0x%08x data=%d", eflags, efflags, edata))
    end

    pcall(function() syscall.sc_close(kq9) end)
end

-- ============================================================
-- PART 10: EVFILT_TIMER stress
-- ============================================================
log("")
log("--- PART 10: EVFILT_TIMER ---")

local EVFILT_TIMER = -7  -- 0xFFF9

local kq10_ok, kq10_ret = pcall(function() return syscall.sc_kqueue() end)
if kq10_ok then
    local kq10 = kq10_ret:tonumber()

    -- Register 50 timers with 0ms timeout (fire immediately)
    local timer_change = memory.alloc(KEVENT_SIZE)
    local timer_ok = 0
    for i = 1, 50 do
        memory.write_qword(timer_change, i)              -- ident = timer ID
        memory.write_word(timer_change + 8, 0xFFF9)      -- EVFILT_TIMER
        memory.write_word(timer_change + 10, EV_ADD + EV_ONESHOT)
        memory.write_dword(timer_change + 12, 0)
        memory.write_qword(timer_change + 16, 1)         -- data = 1ms
        memory.write_qword(timer_change + 24, i)

        local t_ok = pcall(function()
            syscall.sc_kevent(kq10, timer_change, 1, eventlist, 1, timeout)
        end)
        if t_ok then timer_ok = timer_ok + 1 end
    end
    log("  registered " .. timer_ok .. "/50 timers")

    -- Poll for fired timers
    local t_poll_ok, t_poll_ret = pcall(function()
        return syscall.sc_kevent(kq10, timer_change, 0, eventlist, 20, timeout)
    end)
    if t_poll_ok then
        log("  timer events: " .. t_poll_ret:tonumber())
    end

    -- Delete all timers rapidly
    for i = 1, 50 do
        memory.write_qword(timer_change, i)
        memory.write_word(timer_change + 8, 0xFFF9)
        memory.write_word(timer_change + 10, EV_DELETE)
        pcall(function()
            syscall.sc_kevent(kq10, timer_change, 1, eventlist, 1, timeout)
        end)
    end
    log("  deleted 50 timers")

    pcall(function() syscall.sc_close(kq10) end)
end

-- Cleanup
for i, kqfd in ipairs(kqs) do
    pcall(function() syscall.sc_close(kqfd) end)
end
for i = 3, #pipes do
    pcall(function() syscall.sc_close(pipes[i].rfd) end)
    pcall(function() syscall.sc_close(pipes[i].wfd) end)
end

log("")
log("=== KQUEUE STRESS DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
