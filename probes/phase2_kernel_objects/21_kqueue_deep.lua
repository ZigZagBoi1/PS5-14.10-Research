-- 14.10 Recon Probe 21: Deep kqueue exploitation attempts
-- Probe 20 showed: kqueue fully works, EVFILT_PROC on PID 1 accepted
-- This probe targets:
-- 1. EVFILT_PROC to enumerate all PIDs (kernel info leak)
-- 2. EVFILT_SIGNAL to intercept signals
-- 3. Heavy concurrent kqueue operations for edge cases
-- 4. EV_ERROR flag harvesting for kernel error codes
-- 5. Extreme knote counts to stress kernel slab allocator

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: KQUEUE DEEP ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_kqueue = 362,
    sc_kevent = 363,
    sc_close = 6,
    sc_write = 4,
    sc_socketpair = 135,
    sc_getpid = 20,
})

local KEVENT_SIZE = 32
local EV_ADD = 0x0001
local EV_DELETE = 0x0002
local EV_ENABLE = 0x0004
local EV_ONESHOT = 0x0010
local EV_CLEAR = 0x0020
local EV_ERROR = 0x4000
local EV_EOF = 0x8000

local kq = syscall.sc_kqueue():tonumber()
log("kqueue fd=" .. kq)

local change = memory.alloc(KEVENT_SIZE)
local events = memory.alloc(32 * KEVENT_SIZE)
local timeout = memory.alloc(16)
memory.write_qword(timeout, 0)
memory.write_qword(timeout + 8, 0)

-- ============================================================
-- PART 1: PID enumeration via EVFILT_PROC
-- Register NOTE_EXIT on every PID 1-500
-- If a PID exists, EV_ADD succeeds; if not, returns EV_ERROR
-- This leaks the kernel process table!
-- ============================================================
log("")
log("--- PART 1: PID enumeration ---")

local EVFILT_PROC = 0xFFFB  -- -5 as uint16

local live_pids = {}
local dead_pids = 0
local error_pids = 0

-- Batch registration — register 10 at a time for speed
local batch = memory.alloc(10 * KEVENT_SIZE)

for base_pid = 1, 500, 10 do
    -- Build batch
    for i = 0, 9 do
        local pid = base_pid + i
        local off = i * KEVENT_SIZE
        memory.write_qword(batch + off, pid)
        memory.write_word(batch + off + 8, EVFILT_PROC)
        memory.write_word(batch + off + 10, EV_ADD + EV_ONESHOT)
        memory.write_dword(batch + off + 12, 0x80000000) -- NOTE_EXIT
        memory.write_qword(batch + off + 16, 0)
        memory.write_qword(batch + off + 24, pid)
    end

    local b_ok, b_ret = pcall(function()
        return syscall.sc_kevent(kq, batch, 10, events, 10, timeout)
    end)

    if b_ok then
        local n = b_ret:tonumber()
        -- Check returned events for EV_ERROR (registration failures)
        for i = 0, math.min(n - 1, 9) do
            local off = i * KEVENT_SIZE
            local ident = memory.read_qword(events + off):tonumber()
            local flags = memory.read_word(events + off + 10):tonumber()
            local data = memory.read_qword(events + off + 16):tonumber()

            if flags % 0x8000 >= 0x4000 then
                -- EV_ERROR — PID doesn't exist or no permission
                dead_pids = dead_pids + 1
            else
                live_pids[#live_pids + 1] = ident
            end
        end

        -- If n=0, all 10 registered successfully (PIDs exist)
        if n == 0 then
            for i = 0, 9 do
                live_pids[#live_pids + 1] = base_pid + i
            end
        end
    end
end

log("  scanned PIDs 1-500")
log("  live PIDs found: " .. #live_pids)
log("  dead/error: " .. dead_pids)

-- Print all live PIDs
if #live_pids > 0 then
    local pid_strs = {}
    for i, p in ipairs(live_pids) do
        pid_strs[#pid_strs + 1] = tostring(p)
        if i >= 80 then
            pid_strs[#pid_strs + 1] = "..."
            break
        end
    end
    log("  PIDs: " .. table.concat(pid_strs, ","))
end

-- ============================================================
-- PART 2: EVFILT_SIGNAL — intercept signals
-- ============================================================
log("")
log("--- PART 2: EVFILT_SIGNAL ---")

local EVFILT_SIGNAL = 0xFFFA  -- -6 as uint16

local kq2 = syscall.sc_kqueue():tonumber()
local sig_ok_count = 0

for sig = 1, 31 do
    memory.write_qword(change, sig)
    memory.write_word(change + 8, EVFILT_SIGNAL)
    memory.write_word(change + 10, EV_ADD)
    memory.write_dword(change + 12, 0)
    memory.write_qword(change + 16, 0)
    memory.write_qword(change + 24, sig)

    local s_ok, s_ret = pcall(function()
        return syscall.sc_kevent(kq2, change, 1, events, 1, timeout)
    end)
    if s_ok then
        local n = s_ret:tonumber()
        if n == 0 then
            sig_ok_count = sig_ok_count + 1
        else
            -- Check if error
            local f = memory.read_word(events + 10):tonumber()
            if f % 0x8000 >= 0x4000 then
                -- error
            else
                sig_ok_count = sig_ok_count + 1
            end
        end
    end
end
log("  signals registered: " .. sig_ok_count .. "/31")
pcall(function() syscall.sc_close(kq2) end)

-- ============================================================
-- PART 3: EVFILT_USER — user-defined events
-- These are entirely in-kernel state machines
-- ============================================================
log("")
log("--- PART 3: EVFILT_USER ---")

local EVFILT_USER = 0xFFF5  -- -11 as uint16
local NOTE_TRIGGER = 0x01000000

local kq3 = syscall.sc_kqueue():tonumber()

-- Register 20 user events
local user_ok = 0
for i = 1, 20 do
    memory.write_qword(change, i)
    memory.write_word(change + 8, EVFILT_USER)
    memory.write_word(change + 10, EV_ADD + EV_CLEAR)
    memory.write_dword(change + 12, 0)
    memory.write_qword(change + 16, 0)
    memory.write_qword(change + 24, i)

    local u_ok = pcall(function()
        syscall.sc_kevent(kq3, change, 1, events, 1, timeout)
    end)
    if u_ok then user_ok = user_ok + 1 end
end
log("  user events registered: " .. user_ok .. "/20")

-- Trigger some
for i = 1, 10 do
    memory.write_qword(change, i)
    memory.write_word(change + 8, EVFILT_USER)
    memory.write_word(change + 10, 0) -- no flags (just trigger via fflags)
    memory.write_dword(change + 12, NOTE_TRIGGER)
    memory.write_qword(change + 16, 0)
    memory.write_qword(change + 24, i)

    pcall(function()
        syscall.sc_kevent(kq3, change, 1, events, 1, timeout)
    end)
end

-- Poll
local up_ok, up_ret = pcall(function()
    return syscall.sc_kevent(kq3, change, 0, events, 20, timeout)
end)
if up_ok then
    log("  triggered events: " .. up_ret:tonumber())
end

pcall(function() syscall.sc_close(kq3) end)

-- ============================================================
-- PART 4: Extreme knote count stress
-- Register thousands of events to stress slab allocator
-- ============================================================
log("")
log("--- PART 4: extreme knote count ---")

local kq4 = syscall.sc_kqueue():tonumber()

-- Use EVFILT_TIMER with unique idents
local max_knotes = 0
for i = 1, 2000 do
    memory.write_qword(change, i + 10000)  -- high ident to avoid conflicts
    memory.write_word(change + 8, 0xFFF9)  -- EVFILT_TIMER
    memory.write_word(change + 10, EV_ADD + EV_ONESHOT)
    memory.write_dword(change + 12, 0)
    memory.write_qword(change + 16, 999999) -- 999s timeout (won't fire)
    memory.write_qword(change + 24, i)

    local x_ok = pcall(function()
        syscall.sc_kevent(kq4, change, 1, events, 1, timeout)
    end)
    if x_ok then
        max_knotes = i
    else
        break
    end
end
log("  max knotes registered: " .. max_knotes)

-- Now delete them all rapidly
local del_ok = 0
for i = 1, max_knotes do
    memory.write_qword(change, i + 10000)
    memory.write_word(change + 8, 0xFFF9)
    memory.write_word(change + 10, EV_DELETE)

    local d_ok = pcall(function()
        syscall.sc_kevent(kq4, change, 1, events, 1, timeout)
    end)
    if d_ok then del_ok = del_ok + 1 end
end
log("  deleted: " .. del_ok)

-- Re-register immediately after mass delete (reuse freed knotes)
local reuse_ok = 0
for i = 1, 500 do
    memory.write_qword(change, i + 10000)
    memory.write_word(change + 8, 0xFFF9)
    memory.write_word(change + 10, EV_ADD + EV_ONESHOT)
    memory.write_qword(change + 16, 999999)

    local r_ok = pcall(function()
        syscall.sc_kevent(kq4, change, 1, events, 1, timeout)
    end)
    if r_ok then reuse_ok = reuse_ok + 1 end
end
log("  reused after delete: " .. reuse_ok .. "/500")

pcall(function() syscall.sc_close(kq4) end)

-- ============================================================
-- PART 5: Nested kqueue (kqueue watching kqueue)
-- ============================================================
log("")
log("--- PART 5: nested kqueue ---")

local kq_outer = syscall.sc_kqueue():tonumber()
local kq_inner = syscall.sc_kqueue():tonumber()
log("  outer=" .. kq_outer .. " inner=" .. kq_inner)

-- Register EVFILT_READ on inner kqueue from outer
memory.write_qword(change, kq_inner)
memory.write_word(change + 8, 0xFFFF)  -- EVFILT_READ
memory.write_word(change + 10, EV_ADD)
memory.write_dword(change + 12, 0)
memory.write_qword(change + 16, 0)
memory.write_qword(change + 24, 0x4E455354)

local n_ok, n_ret = pcall(function()
    return syscall.sc_kevent(kq_outer, change, 1, events, 1, timeout)
end)
log("  register inner on outer: " ..
    (n_ok and "rv=" .. n_ret:tonumber() or "ERR"))

-- Add a EVFILT_USER event on inner to make it readable
memory.write_qword(change, 1)
memory.write_word(change + 8, EVFILT_USER)
memory.write_word(change + 10, EV_ADD + EV_CLEAR)
memory.write_dword(change + 12, NOTE_TRIGGER)
memory.write_qword(change + 24, 1)
pcall(function()
    syscall.sc_kevent(kq_inner, change, 1, events, 1, timeout)
end)

-- Poll outer — should see inner is readable
local np_ok, np_ret = pcall(function()
    return syscall.sc_kevent(kq_outer, change, 0, events, 5, timeout)
end)
if np_ok then
    log("  outer poll: " .. np_ret:tonumber() .. " events")
    if np_ret:tonumber() > 0 then
        local nident = memory.read_qword(events):tonumber()
        local ndata = memory.read_qword(events + 16):tonumber()
        log("    fd=" .. nident .. " data=" .. ndata)
    end
end

-- Close inner while outer watches it
pcall(function() syscall.sc_close(kq_inner) end)
log("  closed inner kqueue")

-- Poll outer again
local np2_ok, np2_ret = pcall(function()
    return syscall.sc_kevent(kq_outer, change, 0, events, 5, timeout)
end)
if np2_ok then
    local n2 = np2_ret:tonumber()
    log("  outer after inner close: " .. n2 .. " events")
    if n2 > 0 then
        local f = memory.read_word(events + 10):tonumber()
        log(string.format("    flags=0x%04x", f))
    end
end

pcall(function() syscall.sc_close(kq_outer) end)

-- ============================================================
-- PART 6: Info leak via kevent data/fflags after close
-- After closing an fd, check if stale kernel data leaks
-- through the kevent struct fields
-- ============================================================
log("")
log("--- PART 6: stale data leak check ---")

local kq6 = syscall.sc_kqueue():tonumber()
local sp6 = memory.alloc(8)
syscall.sc_socketpair(1, 1, 0, sp6)
local s6a = memory.read_dword(sp6):tonumber()
local s6b = memory.read_dword(sp6 + 4):tonumber()

-- Register and trigger
memory.write_qword(change, s6a)
memory.write_word(change + 8, 0xFFFF)
memory.write_word(change + 10, EV_ADD)
pcall(function() syscall.sc_kevent(kq6, change, 1, events, 1, timeout) end)

local wbuf6 = memory.alloc(64)
for i = 0, 63 do memory.write_byte(wbuf6 + i, 0x77) end
syscall.sc_write(s6b, wbuf6, 32)

-- Poll to get event
pcall(function() syscall.sc_kevent(kq6, change, 0, events, 1, timeout) end)

-- Now close both fds
pcall(function() syscall.sc_close(s6a) end)
pcall(function() syscall.sc_close(s6b) end)

-- Check the event buffer for any kernel pointers
log("  events buffer after close:")
for i = 0, KEVENT_SIZE - 1, 8 do
    local lo = memory.read_dword(events + i):tonumber()
    local hi = memory.read_dword(events + i + 4):tonumber()
    if lo ~= 0 or hi ~= 0 then
        local tag = ""
        if hi >= 0xFFFF0000 then tag = " *** KPTR ***" end
        log(string.format("    +%d: 0x%08x%08x%s", i, hi, lo, tag))
    end
end

pcall(function() syscall.sc_close(kq6) end)

log("")
log("=== KQUEUE DEEP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
