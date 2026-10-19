-- CRASH_CLASS: RISKY
-- PROBE 78d: kevent EVFILT_PROC monitoring during thr_create fault
--
-- Context: kevent works on PS5 (probes 20/21 confirmed EVFILT_TIMER/READ/USER).
-- EVFILT_PROC monitors process-level events: thread exit, faults, signals.
-- If we register EVFILT_PROC before calling thr_create, the kernel might
-- deliver an event when the child thread faults. The event data (kn_data,
-- kn_fflags) in FreeBSD can contain thread IDs, signal numbers, and
-- potentially kernel addresses.
--
-- Strategy:
--   Section A: Register EVFILT_PROC on own PID, thr_create, poll events
--   Section B: Register EVFILT_PROC with NOTE_EXIT|NOTE_TRACK, thr_create, poll
--   Section C: Register EVFILT_SIGNAL for SIGSEGV, thr_create, poll

print("=== PROBE 78d: KEVENT EVFILT_PROC ON THR_CREATE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local sc_kqueue = make_syscall(362)
local sc_kevent = make_syscall(363)
local sc_thr_create = make_syscall(430)
local sc_thr_self = make_syscall(432)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Get our TID for reference
local self_tid = 0
repeat
    local tid_buf = memory.alloc(8)
    zero(tid_buf, 8)
    local tok, trv = pcall(function() return sc_thr_self(uint64(tid_buf)) end)
    if tok then
        self_tid = to_num(rq(tid_buf))
    end
    print("[0] self_tid=" .. self_tid .. " ok=" .. tostring(tok))
until true

-- Create kqueue
local kq_ok, kq_fd = pcall(function() return sc_kqueue() end)
local kq_num = to_num(kq_fd)
print("[0] kqueue fd=" .. kq_num .. " ok=" .. tostring(kq_ok))

if not kq_ok or kq_num < 0 then
    print("[!] kqueue failed, aborting")
    print("=== PROBE 78d ABORTED ===")
    return
end

-- kevent structure layout (FreeBSD amd64):
-- struct kevent {
--   uintptr_t ident;    // +0x00 (8 bytes)
--   short     filter;   // +0x08 (2 bytes)
--   u_short   flags;    // +0x0A (2 bytes)
--   u_int     fflags;   // +0x0C (4 bytes)
--   int64_t   data;     // +0x10 (8 bytes)
--   void     *udata;    // +0x18 (8 bytes)
-- };  // total = 0x20 (32 bytes)

-- Filter constants
local EVFILT_PROC = -5     -- 0xFFFB as signed short
local EVFILT_SIGNAL = -6   -- 0xFFFA

-- Flag constants
local EV_ADD = 0x0001
local EV_ENABLE = 0x0004
local EV_CLEAR = 0x0020

-- Note constants for EVFILT_PROC
local NOTE_EXIT = 0x80000000
local NOTE_FORK = 0x40000000
local NOTE_EXEC = 0x20000000
local NOTE_TRACK = 0x00000001

-- SIGSTOP=17, SIGSEGV=11
local SIGSEGV = 11

-- Helper: write kevent struct
local function write_kevent(buf, ident, filter, flags, fflags, data, udata)
    wq(buf + 0x00, uint64(ident))
    -- filter is signed short at +0x08, flags is unsigned short at +0x0A
    -- Pack both into one dword: flags<<16 | (filter & 0xFFFF)
    local filter_u16 = filter
    if filter < 0 then filter_u16 = 0x10000 + filter end
    wd(buf + 0x08, filter_u16 + flags * 0x10000)
    wd(buf + 0x0C, fflags)
    wq(buf + 0x10, uint64(data))
    wq(buf + 0x18, uint64(udata))
end

-- Helper: read kevent struct
local function read_kevent(buf)
    local ident = rq(buf + 0x00)
    local filter_flags = rd(buf + 0x08)
    local filter = 0
    local flags = 0
    if filter_flags then
        filter = filter_flags % 0x10000
        if filter >= 0x8000 then filter = filter - 0x10000 end
        flags = math.floor(filter_flags / 0x10000)
    end
    local fflags = rd(buf + 0x0C)
    local data = rq(buf + 0x10)
    local udata = rq(buf + 0x18)
    return ident, filter, flags, fflags, data, udata
end

-- Allocate kevent buffers
local changelist = memory.alloc(0x40)  -- 2 kevents
local eventlist = memory.alloc(0x200)  -- 16 events output
zero(changelist, 0x40)
zero(eventlist, 0x200)

-- Allocate thr_create resources
local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)

wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)
wq(ctx + 0xF8, 0)                   -- RIP=0
wq(ctx + 0xE0, stack + 0x3FF0)      -- RSP
wq(ctx + 0x100, 0)                   -- RFLAGS
wq(ctx + 0x48, 0)                    -- RDI
wq(ctx + 0x50, 0)                    -- RSI

wq(id_slot, uint64(string.format("0x%X%08X", 0xDEADBEEF, 0xDEADBEEF)))

-- Timeout struct for kevent (0ms = poll, don't block)
local ts_zero = memory.alloc(16)
wq(ts_zero, 0)
wq(ts_zero + 8, 0)

-- ==============================
-- SECTION A: EVFILT_PROC NOTE_EXIT on own PID
-- ==============================
if TEST_SECTION == 1 then
    print("=== SECTION A: EVFILT_PROC NOTE_EXIT on PID " .. pid .. " ===")

    -- Register EVFILT_PROC watching our own PID for exit/fork events
    write_kevent(changelist, pid, EVFILT_PROC, EV_ADD + EV_ENABLE + EV_CLEAR,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0xAABBCCDD)

    local reg_ok, reg_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(changelist), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)
    print("[A] kevent_register ok=" .. tostring(reg_ok) .. " rv=" .. tostring(reg_rv))

    -- Now create the thread that will fault
    print("[A] [BEFORE] thr_create (RIP=0)")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[A] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))
    print("[A] tid=" .. q(rq(id_slot)))

    -- Immediately poll for events (zero timeout)
    zero(eventlist, 0x200)
    local poll_ok, poll_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(0), uint64(0),
            uint64(eventlist), uint64(8), uint64(ts_zero))
    end)
    local nevents = to_num(poll_rv)
    print("[A] kevent_poll_0 ok=" .. tostring(poll_ok) .. " nevents=" .. nevents)

    -- Dump any received events
    for i = 0, math.min(nevents, 8) - 1 do
        local base = eventlist + (i * 0x20)
        local ident, filter, flags, fflags, data, udata = read_kevent(base)
        print(string.format("[A] event[%d] ident=%s filter=%d flags=0x%04X fflags=0x%08X",
            i, q(ident), filter, flags, fflags or 0))
        print(string.format("[A] event[%d] data=%s udata=%s", i, q(data), q(udata)))
        -- Check data for kernel pointers
        if data then
            local dh, dl = get_hi_lo(data)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                print("[A] event[" .. i .. "] DATA IS KERNEL POINTER!")
            end
        end
    end

    -- Wait 200ms and poll again (event might be delayed)
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 200000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    zero(eventlist, 0x200)
    local poll2_ok, poll2_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(0), uint64(0),
            uint64(eventlist), uint64(8), uint64(ts_zero))
    end)
    local nevents2 = to_num(poll2_rv)
    print("[A] kevent_poll_200ms ok=" .. tostring(poll2_ok) .. " nevents=" .. nevents2)

    for i = 0, math.min(nevents2, 8) - 1 do
        local base = eventlist + (i * 0x20)
        local ident, filter, flags, fflags, data, udata = read_kevent(base)
        print(string.format("[A] event2[%d] ident=%s filter=%d flags=0x%04X fflags=0x%08X",
            i, q(ident), filter, flags, fflags or 0))
        print(string.format("[A] event2[%d] data=%s udata=%s", i, q(data), q(udata)))
        if data then
            local dh, dl = get_hi_lo(data)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                print("[A] event2[" .. i .. "] DATA IS KERNEL POINTER!")
            end
        end
    end

    local c_ok, c_pid = canary()
    print("[A] canary ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))

    wq(ts, 5); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[A] canary_5s ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    print("=== SECTION A COMPLETE ===")

-- ==============================
-- SECTION B: EVFILT_SIGNAL for SIGSEGV
-- ==============================
elseif TEST_SECTION == 2 then
    print("=== SECTION B: EVFILT_SIGNAL SIGSEGV ===")

    write_kevent(changelist, SIGSEGV, EVFILT_SIGNAL, EV_ADD + EV_ENABLE + EV_CLEAR,
        0, 0, 0xDEAD0002)

    local reg_ok, reg_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(changelist), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)
    print("[B] kevent_register ok=" .. tostring(reg_ok) .. " rv=" .. tostring(reg_rv))

    print("[B] [BEFORE] thr_create (RIP=0)")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[B] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))
    print("[B] tid=" .. q(rq(id_slot)))

    -- Poll immediately
    zero(eventlist, 0x200)
    local poll_ok, poll_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(0), uint64(0),
            uint64(eventlist), uint64(8), uint64(ts_zero))
    end)
    local nevents = to_num(poll_rv)
    print("[B] kevent_poll_0 ok=" .. tostring(poll_ok) .. " nevents=" .. nevents)

    for i = 0, math.min(nevents, 8) - 1 do
        local base = eventlist + (i * 0x20)
        local ident, filter, flags, fflags, data, udata = read_kevent(base)
        print(string.format("[B] event[%d] ident=%s filter=%d flags=0x%04X fflags=0x%08X",
            i, q(ident), filter, flags, fflags or 0))
        print(string.format("[B] event[%d] data=%s udata=%s", i, q(data), q(udata)))
    end

    -- Wait 200ms poll again
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 200000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    zero(eventlist, 0x200)
    local poll2_ok, poll2_rv = pcall(function()
        return sc_kevent(uint64(kq_num), uint64(0), uint64(0),
            uint64(eventlist), uint64(8), uint64(ts_zero))
    end)
    local nevents2 = to_num(poll2_rv)
    print("[B] kevent_poll_200ms ok=" .. tostring(poll2_ok) .. " nevents=" .. nevents2)

    for i = 0, math.min(nevents2, 8) - 1 do
        local base = eventlist + (i * 0x20)
        local ident, filter, flags, fflags, data, udata = read_kevent(base)
        print(string.format("[B] event2[%d] ident=%s filter=%d flags=0x%04X fflags=0x%08X",
            i, q(ident), filter, flags, fflags or 0))
        print(string.format("[B] event2[%d] data=%s udata=%s", i, q(data), q(udata)))
    end

    local c_ok, c_pid = canary()
    print("[B] canary ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))

    wq(ts, 5); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[B] canary_5s ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    print("=== SECTION B COMPLETE ===")

else
    print("[!] invalid TEST_SECTION=" .. TEST_SECTION .. " (use 1-2)")
    print("=== PROBE 78d ABORTED ===")
    return
end

print("")
print("=== PROBE 78d SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("Key: check event data fields for kernel pointers or thread info.")
print("=== PROBE 78d COMPLETE ===")
