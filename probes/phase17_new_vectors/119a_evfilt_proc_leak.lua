-- CRASH_CLASS: LOW
-- PROBE 119a: EVFILT_PROC kernel info leak via kevent
--
-- Context: kevent WORKS on PS5 14.10 (probes 20/21 confirmed).
-- EVFILT_TIMER, EVFILT_USER, EVFILT_SIGNAL, EVFILT_READ all work.
-- But EVFILT_PROC was NEVER tested! On FreeBSD, EVFILT_PROC monitors
-- process events and can leak kernel pointers in the event data.
--
-- The gold: kn_data and kn_fflags in older FreeBSD can contain:
-- - Thread/process struct addresses when NOTE_EXIT fires
-- - The faulting PC when a signal is delivered
-- - Memory layout info from NOTE_FORK/NOTE_EXEC
--
-- We monitor our OWN PID, trigger events (signal delivery, exit status),
-- and check if the kevent data contains kernel addresses.
--
-- Section A: Register EVFILT_PROC on our PID with all NOTE_ flags
-- Section B: Trigger SIGCHLD-like events via signal handler
-- Section C: Register EVFILT_PROC then thr_create → check event data
-- Section D: EVFILT_PROC + kevent polling with output buffer analysis
-- Section E: Test EVFILT_PROCDESC (FreeBSD 10+) if available

print("=== PROBE 119a: EVFILT_PROC KERNEL LEAK ===")
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

-- Get PID
local sc_getpid = make_syscall(20)
local pid = 0
pcall(function()
    local rv = sc_getpid()
    pid = to_num(rv)
end)
print("[*] PID: " .. pid)

-- kqueue() = syscall 362
local sc_kqueue = make_syscall(362)
-- kevent() = syscall 363 (FreeBSD 9)
-- Actually on FreeBSD, kevent is at 560 or 363. Let's check both.
local sc_kevent = make_syscall(363)
local sc_kevent2 = make_syscall(560)

-- Create a kqueue
local kq_fd = -1
pcall(function()
    local rv = sc_kqueue()
    kq_fd = to_num(rv)
end)
print("[*] kqueue fd: " .. kq_fd)

if kq_fd < 0 then
    print("ABORT: kqueue() failed")
    return
end

-- struct kevent layout (FreeBSD, 64-bit):
--   +0x00: uintptr_t ident    (8 bytes) - identifier (PID for EVFILT_PROC)
--   +0x08: short     filter   (2 bytes) - filter type
--   +0x0A: u_short   flags    (2 bytes) - action flags
--   +0x0C: u_int     fflags   (4 bytes) - filter-specific flags
--   +0x10: intptr_t  data     (8 bytes) - filter-specific data
--   +0x18: void*     udata    (8 bytes) - user data
-- Total: 0x20 (32 bytes) per kevent

local KEVENT_SIZE = 0x20

-- Filter values
local EVFILT_READ    = -1   -- 0xFFFF
local EVFILT_WRITE   = -2
local EVFILT_AIO     = -3
local EVFILT_VNODE   = -4
local EVFILT_PROC    = -5   -- 0xFFFB
local EVFILT_SIGNAL  = -6
local EVFILT_TIMER   = -7
local EVFILT_PROCDESC = -8
local EVFILT_FS      = -9
local EVFILT_LIO     = -10
local EVFILT_USER    = -11
local EVFILT_SENDFILE = -12
local EVFILT_EMPTY   = -13

-- EV flags
local EV_ADD      = 0x0001
local EV_DELETE   = 0x0002
local EV_ENABLE   = 0x0004
local EV_DISABLE  = 0x0008
local EV_ONESHOT  = 0x0010
local EV_CLEAR    = 0x0020
local EV_RECEIPT  = 0x0040
local EV_ERROR    = 0x4000

-- NOTE_ flags for EVFILT_PROC
local NOTE_EXIT    = 0x80000000
local NOTE_FORK    = 0x40000000
local NOTE_EXEC    = 0x20000000
local NOTE_PCTRLMASK = 0xF0000000
local NOTE_PDATAMASK = 0x000FFFFF
local NOTE_TRACK   = 0x00000001
local NOTE_TRACKERR = 0x00000002
local NOTE_CHILD   = 0x00000004

-- Helper to write a kevent struct
local function write_kevent(buf, ident, filter, flags, fflags, data, udata)
    -- ident (8 bytes)
    safe_wq(buf, uint64(ident))
    -- filter (2 bytes) as part of a dword with flags
    -- filter at +0x08 (signed short), flags at +0x0A (unsigned short)
    local filter_u = filter
    if filter < 0 then filter_u = filter + 0x10000 end
    local combined = filter_u + flags * 0x10000
    -- Actually: +0x08 is filter (2 bytes), +0x0A is flags (2 bytes)
    -- As a dword at +0x08: low 16 = filter, high 16 = flags
    safe_wd(buf + 0x08, filter_u + flags * 0x10000)
    -- fflags at +0x0C (4 bytes)
    safe_wd(buf + 0x0C, fflags)
    -- data at +0x10 (8 bytes)
    safe_wq(buf + 0x10, uint64(data or 0))
    -- udata at +0x18 (8 bytes)
    safe_wq(buf + 0x18, uint64(udata or 0))
end

-- Helper to read a kevent struct
local function read_kevent(buf)
    local ident = safe_rq(buf)
    local filter_flags = safe_rd(buf + 0x08)
    local fflags = safe_rd(buf + 0x0C)
    local data = safe_rq(buf + 0x10)
    local udata = safe_rq(buf + 0x18)

    local filter = 0
    local flags = 0
    if filter_flags then
        filter = filter_flags % 0x10000
        if filter >= 0x8000 then filter = filter - 0x10000 end
        flags = math.floor(filter_flags / 0x10000)
    end

    return {
        ident = ident,
        filter = filter,
        flags = flags,
        fflags = fflags or 0,
        data = data,
        udata = udata
    }
end

-- Dump a kevent for analysis
local function dump_kevent(prefix, ev)
    print(string.format("%s ident=%s filter=%d flags=0x%04X fflags=0x%08X",
        prefix, fmt_addr(ev.ident), ev.filter, ev.flags, ev.fflags))
    print(string.format("%s data=%s udata=%s%s",
        prefix, fmt_addr(ev.data), fmt_addr(ev.udata),
        is_kptr(ev.data) and " *** KERNEL PTR IN DATA ***" or ""))
end


-- ================================================================
-- SECTION A: Register EVFILT_PROC on our PID
-- ================================================================
print("")
print("--- SECTION A: EVFILT_PROC registration ---")

local changelist = memory.alloc(KEVENT_SIZE * 4)
local eventlist = memory.alloc(KEVENT_SIZE * 16)

-- Zero everything
for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(changelist + i, 0) end
for i = 0, KEVENT_SIZE * 16 - 4, 4 do safe_wd(eventlist + i, 0) end

-- Register EVFILT_PROC on our PID with ALL note flags
write_kevent(changelist, pid, EVFILT_PROC,
    EV_ADD + EV_ENABLE + EV_CLEAR,
    NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK,
    0, 0xDEADBEEF)

-- Timeout struct: tv_sec=0, tv_nsec=0 (immediate return)
local timeout = memory.alloc(16)
safe_wq(timeout, uint64(0))      -- tv_sec
safe_wq(timeout + 8, uint64(0))  -- tv_nsec

-- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
print("[A] Registering EVFILT_PROC on PID " .. pid .. "...")

local reg_ret = -999
pcall(function()
    reg_ret = to_num(sc_kevent(
        uint64(kq_fd),
        uint64(changelist),
        uint64(1),
        uint64(eventlist),
        uint64(16),
        uint64(timeout)
    ))
end)
print("[A] kevent register ret: " .. reg_ret)

-- Check if any events returned
if reg_ret > 0 then
    print(string.format("[A] %d events returned on registration!", reg_ret))
    for i = 0, reg_ret - 1 do
        local ev = read_kevent(eventlist + i * KEVENT_SIZE)
        dump_kevent(string.format("  [A-ev%d]", i), ev)
    end
elseif reg_ret == 0 then
    print("[A] Registration succeeded (0 events pending)")
else
    print("[A] Registration FAILED — trying kevent2 (560)...")
    -- Try kevent2 (sys 560, some FreeBSD versions)
    pcall(function()
        reg_ret = to_num(sc_kevent2(
            uint64(kq_fd),
            uint64(changelist),
            uint64(1),
            uint64(eventlist),
            uint64(16),
            uint64(timeout)
        ))
    end)
    print("[A] kevent2 ret: " .. reg_ret)
end

-- Check EV_RECEIPT response
if reg_ret >= 0 then
    -- Try with EV_RECEIPT to see error
    for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(changelist + i, 0) end
    for i = 0, KEVENT_SIZE * 16 - 4, 4 do safe_wd(eventlist + i, 0) end

    write_kevent(changelist, pid, EVFILT_PROC,
        EV_ADD + EV_ENABLE + EV_RECEIPT,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC,
        0, 0xCAFEBABE)

    local receipt_ret = -999
    pcall(function()
        receipt_ret = to_num(sc_kevent(
            uint64(kq_fd),
            uint64(changelist),
            uint64(1),
            uint64(eventlist),
            uint64(1),
            uint64(timeout)
        ))
    end)
    print("")
    print("[A2] EV_RECEIPT ret: " .. receipt_ret)
    if receipt_ret > 0 then
        local ev = read_kevent(eventlist)
        dump_kevent("  [A2]", ev)
        -- data field contains errno on EV_ERROR
        if ev.flags and (ev.flags % (EV_ERROR * 2)) >= EV_ERROR then
            local err = ev.data and to_num(ev.data) or -1
            print(string.format("  [A2] ERROR: errno=%d", err))
        end
    end
end


-- ================================================================
-- SECTION B: Self-signal then poll for events
-- ================================================================
print("")
print("--- SECTION B: Signal delivery + kevent poll ---")

-- kill(getpid(), SIGUSR1) then kevent poll
local sc_kill = make_syscall(37)

-- Also register EVFILT_SIGNAL for SIGUSR1 (should work per probe 20/21)
for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(changelist + i, 0) end
for i = 0, KEVENT_SIZE * 16 - 4, 4 do safe_wd(eventlist + i, 0) end

-- Register EVFILT_SIGNAL on SIGUSR1 (signal 30)
write_kevent(changelist, 30, -6, EV_ADD + EV_ENABLE, 0, 0, 0)

local sig_ret = -999
pcall(function()
    sig_ret = to_num(sc_kevent(
        uint64(kq_fd),
        uint64(changelist),
        uint64(1),
        uint64(eventlist),
        uint64(0),
        uint64(timeout)
    ))
end)
print("[B] EVFILT_SIGNAL register: " .. sig_ret)

-- Send ourselves SIGUSR1
pcall(function() sc_kill(uint64(pid), uint64(30)) end)
print("[B] Sent SIGUSR1 to self")

-- Poll for events
for i = 0, KEVENT_SIZE * 16 - 4, 4 do safe_wd(eventlist + i, 0) end
safe_wq(timeout, uint64(0))
safe_wq(timeout + 8, uint64(0))

local poll_ret = -999
pcall(function()
    poll_ret = to_num(sc_kevent(
        uint64(kq_fd),
        uint64(0),
        uint64(0),
        uint64(eventlist),
        uint64(16),
        uint64(timeout)
    ))
end)
print("[B] kevent poll ret: " .. poll_ret)

if poll_ret > 0 then
    for i = 0, poll_ret - 1 do
        local ev = read_kevent(eventlist + i * KEVENT_SIZE)
        dump_kevent(string.format("  [B-ev%d]", i), ev)
        -- CRITICAL: Check all qwords in the raw kevent for kernel pointers
        for off = 0, KEVENT_SIZE - 8, 8 do
            local qval = safe_rq(eventlist + i * KEVENT_SIZE + off)
            if is_kptr(qval) then
                local kh, kl = get_hi_lo(qval)
                print(string.format("  !!! KERNEL PTR at kevent+0x%02X: 0x%08X_%08X !!!", off, kh, kl))
            end
        end
    end
end


-- ================================================================
-- SECTION C: Multiple filter types — comprehensive event data scan
-- ================================================================
print("")
print("--- SECTION C: Multi-filter kernel pointer scan ---")

local filters_to_test = {
    { name = "EVFILT_PROC",   filter = -5,  ident = pid, fflags = 0xF0000007 },
    { name = "EVFILT_TIMER",  filter = -7,  ident = 42,  fflags = 0 },
    { name = "EVFILT_USER",   filter = -11, ident = 99,  fflags = 0x01000000 }, -- NOTE_TRIGGER
    { name = "EVFILT_FS",     filter = -9,  ident = 0,   fflags = 0 },
    { name = "EVFILT_PROCDESC", filter = -8, ident = pid, fflags = 0 },
}

for _, ft in ipairs(filters_to_test) do
    -- Fresh changelist/eventlist
    for i = 0, KEVENT_SIZE - 1, 4 do safe_wd(changelist + i, 0) end
    for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(eventlist + i, 0) end

    write_kevent(changelist, ft.ident, ft.filter,
        EV_ADD + EV_ENABLE + EV_RECEIPT, ft.fflags, 0, 0xA0A0A0A0)

    local ret = -999
    pcall(function()
        ret = to_num(sc_kevent(
            uint64(kq_fd),
            uint64(changelist),
            uint64(1),
            uint64(eventlist),
            uint64(4),
            uint64(timeout)
        ))
    end)

    local status = "ret=" .. ret
    if ret > 0 then
        local ev = read_kevent(eventlist)
        if ev.flags and (ev.flags % (EV_ERROR * 2)) >= EV_ERROR then
            local err = ev.data and to_num(ev.data) or -1
            status = status .. " ERROR errno=" .. err
        else
            status = status .. " OK"
            -- Check for kernel pointers
            for off = 0, KEVENT_SIZE - 8, 8 do
                local qval = safe_rq(eventlist + off)
                if is_kptr(qval) then
                    local kh, kl = get_hi_lo(qval)
                    status = status .. string.format(" KPTR@+0x%02X=0x%08X_%08X", off, kh, kl)
                end
            end
        end
    end

    print(string.format("  %-18s %s", ft.name, status))
end


-- ================================================================
-- SECTION D: EVFILT_USER trigger + data readback
-- ================================================================
print("")
print("--- SECTION D: EVFILT_USER data analysis ---")

-- EVFILT_USER lets us trigger events and read back data
-- The kernel processes the trigger and writes data — check all fields
for i = 0, KEVENT_SIZE - 1, 4 do safe_wd(changelist + i, 0) end
for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(eventlist + i, 0) end

-- First register
write_kevent(changelist, 7777, EVFILT_USER, EV_ADD + EV_ENABLE + EV_CLEAR, 0, 0, 0)

pcall(function()
    sc_kevent(uint64(kq_fd), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(0), uint64(timeout))
end)

-- Now trigger with NOTE_TRIGGER and specific fflags pattern
for i = 0, KEVENT_SIZE - 1, 4 do safe_wd(changelist + i, 0) end
write_kevent(changelist, 7777, EVFILT_USER, 0,
    0x01000000 + 0x41414141,  -- NOTE_TRIGGER | test pattern
    0, 0)

pcall(function()
    sc_kevent(uint64(kq_fd), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(0), uint64(timeout))
end)

-- Poll
for i = 0, KEVENT_SIZE * 4 - 4, 4 do safe_wd(eventlist + i, 0) end
local user_ret = -999
pcall(function()
    user_ret = to_num(sc_kevent(
        uint64(kq_fd), uint64(0), uint64(0),
        uint64(eventlist), uint64(4), uint64(timeout)))
end)
print("[D] EVFILT_USER poll ret: " .. user_ret)

if user_ret > 0 then
    local ev = read_kevent(eventlist)
    dump_kevent("  [D]", ev)

    -- Raw hex dump of entire kevent struct
    print("  [D] Raw kevent hex dump:")
    for off = 0, KEVENT_SIZE - 4, 4 do
        local dw = safe_rd(eventlist + off)
        print(string.format("    +0x%02X: 0x%08X", off, dw or 0))
    end
end


-- ================================================================
-- SECTION E: Close kqueue and final analysis
-- ================================================================
print("")
print("--- SECTION E: Final ---")

local sc_close = make_syscall(6)
pcall(function() sc_close(uint64(kq_fd)) end)
print("[E] kqueue closed")

print("")
print("=== PROBE 119a COMPLETE ===")
