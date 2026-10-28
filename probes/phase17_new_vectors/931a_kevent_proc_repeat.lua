-- CRASH_CLASS: HIGH
-- PROBE 931a: repeat EVFILT_PROC registration — isolate the 2026-10-28 console panic
--
-- Context: 105a registered EVFILT_PROC on its own pid with NOTE_TRACK and
-- returned 0. A later connection (78d) registered EVFILT_PROC on the same pid
-- and the kevent call never returned; the console then crashed. The process is
-- shared across TCP connections, so 105a's kqueue was still open.
--
-- This probe separates the two candidate mechanisms:
--   SECTION 1  two kqueues, both registering EVFILT_PROC self, NO NOTE_TRACK
--   SECTION 2  first registration carries NOTE_TRACK, second does not
--   SECTION 3  the 78d shape exactly (nevents=0, eventlist=NULL)
--
-- Every section prints a marker before the call that could hang, so a dead run
-- still says where it stopped. SECTION 1 is the safe measurement; 2 and 3 are
-- run only on request (edit SECTION below).
--
-- Run SECTION 1 first. If it survives, SECTION 2 is the discriminating run.

local SECTION = 5

print("=== PROBE 931a: KEVENT EVFILT_PROC REPEAT ===")
print("SECTION=" .. SECTION)
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function zero(buf, n)
    for i = 0, n - 1, 4 do wd(buf + i, 0) end
end

local sc_getpid = make_syscall(20)
local sc_kqueue = make_syscall(362)
local sc_kevent = make_syscall(363)
local sc_close  = make_syscall(6)

local EVFILT_PROC = -5
local EV_ADD     = 0x0001
local EV_ENABLE  = 0x0004
local EV_CLEAR   = 0x0020
local NOTE_EXIT  = 0x80000000
local NOTE_FORK  = 0x40000000
local NOTE_EXEC  = 0x20000000
local NOTE_TRACK = 0x00000001

local ok_pid, rv_pid = pcall(function() return sc_getpid() end)
local pid = ok_pid and to_num(rv_pid) or -1
print("pid=" .. pid)
print("")

local changelist = memory.alloc(0x40)
local eventlist  = memory.alloc(0x200)
local ts         = memory.alloc(16)   -- zero timespec: never block

local function kevent_write(buf, ident, filter, flags, fflags, data_, udata)
    zero(buf, 0x20)
    wq(buf + 0x00, uint64(ident))
    local f = filter
    if f < 0 then f = 0x10000 + f end
    wd(buf + 0x08, f + flags * 0x10000)
    wd(buf + 0x0C, fflags)
    wq(buf + 0x10, uint64(data_))
    wq(buf + 0x18, uint64(udata))
end

local function register(kq, fflags, label)
    kevent_write(changelist, pid, EVFILT_PROC,
        EV_ADD + EV_ENABLE + EV_CLEAR, fflags, 0, 0xAABB0000)
    print("  [BEFORE] " .. label .. " (kq=" .. kq .. " fflags=0x" ..
        string.format("%X", fflags) .. ")")
    local ok, rv = pcall(function()
        return to_num(sc_kevent(uint64(kq), uint64(changelist), uint64(1),
            uint64(eventlist), uint64(4), uint64(ts)))
    end)
    print("  [AFTER ] " .. label .. " ok=" .. tostring(ok) ..
        " rv=" .. tostring(rv))
    return ok and rv == 0
end

local function new_kq(label)
    local ok, fd = pcall(function() return to_num(sc_kqueue()) end)
    local n = ok and fd or -999
    print("  " .. label .. " kqueue fd=" .. n)
    return n
end

--------------------------------------------------------------------
-- SECTION 1: two registrations, no NOTE_TRACK
--------------------------------------------------------------------
local kqA = new_kq("A:")
if kqA >= 0 then
    register(kqA, NOTE_EXIT + NOTE_FORK + NOTE_EXEC, "A register")
    print("  [STEP] A registered, closing nothing yet")

    local kqB = new_kq("B:")
    if kqB >= 0 then
        register(kqB, NOTE_EXIT + NOTE_FORK + NOTE_EXEC, "B register")
        print("  [STEP] B registered - polling A")

        print("  [BEFORE] poll A")
        local okp, np = pcall(function()
            return to_num(sc_kevent(uint64(kqA), uint64(0), uint64(0),
                uint64(eventlist), uint64(4), uint64(ts)))
        end)
        print("  [AFTER ] poll A ok=" .. tostring(okp) .. " nevents=" .. tostring(np))

        local close_ok, _ = pcall(function() return sc_close(uint64(kqB)) end)
        print("  [STEP] B closed ok=" .. tostring(close_ok))
    end
    local close_ok, _ = pcall(function() return sc_close(uint64(kqA)) end)
    print("  [STEP] A closed ok=" .. tostring(close_ok))
end
print("[SECTION 1] complete")
print("")

--------------------------------------------------------------------
-- SECTION 2: NOTE_TRACK first, plain second
--------------------------------------------------------------------
if SECTION == 2 then
    local kqC = new_kq("C (TRACK):")
    if kqC >= 0 then
        register(kqC, NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK, "C register TRACK")
        print("  [STEP] C registered with NOTE_TRACK")

        local kqD = new_kq("D:")
        if kqD >= 0 then
            register(kqD, NOTE_EXIT + NOTE_FORK + NOTE_EXEC, "D register plain")
            pcall(function() return sc_close(uint64(kqD)) end)
        end
        pcall(function() return sc_close(uint64(kqC)) end)
        print("  [STEP] C/D closed")
    end
    print("[SECTION 2] complete")
    print("")
end

--------------------------------------------------------------------
-- SECTION 3: the 78d shape, nevents=0 and eventlist=NULL
--------------------------------------------------------------------
if SECTION == 3 then
    local kqE = new_kq("E:")
    if kqE >= 0 then
        kevent_write(changelist, pid, EVFILT_PROC,
            EV_ADD + EV_ENABLE + EV_CLEAR,
            NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0)
        print("  [BEFORE] E register with nevents=0 eventlist=NULL")
        local ok, rv = pcall(function()
            return to_num(sc_kevent(uint64(kqE), uint64(changelist), uint64(1),
                uint64(0), uint64(0), uint64(0)))
        end)
        print("  [AFTER ] E register ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
        pcall(function() return sc_close(uint64(kqE)) end)
    end
    print("[SECTION 3] complete")
    print("")
end

--------------------------------------------------------------------
-- SECTION 4: nevents=0 and eventlist=NULL, but a zero timespec
--------------------------------------------------------------------
if SECTION == 4 then
    local kqF = new_kq("F:")
    if kqF >= 0 then
        kevent_write(changelist, pid, EVFILT_PROC,
            EV_ADD + EV_ENABLE + EV_CLEAR,
            NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0)
        print("  [BEFORE] F register nevents=0 NULL eventlist, zero timeout")
        local ok, rv = pcall(function()
            return to_num(sc_kevent(uint64(kqF), uint64(changelist), uint64(1),
                uint64(0), uint64(0), uint64(ts)))
        end)
        print("  [AFTER ] F register ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
        pcall(function() return sc_close(uint64(kqF)) end)
    end
    print("[SECTION 4] complete")
    print("")
end

--------------------------------------------------------------------
-- SECTION 5: the 78d shape verbatim — NULL timeout, nevents=0, NULL eventlist
--------------------------------------------------------------------
if SECTION == 5 then
    local kqG = new_kq("G:")
    if kqG >= 0 then
        kevent_write(changelist, pid, EVFILT_PROC,
            EV_ADD + EV_ENABLE + EV_CLEAR,
            NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0xAABBCCDD)
        print("  [BEFORE] G register nevents=0 NULL eventlist NULL timeout (78d shape)")
        local ok, rv = pcall(function()
            return to_num(sc_kevent(uint64(kqG), uint64(changelist), uint64(1),
                uint64(0), uint64(0), uint64(0)))
        end)
        print("  [AFTER ] G register ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
        pcall(function() return sc_close(uint64(kqG)) end)
    end
    print("[SECTION 5] complete")
    print("")
end

--------------------------------------------------------------------
-- SECTION 6: no changes at all, NULL timeout — a pure "wait for events"
--------------------------------------------------------------------
if SECTION == 6 then
    local kqH = new_kq("H:")
    if kqH >= 0 then
        print("  [BEFORE] H wait nchanges=0 nevents=0 NULL timeout")
        local ok, rv = pcall(function()
            return to_num(sc_kevent(uint64(kqH), uint64(0), uint64(0),
                uint64(0), uint64(0), uint64(0)))
        end)
        print("  [AFTER ] H wait ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
        pcall(function() return sc_close(uint64(kqH)) end)
    end
    print("[SECTION 6] complete")
    print("")
end

print("=== PROBE 931a COMPLETE ===")
