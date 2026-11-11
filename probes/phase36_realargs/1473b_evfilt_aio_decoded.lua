-- CRASH_CLASS: LOW -- kqueue only; no device access, no writes outside our own buffers.
-- PROBE 1473b: EVFILT_AIO, decoded -- is the registration accepted or echoed back as EV_ERROR?
--
-- Context:
--   1473a registered EVFILT_AIO on a live AIO request id and read every kevent return value of 1
--   as "an event was delivered", concluding that the filter is a permanently-ready no-op that
--   keeps firing after the request is deleted.  That reading is wrong if the value 1 is an
--   EV_ERROR echo: kqueue reports a FAILED change by placing one event in the eventlist with
--   EV_ERROR (0x4000) set in fflags and the errno in data, and kevent's return value counts that
--   event.  93d3 already measured exactly that for this filter on this console
--   (results/phase34_shm_race/93d3_kevent_sony_fuzz_20261105_085507.txt: `EVFILT_AIO: ret=1
--   changed=true ... 4000FFFD ... data=1` = filter -3, flags 0x4000, errno EPERM(1)).
--
--   This probe separates the two readings with the smallest possible instrument:
--     [1] a change-only call (nevents = 0).  A rejected change returns -1 and the errno is
--         readable; an accepted change returns 0.
--     [2] a receive-only call (nchanges = 0, changelist NULL) after a change-only attempt.
--         Nothing can be echoed here, so any event returned was genuinely queued by the filter.
--     [3] the same two calls with an ident that was never a request (0x0FFF) and with ident 0.
--     [4] a request that is genuinely complete (socket fed) before the calls, so a working filter
--         has something real to deliver.
--
--   Every event is printed as ident / filter / flags / data, with the flags word decoded, because
--   1473a threw that word away and with it the only discriminator.
--
-- -- prior art:
--   results/phase34_shm_race/93d3_kevent_sony_fuzz_20261105_085507.txt (ident 0 -> EV_ERROR EPERM)
--   results/phase36_realargs/1473a_evfilt_aio_lifetime_20261109_181742.txt (the misread run)
--   probes/phase13_53batch/56q_kevent_scm_rights_sendfile.lua (kevent struct and call shape)

print("=== PROBE 1473b: EVFILT_AIO DECODED ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function sgn(rv) local n = to_num(rv) if n < 0 then return -1 end return n end
local function hx(v) if v == nil then return "????" end return string.format("%08X", v % 4294967296) end
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) % 4294967296 end return nil end
local function rdq(a) local ok, v = pcall(function() return memory.read_qword(a) end) if ok then local h, l = 0, to_num(v) % 4294967296 if type(v) == "table" and v.h then h = v.h end return h * 4294967296 + l end return nil end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wrq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function as_addr(t) local s = tostring(t) local m = s:match("0x(%x+)") if m then return tonumber(m, 16) end return to_num(t) end
local function es() local ok, s = pcall(function() return get_error_string() end) if ok and type(s) == "string" then return s end return "?" end

local AIO_SUB  = make_syscall(669)
local AIO_POLL = make_syscall(664)
local AIO_DEL  = make_syscall(662)
local KQUEUE   = make_syscall(362)
local KEVENT   = make_syscall(363)
local GETPID   = make_syscall(20)
local SSOCKET  = make_syscall(135)
local WRITE    = make_syscall(4)
local MAP      = make_syscall(477)

local pid = sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("canary getpid=%d", pid))

local ok, va = pcall(function() return MAP(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local p = ok and to_num(va) or -1
if p < 0x10000 or p > 0x8000000000 then print("mmap failed"); return end

local REQ    = p + 0x0000
local DATA   = p + 0x0100
local RESULT = p + 0x0200
local IDS    = p + 0x0300
local STATE  = p + 0x0400
local PAIR   = p + 0x0500
local CHG    = p + 0x0600
local EVT    = p + 0x0700
local TS     = p + 0x0800

local sp = sgn(SSOCKET(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0)))
local rd_fd, wr_fd = rd(PAIR), rd(PAIR + 4)
local kq = sgn(KQUEUE(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[0] socketpair=%d read=%d write=%d kqueue=%d", sp, rd_fd, wr_fd, kq))
if rd_fd <= 0 or kq < 0 then print("setup failed"); return end

local payload = memory.alloc(16)
local PL = as_addr(payload)
for i = 0, 15 do pcall(function() memory.write_byte(uint64(PL + i), 0x41 + i) end) end
local function feed() pcall(function() WRITE(uint64(wr_fd), uint64(PL), uint64(16), uint64(0), uint64(0), uint64(0)) end) end

local EV_ADD, EV_ERROR, EVFILT_AIO = 0x1, 0x4000, -3

local function arm_request()
    for j = 0, 0x24, 4 do wr(REQ + j, 0) end
    wrq(REQ + 0x08, 16)
    wrq(REQ + 0x10, DATA)
    wrq(REQ + 0x18, RESULT)
    wr(REQ + 0x20, rd_fd)
end
local function submit()
    arm_request(); wr(IDS, 0); wrq(RESULT, 0)
    sgn(AIO_SUB(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    return rd(IDS)
end

local function set_change(ident, filter, flags)
    wrq(CHG + 0x00, ident)
    wr(CHG + 0x08, ((flags % 65536) * 65536 + (filter % 65536)) % 4294967296)
    wr(CHG + 0x0C, 0)
    wrq(CHG + 0x10, 0)
    wrq(CHG + 0x18, 0)
end
local function clear_events()
    for i = 0, 3 do
        wrq(EVT + i * 0x20 + 0x00, 0); wr(EVT + i * 0x20 + 0x08, 0)
        wr(EVT + i * 0x20 + 0x0C, 0); wrq(EVT + i * 0x20 + 0x10, 0); wrq(EVT + i * 0x20 + 0x18, 0)
    end
end
local function print_event(i)
    local base = EVT + i * 0x20
    local fw = rd(base + 0x08) or 0
    local filter = fw % 65536
    if filter >= 32768 then filter = filter - 65536 end
    local flags = math.floor(fw / 65536) % 65536
    local data = rdq(base + 0x10)
    print(string.format("     ev[%d] ident=0x%X filter=%d flags=0x%04X data=%d%s",
        i, rdq(base) or 0, filter, flags, data or -1,
        (flags % (EV_ERROR * 2) >= EV_ERROR) and "  <-- EV_ERROR echo" or ""))
end

local function change_only(ident, tag)
    set_change(ident, EVFILT_AIO, EV_ADD)
    local rv = sgn(KEVENT(uint64(kq), uint64(CHG), uint64(1), uint64(0), uint64(0), uint64(0)))
    if rv == -1 then
        print(string.format("   %s change-only -> -1 errno=%s", tag, es()))
    else
        print(string.format("   %s change-only -> %d (accepted)", tag, rv))
    end
    return rv
end
local function receive(tag)
    clear_events()
    local rv = sgn(KEVENT(uint64(kq), uint64(0), uint64(0), uint64(EVT), uint64(4), uint64(0)))
    print(string.format("   %s receive-only -> %d", tag, rv))
    if rv > 0 then for i = 0, math.min(rv, 4) - 1 do print_event(i) end end
    return rv, rd(EVT + 0x08)
end

--------------------------------------------------------------------------
-- [1] change-only, live request identifier
--------------------------------------------------------------------------
print("")
print("[1] change-only on a live request")
local id1 = submit()
print(string.format("   id=0x%X", id1))
change_only(id1, "live")
receive("live")

--------------------------------------------------------------------------
-- [2] an identifier that was never a request, and ident 0
--------------------------------------------------------------------------
print("")
print("[2] controls")
change_only(0x0FFF, "never")
receive("never")
change_only(0, "zero")
receive("zero")

--------------------------------------------------------------------------
-- [3] a request that is genuinely complete before the change
--------------------------------------------------------------------------
print("")
print("[3] complete request, then change-only and receive-only")
local id2 = submit()
print(string.format("   id=0x%X", id2))
feed()
wr(STATE, 0x5A5A5A5A)
local rvp = sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(STATE)))
print(string.format("   664 poll -> rv=%d state=%s", rvp, hx(rd(STATE))))
change_only(id2, "complete")
receive("complete")

--------------------------------------------------------------------------
-- [4] delete, then change-only again
--------------------------------------------------------------------------
print("")
print("[4] delete, then change-only on the deleted identifier")
wr(IDS, id2); wr(STATE, 0x5A5A5A5A)
local rvd = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
print(string.format("   662 delete -> rv=%d state=%s", rvd, hx(rd(STATE))))
change_only(id2, "deleted")
receive("deleted")

print("")
print(string.format("[Z] alive pid=%d (was %d)", sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))), pid))
print("")
print("=== PROBE 1473b COMPLETE ===")
