-- CRASH_CLASS: MODERATE
-- PROBE 1446b: select(93)/pselect(522) fd_set copy length — guard-page discriminator
--
-- Context: docs/MEMCPY_PROVENANCE.md section 6 ranks 0x70322d first of seven syscall-reachable
--   `memcpy` sites with a user-flavoured destination and a caller-chosen length:
--       memcpy(arg2+0x20, arg3, arg4)   -- twelve straight-line instructions, no capacity compare,
--                                          no branch, payload length then stored as a single BYTE
--   Its shallowest syscall-reachable route is through syscalls 93 (select) and 522 (pselect)
--   (docs/sysent-names-13.60.csv: `93,select,0x265928`, `522,pselect,0x265ce0`), and the second
--   candidate 0x4ef6e6 `memcpy(*(arg2+0x10), src, len)` sits at depth 2 from the same pair.
--
--   1446a (results/phase36_realargs/1446a_select_fdset_bound_20261109_170718.txt) tried to measure
--   the write-back length, but the bitmaps were left pattern-filled (all bits SET), so every call
--   died with EBADF before touching them and only the timeval changed (changed=4 at offset 0x8000).
--   That run did record two useful floors: select(8) and pselect(8) both return 3, and
--   select(0xFFFFFFFFFFFFFFFF, ...) returns 0 rather than EINVAL.
--
--   This probe measures the copy-in length instead, which needs no write-back at all: the fd_set is
--   placed so its 128 bytes end exactly at a page boundary and the following page is munmapped.  A
--   kernel that honours nfds reads nd/8 bytes and walks into the hole -> EFAULT.  A kernel that
--   clamps to FD_SETSIZE reads exactly 128 bytes and never notices the hole.  No set bits are used,
--   so EBADF cannot mask the result.
--
-- -- prior art: results/INDEX.md has no select/pselect row with an nfds sweep; 1446a is the only
--   attempt (its capture is cited above).  probes/phase23_cve_2026/502a_select_close_heavy.lua and
--   probes/phase34_shm_race/93e2_poll_close_race.lua use select purely as a timing device with
--   nfds = fd + 1.  docs/MEMCPY_PROVENANCE.md:291 (C1) and :346 (C2) are the static leads;
--   docs/DEAD_ENDS.md has no select bullet.
--
-- Discriminator: for nfds <= 1024 the call must never answer EFAULT; for nfds > 1024 an EFAULT can
--   only come from reading past the bitmap, i.e. the clamp is missing.

print("=== PROBE 1446b: SELECT FDSET COPY LENGTH ===")
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

-- Two pages, then drop the second one: [Q, Q+0x1000) mapped, [Q+0x1000, Q+0x2000) a hole.
local Q = map(0x2000, 3)
if Q < 0 then
    print("mmap failed -- aborting")
    print("=== PROBE 1446b ABORT ===")
    return
end
local i = 0
while i < 0x2000 do
    wr(Q + i, 0)          -- zero everything: no fd bits set, so EBADF cannot mask a result
    i = i + 4
end
local rv_unmap = sgn(sc73(uint64(Q + 0x1000), uint64(0x1000)))
print(string.format("pid=%d region=0x%08X hole=0x%08X munmap=%d", pid, Q, Q + 0x1000, rv_unmap))
if rv_unmap ~= 0 then
    print("  hole could not be created -- the EFAULT discriminator is unavailable")
end
print("")

-- The bitmap ends exactly at the page boundary.
local BITMAP = Q + 0xF80
local TIMEOUT = Q + 0x800
wrq(TIMEOUT, 0)
wrq(TIMEOUT + 8, 0)

-- Never read the hole from userland: a fault there makes the loader's signal
-- handler write a raw mcontext dump into this socket and the capture becomes
-- binary (that is what voided the first 1446b run).  The hole is only ever
-- touched by the kernel.
print(string.format("[0] bitmap=0x%08X ends 0x%08X (next page unmapped)", BITMAP, BITMAP + 0x80))
print("")

--------------------------------------------------------------------------
-- [A] select(93): nfds <= 1024 must never EFAULT; above 1024 an EFAULT means
--     the kernel read nd/8 bytes past the bitmap.
--------------------------------------------------------------------------
print("[A] select(93) nfds sweep, bitmap flush against the hole")
local NFD = {1, 8, 64, 512, 1020, 1024, 1028, 1088, 2048, 4096, 8192, 65536}
local bi = 1
while bi <= 12 do
    local n = NFD[bi]
    local rv = sgn(sc93(uint64(n), uint64(BITMAP), uint64(0), uint64(0), uint64(TIMEOUT)))
    local note = ""
    if rv < 0 then
        local e = es()
        if e:find("Bad address") then
            if n > 1024 then
                note = "  <-- EFAULT PAST FD_SETSIZE: nfds is trusted"
            else
                note = "  <-- EFAULT below FD_SETSIZE: discriminator broken"
            end
        end
        print(string.format("  nfds=%-6d rv=-1 (%s)%s", n, e, note))
    else
        print(string.format("  nfds=%-6d rv=%d", n, rv))
    end
    bi = bi + 1
end
print("")

--------------------------------------------------------------------------
-- [B] the same bitmap in the writefds and exceptfds slots: a port could clamp
--     only one of the three copies.
--------------------------------------------------------------------------
print("[B] slot roles at nfds=8192 (all above FD_SETSIZE)")
local sv = sgn(sc93(uint64(8192), uint64(BITMAP), uint64(0), uint64(0), uint64(TIMEOUT)))
print(string.format("  readfds   rv=%d (%s)", sv, es()))
sv = sgn(sc93(uint64(8192), uint64(0), uint64(BITMAP), uint64(0), uint64(TIMEOUT)))
print(string.format("  writefds  rv=%d (%s)", sv, es()))
sv = sgn(sc93(uint64(8192), uint64(0), uint64(0), uint64(BITMAP), uint64(TIMEOUT)))
print(string.format("  exceptfds rv=%d (%s)", sv, es()))
print("")

--------------------------------------------------------------------------
-- [C] pselect(522): six args (nfds, r, w, e, timeout, sigmask)
--------------------------------------------------------------------------
print("[C] pselect(522) nfds sweep")
local PNFD = {1, 1024, 1028, 2048, 8192, 65536}
local pi = 1
while pi <= 6 do
    local n = PNFD[pi]
    local rv = sgn(sc522(uint64(n), uint64(BITMAP), uint64(0), uint64(0),
                         uint64(TIMEOUT), uint64(0)))
    local note = ""
    if rv < 0 then
        local e = es()
        if e:find("Bad address") and n > 1024 then
            note = "  <-- EFAULT PAST FD_SETSIZE: nfds is trusted"
        end
        print(string.format("  nfds=%-6d rv=-1 (%s)%s", n, e, note))
    else
        print(string.format("  nfds=%-6d rv=%d", n, rv))
    end
    pi = pi + 1
end
print("")

--------------------------------------------------------------------------
-- [D] control: the same 8192/65536 nfds with the bitmap at the START of the
--     page, where 8 KiB of zeroed slack follows.  If these return normally while
--     [A] answered EFAULT on the identical nfds, the EFAULT in [A] can only come
--     from the kernel reading past the 128-byte FD_SETSIZE limit.
--------------------------------------------------------------------------
print("[D] control, bitmap at page start (8 KiB of zeroed slack follows)")
local CAL = Q + 0x0000
wrq(CAL, 0)
wrq(CAL + 8, 0)
local ci = 1
local CN = {1024, 8192, 65536}
while ci <= 3 do
    local rv = sgn(sc93(uint64(CN[ci]), uint64(CAL), uint64(0), uint64(0), uint64(TIMEOUT)))
    print(string.format("  nfds=%-6d rv=%d (%s)", CN[ci], rv, es()))
    ci = ci + 1
end
print("")

print(string.format("[E] survivor pid=%d (was %d)", sgn(sc20()), pid))
print("")
print("=== PROBE 1446b COMPLETE ===")
