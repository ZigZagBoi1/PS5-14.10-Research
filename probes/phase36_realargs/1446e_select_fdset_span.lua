-- CRASH_CLASS: LOW
-- PROBE 1446e: select(93)/pselect(522) — is nfds clamped to FD_SETSIZE before the fd_set copy?
--
-- Context: docs/MEMCPY_PROVENANCE.md:291 ranks 0x70322d first among syscall-reachable unchecked
--   copies — `memcpy(arg2+0x20, arg3, arg4)`, twelve straight-line instructions, no capacity
--   compare, no branch, the length then stored into a single byte.  Its shallowest route is
--   syscalls 93 (select) and 522 (pselect) per docs/sysent-names-13.60.csv.
--
--   Instrument history, so this file is not read in isolation:
--     * 1446a (results/phase36_realargs/1446a_select_fdset_bound_20261109_170718.txt) left the
--       bitmaps pattern-filled, so every call answered EBADF before writing them back; it did
--       establish that select(8) and pselect(8) return 3 and that select(0xFFFFFFFFFFFFFFFF,...)
--       returns 0 rather than EINVAL.
--     * 1446b and 1446c both placed the bitmap flush against a munmapped guard page and both died
--       in their own setup.  1446d
--       (results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt) proved why:
--       after `munmap(base+0x3000, 0x1000)` returns 0, a read at `base` faults.  1446d's steps 1-11
--       all succeeded (writes and readbacks at base, +0x2FFC and +0x3FFC), so mmap and the write
--       helper are sound.
--
--       CORRECTION 2026-11-10: the conclusion drawn there — "syscall 73 removes the whole mapping,
--       not the requested page, and no guard hole can be built that way" — is void. The kernel page
--       is 16 KiB (1544a), so `base` and `base+0x3000` were two addresses inside the SAME 0x4000
--       page; the munmap removed that one page, which is why `base` faulted. 1544a measured the real
--       behaviour on a sixteen-page 0x40000 entry and 73 removed exactly the page named. A guard
--       hole IS buildable: map at least two pages and munmap one whole 16 KiB page of them.
--
--   This probe drops the guard page and uses the copy length itself as the instrument: the fd_set
--   lives in a region of known size, and an nfds whose implied copy (nfds/8 bytes) exceeds that
--   region can only answer EFAULT if nfds reaches the copy.  FreeBSD clamps `nd > FD_SETSIZE` to
--   FD_SETSIZE first, in which case every one of these calls copies 128 bytes and none can fault.
--
-- -- prior art: 1446a/1446b/1446c/1446d above are the only select-length attempts in the tree;
--   probes/phase23_cve_2026/502a_select_close_heavy.lua and probes/phase34_shm_race/93e2_poll_close_race.lua
--   use select as a timing device with nfds = fd + 1.  docs/DEAD_ENDS.md has no select bullet.
--
-- Discriminator: [A] runs inside a 64 KiB region and sweeps nfds up to 4194304 (512 KiB implied).
--   EFAULT only appears when nfds/8 exceeds 65536, i.e. at nfds > 524288.  [B] repeats the two
--   largest values inside a 4 MiB region: if they stop faulting, the failure in [A] was the copy
--   length and nfds is trusted; if they still fault, the EFAULT has another cause.

print("=== PROBE 1446e: SELECT FDSET LENGTH (no guard page) ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc477 = make_syscall(477)
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

local function run_sweep(tag, base, span, list, count)
    local TIMEOUT = base + 0x200
    wrq(TIMEOUT, 0)
    wrq(TIMEOUT + 8, 0)
    print(string.format("%s region=0x%08X span=%d bytes  bitmap=0x%08X  timeout=0x%08X",
        tag, base, span, base, TIMEOUT))
    local n = 1
    while n <= count do
        local nd = list[n]
        local implied = nd / 8
        local rv = sgn(sc93(uint64(nd), uint64(base), uint64(0), uint64(0), uint64(TIMEOUT)))
        local e = es()
        local note = ""
        if rv < 0 and e:find("Bad address") then
            if implied > span then
                note = "  <-- EFAULT where nfds/8 exceeds the region: nfds is trusted"
            else
                note = "  <-- EFAULT inside the region: discriminator broken"
            end
        end
        print(string.format("  nfds=%-8d implied=%-7d rv=%-2d (%-22s)%s", nd, implied, rv, e, note))
        n = n + 1
    end
    print("")
end

--------------------------------------------------------------------------
-- [A] 64 KiB region: the bitmap starts at base, so nfds/8 bytes are read
--     from it.  Everything at or below 524288 fits; above that it cannot.
--------------------------------------------------------------------------
local A = map(0x10000, 3)
if A < 0 then
    print("mmap failed -- aborting")
    print("=== PROBE 1446e ABORT ===")
    return
end
local k = 0
while k < 0x10000 do
    wr(A + k, 0)
    k = k + 4
end
print(string.format("pid=%d", pid))
print("")
run_sweep("[A]", A, 0x10000, {1024, 1025, 8192, 65536, 131072, 262144, 524288, 1048576, 4194304}, 9)

--------------------------------------------------------------------------
-- [B] 4 MiB region: the two values that could not fit in [A] must now succeed.
--     If they fault here too, the [A] EFAULT was not a length effect.
--------------------------------------------------------------------------
local B = map(0x400000, 3)
if B < 0 then
    print("[B] mmap failed -- control unavailable")
else
    local j = 0
    while j < 0x400000 do
        wr(B + j, 0)
        j = j + 0x1000
    end
    run_sweep("[B]", B, 0x400000, {524288, 1048576, 4194304, 8388608}, 4)
end

--------------------------------------------------------------------------
-- [C] pselect(522) at the same boundary inside the 64 KiB region
--------------------------------------------------------------------------
print("[C] pselect(522), 64 KiB region")
local TIMEOUT = A + 0x200
wrq(TIMEOUT, 0)
wrq(TIMEOUT + 8, 0)
local pc = 1
local PN = {1024, 524288, 1048576, 4194304}
while pc <= 4 do
    local nd = PN[pc]
    local rv = sgn(sc522(uint64(nd), uint64(A), uint64(0), uint64(0), uint64(TIMEOUT), uint64(0)))
    print(string.format("  nfds=%-8d implied=%-7d rv=%-2d (%s)", nd, nd / 8, rv, es()))
    pc = pc + 1
end
print("")

print(string.format("[D] survivor pid=%d (was %d)", sgn(sc20()), pid))
print("")
print("=== PROBE 1446e COMPLETE ===")
