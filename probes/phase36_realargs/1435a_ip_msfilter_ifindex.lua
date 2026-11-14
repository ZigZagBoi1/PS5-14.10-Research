-- CRASH_CLASS: LOW
-- PROBE 1435a: IPv4 IP_MSFILTER -- find the interface index, then read the list back
--
-- 1434a established that the v4 multicast surface is live on 14.10:
--   join 224.0.0.1 with ip_mreq.imr_interface = 0 (INADDR_ANY) -> 0
--   join with 127.0.0.1                                       -> 0
--   second join on the same group                             -> EADDRINUSE(48)
-- but every IP_MSFILTER call answered EADDRNOTAVAIL(49) because msfr_ifindex
-- was hardcoded to 1 -- the index the *v6* socket accepts.  INADDR_ANY resolved
-- to some other interface.  So the index is swept here.
--
-- If one index answers 0, the v4 source filter is fully live and [C] runs the
-- same claim/readback test that made the v6 side measurable: set N sources,
-- read back with claim 1 and 128, and count how many dwords the kernel writes.
--
-- Prior art:
--   1434a results/phase36_realargs/1434a_ip_mcast_surface_20261109_164244.txt
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--   1428a results/phase36_realargs/1428a_msfilter_readback_count_20261109_162635.txt
--   1432a results/phase36_realargs/1432a_msfilter_tail_reuse_20261109_163702.txt
--   docs/PRIVATE_IPV6_MSFILTER_1360_STATIC_2026-10-22.md

print("=== PROBE 1435a: IP_MSFILTER IFINDEX DISCOVERY ===")
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

local sock = -1
local buf = memory.alloc(0x200)
local glen = memory.alloc(16)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end
local src = map(0x10000)
local dst = map(0x4000)
assert(src and dst, "mmap failed")

local function put_sin(off, a0, a1, a2, a3)
    b(buf, off + 0, 16)
    b(buf, off + 1, AF_INET)
    b(buf, off + 2, 0); b(buf, off + 3, 0)
    b(buf, off + 4, a0); b(buf, off + 5, a1); b(buf, off + 6, a2); b(buf, off + 7, a3)
end

-- one 128-byte source entry for the v4 list: sockaddr_in, addr at +4
local function put_src(i, a0, a1, a2, a3)
    local e = src + i * 128
    b(e, 0, 16); b(e, 1, AF_INET)
    b(e, 2, 0); b(e, 3, 0)
    b(e, 4, a0); b(e, 5, a1); b(e, 6, a2); b(e, 7, a3)
end

-- build the 152-byte __msfilterreq for IP_MSFILTER
local function msf(ix, nsrc, out, a3)
    z(buf, 0x200)
    d(buf, 0, ix)
    d(buf, 4, 1)          -- MCAST_INCLUDE
    d(buf, 8, nsrc)
    put_sin(16, 0xE0, 0x00, 0x00, (a3 or 0x01))
    memory.write_qword(buf + 144, uint64(out or 0))
    return 152
end

local function call_set(name, len)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(sock), uint64(IPPROTO_IP), uint64(name),
            uint64(buf), uint64(len), uint64(0))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end
local function call_get(name, len)
    d(glen, 0, len)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(sock), uint64(IPPROTO_IP), uint64(name),
            uint64(buf), uint64(glen), uint64(0))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end

sock = to_num(socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("socket=%-4d", sock))
z(buf, 0x200)
b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)
d(buf, 4, 0)
print(string.format("join 224.0.0.1 (iface=ANY) -> rv=%s errno=%s",
    tostring(call_set(12, 8)), es()))
print("")

-- ---------------------------------------------------------------------
print("[A] IP_MSFILTER (74) index sweep, 1 source, 152 bytes")
local good = nil
for ix = 0, 8 do
    put_src(0, 0xE0, 0x00, 0x00, 0x02)
    local len = msf(ix, 1, src)
    local rvs = call_set(74, len)
    local e1 = es()
    local len2 = msf(ix, 1, dst)
    for i = 0, 4095 do memory.write_dword(dst + i * 4, 0xA5A5A5A5) end
    local rvg = call_get(74, len2)
    local e2 = es()
    local nsrc = rd(buf, 8)
    print(string.format("  ix=%d set=%-6s (%-28s) get=%-6s (%-28s) nsrc=%d",
        ix, tostring(rvs), e1, tostring(rvg), e2, nsrc))
    if rvs == 0 and not good then good = ix end
end
print(string.format("  -> working index: %s", good and tostring(good) or "none"))
print("")

if not good then
    print("[B] no index works -- reading the v4 list is unreachable")
    print("")
    print("=== PROBE 1435a COMPLETE ===")
    return
end

-- ---------------------------------------------------------------------
print(string.format("[B] source-filter round trip on ix=%d", good))
for _, n in ipairs({0, 1, 2, 8, 128}) do
    for i = 0, math.max(n - 1, 0) do put_src(i, 0xE0, 0x00, 0x40, i) end
    local len = msf(good, n, src)
    local rvs = call_set(74, len)
    local e1 = es()
    -- read back with claim == real count
    local len2 = msf(good, n, dst)
    for i = 0, 4095 do memory.write_dword(dst + i * 4, 0xA5A5A5A5) end
    local rvg = call_get(74, len2)
    local e2 = es()
    local got = rd(buf, 8)
    local changed, first = 0, rd(dst, 0)
    for i = 0, 4095 do
        if rd(dst, i * 4) ~= 0xA5A5A5A5 then changed = changed + 1 end
    end
    print(string.format("  set %3d -> %-6s (%-24s)  get-> %-6s (%-24s) numsrc=%-4d changed=%d d0=%08X",
        n, tostring(rvs), e1, tostring(rvg), e2, got, changed, first))
end
print("")

-- ---------------------------------------------------------------------
print("[C] claim 128 on a 1-source filter (the length-trust test)")
put_src(0, 0xE0, 0x00, 0x40, 0x11)
print(string.format("  arm 1 source -> %s", tostring(call_set(74, msf(good, 1, src)))))
local len2 = msf(good, 128, dst)
for i = 0, 4095 do memory.write_dword(dst + i * 4, 0xA5A5A5A5) end
local rvg = call_get(74, len2)
local e2 = es()
local changed, nzh = 0, 0
for i = 0, 4095 do
    local w = rd(dst, i * 4)
    if w ~= 0xA5A5A5A5 then changed = changed + 1 end
    if w ~= 0xA5A5A5A5 and w ~= 0 then nzh = nzh + 1 end
end
print(string.format("  get claim=128 -> rv=%s errno=%s numsrc=%d",
    tostring(rvg), e2, rd(buf, 8)))
print(string.format("  changed=%d dwords (non-zero past pattern = %d)", changed, nzh))
print("")

-- ---------------------------------------------------------------------
print("[D] the per-source options, 12-byte ip_mreq_source")
for _, name in ipairs({39, 40, 41, 72, 73}) do
    z(buf, 0x200)
    b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)   -- group
    b(buf, 4, 0xE0); b(buf, 5, 0); b(buf, 6, 0); b(buf, 7, 0x02)   -- source
    d(buf, 8, 0)                                                   -- interface addr
    print(string.format("  opt %2d set=%-6s errno=%s", name, tostring(call_set(name, 12)), es()))
end
print("")

print("[E] survivor check")
print(string.format("  get 74 ix=%d -> rv=%s", good, tostring(call_get(74, msf(good, 1, dst)))))

print("")
print("=== PROBE 1435a COMPLETE ===")
