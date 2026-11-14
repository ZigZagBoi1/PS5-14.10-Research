-- CRASH_CLASS: LOW
-- PROBE 1434a: IPv4 multicast source-filter surface, discovered not assumed
--
-- docs/DEAD_ENDS.md records "IPV6_MSFILTER/MCAST_* all return -1" from probes
-- 50e2/50e3, but 50e2/50e3 passed one fixed struct size to every option.  That is
-- exactly the mistake that hid IPV6_MSFILTER from 50e2/50e3 for four months
-- (50f later showed option 74 works with the 152-byte __msfilterreq, and 1427a
-- showed it is fully live).  The v4 side has never been retested with the right
-- shape, and 181a recorded options 72 and 73 returning 0 with a 16-byte buffer --
-- i.e. something in the v4 range does dispatch.
--
-- So this probe discovers rather than assumes:
--   [A] join 224.0.0.1 on ifindex 1 through IP_ADD_MEMBERSHIP (struct ip_mreq, 8)
--   [B] sweep optname 0..90 at IPPROTO_IP with a zeroed 264-byte buffer and print
--       errno for every row -- ENOPROTOOPT(42) means "not implemented",
--       anything else means the handler ran
--   [C] refine every non-42 option with the struct its contract names:
--         42/45 group_req 136, 43/44/46/47 group_source_req 264,
--         48/74 __msfilterreq 152, 12/13 ip_mreq 8, 39-41/72/73 ip_mreq_source 12
--   [D] if IP_MSFILTER (74) is live, read the filter list back with the 152-byte
--       struct, which is the corruption detector the v4 CVE work never had
--
-- Prior art:
--   50e2 results/phase11_network_attacks/50e2_msfilter_v4_*.txt
--   50f  results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt
--   181a results/phase11_network_attacks/181a_*.txt  (opts 72/73 -> 0 with 16 B)
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--   1433a results/phase36_realargs/1433a_msfilter_ifindex_family_20261109_163958.txt

print("=== PROBE 1434a: IPV4 MCAST SOURCE-FILTER SURFACE ===")
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

local sock = -1            -- declared before the helpers: Lua binds upvalues at compile time
local buf = memory.alloc(0x200)
local glen = memory.alloc(16)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end
local src = map(0x10000)          -- 128 x 128-byte sources
local dst = map(0x4000)
assert(src and dst, "mmap failed")

-- sockaddr_in inside a sockaddr_storage: len 16, family 2, port 0, addr E0 xx xx xx
local function put_sin(off, a0, a1, a2, a3)
    b(buf, off + 0, 16)
    b(buf, off + 1, AF_INET)
    b(buf, off + 2, 0); b(buf, off + 3, 0)
    b(buf, off + 4, a0); b(buf, off + 5, a1); b(buf, off + 6, a2); b(buf, off + 7, a3)
end

local function call_get(level, name, len)
    d(glen, 0, len)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(sock), uint64(level), uint64(name),
            uint64(buf), uint64(glen), uint64(0))
    end)
    if not ok then return "EXC" end
    rv = to_num(r)
    return rv
end

local function call_set(level, name, len)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(sock), uint64(level), uint64(name),
            uint64(buf), uint64(len), uint64(0))
    end)
    if not ok then return "EXC" end
    rv = to_num(r)
    return rv
end

sock = to_num(socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("socket(AF_INET,DGRAM,UDP)=%d", sock))
if sock < 0 or sock > 4096 then
    print("no v4 socket -- aborting")
    print("=== PROBE 1434a COMPLETE ===")
    return
end
print("")

-- ---------------------------------------------------------------------
print("[A] join 224.0.0.1 (struct ip_mreq: multiaddr, then an interface ADDRESS)")
-- the second dword of ip_mreq is an in_addr, not an ifindex: 0 = INADDR_ANY
local theirf = {0, 1, 0x0100007F, 0x0000000A}
for _, a in ipairs(theirf) do
    z(buf, 0x200)
    b(buf, 0, 0xE0); b(buf, 1, 0x00); b(buf, 2, 0x00); b(buf, 3, 0x01)
    d(buf, 4, a)
    print(string.format("  join if_addr=0x%08X -> rv=%-4s errno=%s",
        a, tostring(call_set(IPPROTO_IP, 12, 8)), es()))
end
-- sqlock group 224.0.0.1 on the default interface should now be joined
z(buf, 0x200)
b(buf, 0, 0xE0); b(buf, 1, 0x00); b(buf, 2, 0x00); b(buf, 3, 0x01)
d(buf, 4, 0)
print(string.format("  join (default iface) -> rv=%-4s errno=%s",
    tostring(call_set(IPPROTO_IP, 12, 8)), es()))
print("")

-- ---------------------------------------------------------------------
print("[B] discovery sweep, optname 0..90, zeroed 264-byte buffer")
local live = {}
for name = 0, 90 do
    z(buf, 0x200)
    put_sin(8, 0xE0, 0x00, 0x00, 0x01)     -- group_req layout
    d(buf, 0, 1)                           -- gr_interface
    local rvs = call_set(IPPROTO_IP, name, 264)
    local e1 = es()
    z(buf, 0x200)
    put_sin(8, 0xE0, 0x00, 0x00, 0x01)
    d(buf, 0, 1)
    local rvg = call_get(IPPROTO_IP, name, 264)
    local e2 = es()
    if e1 ~= "Protocol not available" or e2 ~= "Protocol not available" then
        print(string.format("  opt %2d  set=%-6s (%-22s)  get=%-6s (%s)",
            name, tostring(rvs), e1, tostring(rvg), e2))
        live[#live + 1] = name
    end
end
print(string.format("  -> %d option(s) dispatched beyond ENOPROTOOPT", #live))
print("")

-- ---------------------------------------------------------------------
print("[C] refine every live option with the struct its contract names")
local function shape_grp(n)
    z(buf, 0x200)
    d(buf, 0, 1)
    put_sin(8, 0xE0, 0x00, 0x00, 0x01)
    return 136
end
local function shape_srcgrp(n)
    z(buf, 0x200)
    d(buf, 0, 1)
    put_sin(8, 0xE0, 0x00, 0x00, 0x01)
    put_sin(136, 0xE0, 0x00, 0x00, 0x02)
    return 264
end
local function shape_msf(n)
    z(buf, 0x200)
    d(buf, 0, 1)          -- msfr_ifindex
    d(buf, 4, 1)          -- msfr_fmode = MCAST_INCLUDE
    d(buf, 8, 1)          -- msfr_nsrcs
    put_sin(16, 0xE0, 0x00, 0x00, 0x01)
    z(src, 256)
    b(src, 0, 16); b(src, 1, AF_INET)
    b(src, 4, 0xE0); b(src, 5, 0); b(src, 6, 0); b(src, 7, 0x02)
    memory.write_qword(buf + 144, uint64(src))
    return 152
end
local function shape_mreq(n)
    z(buf, 0x200)
    b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)
    d(buf, 4, 1)
    return 8
end
local function shape_reqsrc(n)
    z(buf, 0x200)
    b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)   -- multiaddr
    b(buf, 4, 0xE0); b(buf, 5, 0); b(buf, 6, 0); b(buf, 7, 0x02)   -- sourceaddr
    d(buf, 8, 1)                                                    -- interface
    return 12
end

local shapes = {
    [8]  = shape_mreq, [9]  = shape_mreq, [10] = shape_mreq, [11] = shape_mreq,
    [12] = shape_mreq, [13] = shape_mreq,
    [39] = shape_reqsrc, [40] = shape_reqsrc, [41] = shape_reqsrc,
    [72] = shape_reqsrc, [73] = shape_reqsrc,
    [42] = shape_grp, [45] = shape_grp,
    [43] = shape_srcgrp, [44] = shape_srcgrp, [46] = shape_srcgrp, [47] = shape_srcgrp,
    [48] = shape_msf, [74] = shape_msf,
}
for _, name in ipairs(live) do
    local f = shapes[name]
    if f then
        local len = f(name)
        local rvs = call_set(IPPROTO_IP, name, len)
        local e1 = es()
        local len2 = f(name)
        local rvg = call_get(IPPROTO_IP, name, len2)
        local e2 = es()
        print(string.format("  opt %2d len=%-4d set=%-6s (%-24s) get=%-6s (%s)",
            name, len, tostring(rvs), e1, tostring(rvg), e2))
        local nsrc = rd(buf, 8)
        if name == 48 or name == 74 then
            print(string.format("       msfr_ifindex=%d fmode=%d nsrc=%d",
                rd(buf, 0), rd(buf, 4), nsrc))
        end
    else
        print(string.format("  opt %2d -> no shape table entry, skipped", name))
    end
end
print("")

-- ---------------------------------------------------------------------
print("[D] v4 filter readback with a 128-source claim (the detector)")
local len = shape_msf(0)
d(buf, 8, 128)
memory.write_qword(buf + 144, uint64(dst))
for i = 0, 4095 do memory.write_dword(dst + i * 4, 0xA5A5A5A5) end
local rv = call_get(IPPROTO_IP, 74, 152)
local e = es()
local changed, nzh = 0, 0
for i = 0, 4095 do
    local w = rd(dst, i * 4)
    if w ~= 0xA5A5A5A5 then changed = changed + 1 end
    if w ~= 0xA5A5A5A5 and w ~= 0 then nzh = nzh + 1 end
end
print(string.format("  get(IP_MSFILTER, claim=128) -> rv=%s errno=%s", tostring(rv), e))
print(string.format("  changed=%d dwords  (of which non-zero=%d)", changed, nzh))
print("")

print("[E] survivor check")
z(buf, 0x200)
b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)
d(buf, 4, 0)
print(string.format("  drop 224.0.0.1 -> rv=%s errno=%s", tostring(call_set(IPPROTO_IP, 13, 8)), es()))

print("")
print("=== PROBE 1434a COMPLETE ===")
