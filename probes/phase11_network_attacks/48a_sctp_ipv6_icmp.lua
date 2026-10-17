-- CRASH_CLASS: LOW
-- PROBE 48a: SCTP, IPv6, ICMP Socket Availability
--
-- Context: All loader-internal code execution paths are dead (CClosure+0
-- read-only, fn_addr unused, ROP chain unused). Network-side attacks are
-- the only remaining path. This probe tests which protocol families and
-- socket types are available — SCTP, IPv6, ICMPv6, DIVERT, raw protocols.
--
-- Each protocol that opens successfully is new, untested kernel attack surface.
-- SCTP in particular has had many kernel CVEs in FreeBSD.
--
-- This probe:
--   A. SCTP socket creation (multiple types)
--   B. IPv6 socket creation + dual-stack test
--   C. ICMP/ICMPv6 raw socket test
--   D. DIVERT socket test (FreeBSD firewall interception)
--   E. Protocol sweep: try all IP protocols 0-142 as raw sockets
--   F. Socket option enumeration on any working socket

print("=== PROBE 48a: SCTP/IPv6/ICMP AVAILABILITY ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)

local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)
local sc_bind = make_syscall(104)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_connect = make_syscall(98)
local sc_sendto = make_syscall(133)

-- Protocol constants
local AF_INET  = 2
local AF_INET6 = 28
local AF_LOCAL = 1
local AF_ROUTE = 17
local AF_DIVERT = 44   -- FreeBSD divert socket

local SOCK_STREAM = 1
local SOCK_DGRAM  = 2
local SOCK_RAW    = 3
local SOCK_SEQPACKET = 5

local IPPROTO_TCP  = 6
local IPPROTO_UDP  = 17
local IPPROTO_SCTP = 132
local IPPROTO_ICMP = 1
local IPPROTO_ICMPV6 = 58
local IPPROTO_RAW  = 255
local IPPROTO_DIVERT = 258  -- FreeBSD IPPROTO_DIVERT

local function try_socket(af, stype, proto, desc)
    local ok, rv = pcall(function() return sc_socket(uint64(af), uint64(stype), uint64(proto)) end)
    local fd = ok and to_num(rv) or -999
    local status = fd >= 0 and "OPEN fd=" .. fd or "FAILED (" .. fd .. ")"
    print(string.format("  %-40s %s", desc, status))
    if fd >= 0 then
        pcall(function() sc_close(uint64(fd)) end)
    end
    return fd
end

-- ============================================
-- SECTION A: SCTP sockets
-- ============================================
print("=== A: SCTP SOCKETS ===")
local sctp_stream = try_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, "SCTP/INET stream")
local sctp_dgram  = try_socket(AF_INET, SOCK_DGRAM, IPPROTO_SCTP, "SCTP/INET dgram")
local sctp_seq    = try_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP, "SCTP/INET seqpacket")
local sctp_raw    = try_socket(AF_INET, SOCK_RAW, IPPROTO_SCTP, "SCTP/INET raw")
local sctp6_stream = try_socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP, "SCTP/INET6 stream")
local sctp6_seq    = try_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, "SCTP/INET6 seqpacket")

local any_sctp = (sctp_stream >= 0 or sctp_dgram >= 0 or sctp_seq >= 0 or
                  sctp_raw >= 0 or sctp6_stream >= 0 or sctp6_seq >= 0)
if any_sctp then
    print("  *** SCTP IS AVAILABLE — new attack surface! ***")
else
    print("  SCTP: all socket types blocked")
end
print("")

-- ============================================
-- SECTION B: IPv6 sockets
-- ============================================
print("=== B: IPv6 SOCKETS ===")
local v6_tcp   = try_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, "TCP/IPv6")
local v6_udp   = try_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "UDP/IPv6")
local v6_raw   = try_socket(AF_INET6, SOCK_RAW, IPPROTO_RAW, "RAW/IPv6")
local v6_icmp6 = try_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, "ICMPv6/IPv6")
local v6_dgram0 = try_socket(AF_INET6, SOCK_DGRAM, 0, "DGRAM/IPv6 proto=0")

local any_v6 = (v6_tcp >= 0 or v6_udp >= 0 or v6_raw >= 0 or
                v6_icmp6 >= 0 or v6_dgram0 >= 0)
if any_v6 then
    print("  *** IPv6 IS AVAILABLE — new attack surface! ***")

    -- Test dual-stack: can IPv6 socket receive IPv4?
    if v6_udp >= 0 then
        -- Re-open and test IPV6_V6ONLY
        local ok6, rv6 = pcall(function()
            return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
        end)
        local fd6 = ok6 and to_num(rv6) or -1
        if fd6 >= 0 then
            local optval = memory.alloc(4)
            local optlen = memory.alloc(4)
            safe_wd(optlen, 4)
            -- IPV6_V6ONLY = 27 on FreeBSD, level IPPROTO_IPV6 = 41
            local ok_go, rv_go = pcall(function()
                return sc_getsockopt(uint64(fd6), uint64(41), uint64(27),
                    uint64(optval), uint64(optlen))
            end)
            local v6only = safe_rd(optval)
            print(string.format("  IPV6_V6ONLY default: %s (getsockopt ret=%s)",
                tostring(v6only), ok_go and tostring(to_num(rv_go)) or "fail"))

            -- Try to disable V6ONLY (enable dual-stack)
            safe_wd(optval, 0)
            local ok_so, rv_so = pcall(function()
                return sc_setsockopt(uint64(fd6), uint64(41), uint64(27),
                    uint64(optval), uint64(4))
            end)
            print(string.format("  Disable V6ONLY: ret=%s",
                ok_so and tostring(to_num(rv_so)) or "fail"))

            pcall(function() sc_close(uint64(fd6)) end)
        end
    end
else
    print("  IPv6: all socket types blocked")
end
print("")

-- ============================================
-- SECTION C: ICMP sockets
-- ============================================
print("=== C: ICMP SOCKETS ===")
try_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, "ICMP/INET raw")
try_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, "ICMP/INET dgram (unprivileged)")
try_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, "ICMPv6/INET6 raw")
try_socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, "ICMPv6/INET6 dgram")
print("")

-- ============================================
-- SECTION D: DIVERT sockets
-- ============================================
print("=== D: DIVERT / SPECIAL SOCKETS ===")
try_socket(AF_DIVERT, SOCK_RAW, 0, "DIVERT raw proto=0")
try_socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT, "INET raw proto=DIVERT")
try_socket(AF_ROUTE, SOCK_RAW, 0, "AF_ROUTE raw (already tested)")
-- Netgraph (FreeBSD only)
try_socket(32, SOCK_DGRAM, 0, "AF_NETGRAPH dgram")
try_socket(32, SOCK_STREAM, 0, "AF_NETGRAPH stream")
-- Bluetooth
try_socket(36, SOCK_RAW, 0, "AF_BLUETOOTH raw")
try_socket(36, SOCK_SEQPACKET, 0, "AF_BLUETOOTH seqpacket")
print("")

-- ============================================
-- SECTION E: Protocol sweep (raw sockets)
-- ============================================
print("=== E: RAW SOCKET PROTOCOL SWEEP ===")
print("Testing all IP protocols 0-142 as SOCK_RAW/INET:")
local working_protos = {}
for proto = 0, 142 do
    local ok, rv = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(proto))
    end)
    local fd = ok and to_num(rv) or -999
    if fd >= 0 then
        table.insert(working_protos, proto)
        pcall(function() sc_close(uint64(fd)) end)
    end
end
print("  Working protocols: " .. #working_protos)
for _, p in ipairs(working_protos) do
    local name = "unknown"
    if p == 0 then name = "HOPOPT"
    elseif p == 1 then name = "ICMP"
    elseif p == 2 then name = "IGMP"
    elseif p == 4 then name = "IP-in-IP"
    elseif p == 6 then name = "TCP"
    elseif p == 17 then name = "UDP"
    elseif p == 41 then name = "IPv6-encap"
    elseif p == 43 then name = "IPv6-Route"
    elseif p == 44 then name = "IPv6-Frag"
    elseif p == 47 then name = "GRE"
    elseif p == 50 then name = "ESP"
    elseif p == 51 then name = "AH"
    elseif p == 58 then name = "ICMPv6"
    elseif p == 59 then name = "IPv6-NoNxt"
    elseif p == 60 then name = "IPv6-Opts"
    elseif p == 89 then name = "OSPF"
    elseif p == 103 then name = "PIM"
    elseif p == 112 then name = "VRRP"
    elseif p == 132 then name = "SCTP"
    elseif p == 136 then name = "UDPLite"
    end
    print(string.format("    proto %3d: %s", p, name))
end
print("")

-- Also sweep IPv6 raw protocols
print("Testing IPv6 raw socket protocols:")
local working_v6_protos = {}
for _, proto in ipairs({0, 1, 2, 6, 17, 41, 43, 44, 47, 50, 51, 58, 59, 60,
                        89, 103, 112, 132, 136, 255}) do
    local ok, rv = pcall(function()
        return sc_socket(uint64(AF_INET6), uint64(SOCK_RAW), uint64(proto))
    end)
    local fd = ok and to_num(rv) or -999
    if fd >= 0 then
        table.insert(working_v6_protos, proto)
        pcall(function() sc_close(uint64(fd)) end)
    end
end
print("  Working IPv6 protocols: " .. #working_v6_protos)
for _, p in ipairs(working_v6_protos) do
    print(string.format("    proto %3d", p))
end
print("")

-- ============================================
-- SECTION F: Socket option enumeration
-- ============================================
print("=== F: SOCKET OPTION ENUMERATION ===")
-- Open a UDP socket and enumerate interesting socket options
local ok_u, rv_u = pcall(function()
    return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
end)
local udp_fd = ok_u and to_num(rv_u) or -1
if udp_fd >= 0 then
    local optval = memory.alloc(256)
    local optlen = memory.alloc(4)

    -- SOL_SOCKET options
    print("SOL_SOCKET (0xFFFF) options:")
    local sol_opts = {
        {0x0001, "SO_DEBUG"}, {0x0002, "SO_ACCEPTCONN"}, {0x0004, "SO_REUSEADDR"},
        {0x0008, "SO_KEEPALIVE"}, {0x0010, "SO_DONTROUTE"}, {0x0020, "SO_BROADCAST"},
        {0x0080, "SO_LINGER"}, {0x0100, "SO_OOBINLINE"}, {0x0200, "SO_REUSEPORT"},
        {0x0400, "SO_TIMESTAMP"}, {0x0800, "SO_NOSIGPIPE"},
        {0x1001, "SO_SNDBUF"}, {0x1002, "SO_RCVBUF"},
        {0x1003, "SO_SNDLOWAT"}, {0x1004, "SO_RCVLOWAT"},
        {0x1005, "SO_SNDTIMEO"}, {0x1006, "SO_RCVTIMEO"},
        {0x1007, "SO_ERROR"}, {0x1008, "SO_TYPE"},
        {0x1009, "SO_LABEL"}, {0x1010, "SO_PEERLABEL"},
        {0x1011, "SO_LISTENQLIMIT"}, {0x1012, "SO_LISTENQLEN"},
        {0x1013, "SO_LISTENINCQLEN"}, {0x1015, "SO_SETFIB"},
        {0x1016, "SO_USER_COOKIE"}, {0x1017, "SO_PROTOCOL"},
    }
    for _, opt in ipairs(sol_opts) do
        for i = 0, 255 do safe_wd(optval + i, 0) end
        safe_wd(optlen, 256)
        local ok_g, rv_g = pcall(function()
            return sc_getsockopt(uint64(udp_fd), uint64(0xFFFF), uint64(opt[1]),
                uint64(optval), uint64(optlen))
        end)
        local ret = ok_g and to_num(rv_g) or -999
        if ret == 0 then
            local len = safe_rd(optlen) or 0
            local val = safe_rd(optval) or 0
            print(string.format("    0x%04X %-20s len=%d val=%d (0x%X)",
                opt[1], opt[2], len, val, val))
        end
    end

    -- IPPROTO_IP options (level 0)
    print("")
    print("IPPROTO_IP (0) options:")
    local ip_opts = {
        {1, "IP_OPTIONS"}, {2, "IP_HDRINCL"}, {3, "IP_TOS"},
        {4, "IP_TTL"}, {5, "IP_RECVOPTS"}, {6, "IP_RECVRETOPTS"},
        {7, "IP_RECVDSTADDR"}, {8, "IP_SENDSRCADDR"}, {9, "IP_RETOPTS"},
        {10, "IP_MULTICAST_IF"}, {11, "IP_MULTICAST_TTL"},
        {12, "IP_MULTICAST_LOOP"}, {21, "IP_PORTRANGE"},
        {22, "IP_RECVIF"}, {23, "IP_IPSEC_POLICY"},
        {24, "IP_FAITH"}, {25, "IP_ONESBCAST"}, {26, "IP_BINDANY"},
        {27, "IP_BINDMULTI"}, {28, "IP_RSS_LISTEN_BUCKET"},
        {29, "IP_ORIGDSTADDR"}, {30, "IP_RECVORIGDSTADDR"},
    }
    for _, opt in ipairs(ip_opts) do
        for i = 0, 63 do safe_wd(optval + i, 0) end
        safe_wd(optlen, 64)
        local ok_g, rv_g = pcall(function()
            return sc_getsockopt(uint64(udp_fd), uint64(0), uint64(opt[1]),
                uint64(optval), uint64(optlen))
        end)
        local ret = ok_g and to_num(rv_g) or -999
        if ret == 0 then
            local len = safe_rd(optlen) or 0
            local val = safe_rd(optval) or 0
            print(string.format("    %2d %-22s len=%d val=%d", opt[1], opt[2], len, val))
        end
    end

    pcall(function() sc_close(uint64(udp_fd)) end)
end
print("")

-- ============================================
-- SECTION G: Summary
-- ============================================
print("=== G: SUMMARY ===")
print("SCTP available: " .. tostring(any_sctp))
print("IPv6 available: " .. tostring(any_v6))
print("Raw protocols working (IPv4): " .. #working_protos)
print("Raw protocols working (IPv6): " .. #working_v6_protos)
print("")
if any_sctp then
    print("*** SCTP OPEN — write SCTP attack probes next ***")
end
if any_v6 then
    print("*** IPv6 OPEN — write IPv6 NDP/fragment probes next ***")
end
if #working_protos > 3 then
    print("*** Multiple raw protocols — each is kernel attack surface ***")
end
print("=== PROBE 48a COMPLETE ===")
