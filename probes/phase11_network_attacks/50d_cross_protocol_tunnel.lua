-- CRASH_CLASS: HIGH
-- PROBE 50d: Cross-Protocol Tunneling Edge Cases
--
-- Context: Probes 50a tested exotic protocol handlers with simple payloads.
-- This probe goes deeper into tunneling protocols — IPv6-in-IPv4 (proto 41),
-- IP-in-IP (proto 4), and GRE (proto 47) — targeting the DECAPSULATION
-- logic specifically. Tunnel decapsulation is historically buggy because:
--
--   1. The inner packet re-enters ip_input() or ip6_input() recursively.
--      Stack depth, mbuf chain corruption, and re-entrant lock bugs hide here.
--   2. Inner/outer header conflicts (different src/dst, TTL underflow after
--      decap, inner packet larger than outer) stress trust boundaries.
--   3. Nested tunneling (tunnel-in-tunnel-in-tunnel) can overflow recursion
--      limits or confuse routing decisions.
--   4. Fragmented tunneled packets force two-phase reassembly (outer frags
--      reassembled, then inner frags) stressing memory allocators.
--
-- FreeBSD tunnel handling:
--   - Proto 4 (IPIP): in_gif_input() → ip_input() re-entry
--   - Proto 41 (6in4): in6_gif_input() → ip6_input() re-entry
--   - Proto 47 (GRE): gre_input() → decap based on protocol field
--
-- The raw socket + IP_HDRINCL + loopback combination lets us construct
-- arbitrary tunnel packets including pathological nesting.

print("=== PROBE 50d: CROSS-PROTOCOL TUNNELING EDGE CASES ===")
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
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local sc_socket = make_syscall(97)
local sc_setsockopt = make_syscall(105)
local sc_sendto = make_syscall(133)
local sc_close = make_syscall(6)

local AF_INET = 2
local SOCK_RAW = 3
local IP_HDRINCL = 2

local function setsockopt_int(fd, level, name, value)
    local buf = memory.alloc(4)
    safe_wd(buf, value)
    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(level), uint64(name),
            uint64(buf), uint64(4))
    end)
    if ok then return to_num(ret) end
    return -999
end

local function close_fd(fd)
    if fd and fd >= 0 then
        pcall(function() sc_close(uint64(fd)) end)
    end
end

-- Create raw socket
local rfd = -1
repeat
    local ok, fd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(255))
    end)
    if not ok or to_num(fd) < 0 then
        print("FATAL: Cannot create raw socket")
        break
    end
    rfd = to_num(fd)
    setsockopt_int(rfd, 0, IP_HDRINCL, 1)
until true

if rfd < 0 then
    print("Cannot proceed without raw socket")
    return
end

local dest = memory.alloc(16)
safe_wb(dest, 16)
safe_wb(dest + 1, AF_INET)
safe_wb(dest + 2, 0)   -- port high
safe_wb(dest + 3, 0)   -- port low
safe_wb(dest + 4, 127) -- 127.0.0.1
safe_wb(dest + 5, 0)
safe_wb(dest + 6, 0)
safe_wb(dest + 7, 1)

local tests = 0
local sent_ok = 0

-- Helper: write IPv4 header at offset in buffer
local function write_ipv4_hdr(buf, off, proto, total_len, ttl, src_a, src_b, src_c, src_d, dst_a, dst_b, dst_c, dst_d)
    ttl = ttl or 64
    safe_wb(buf + off, 0x45)           -- ver=4, ihl=5
    safe_wb(buf + off + 1, 0)         -- tos
    safe_wb(buf + off + 2, math.floor(total_len / 256))
    safe_wb(buf + off + 3, total_len % 256)
    safe_wb(buf + off + 4, 0)         -- id
    safe_wb(buf + off + 5, 0)
    safe_wb(buf + off + 6, 0)         -- flags/frag
    safe_wb(buf + off + 7, 0)
    safe_wb(buf + off + 8, ttl)
    safe_wb(buf + off + 9, proto)
    safe_wb(buf + off + 10, 0)        -- checksum (kernel fills for outer)
    safe_wb(buf + off + 11, 0)
    safe_wb(buf + off + 12, src_a)
    safe_wb(buf + off + 13, src_b)
    safe_wb(buf + off + 14, src_c)
    safe_wb(buf + off + 15, src_d)
    safe_wb(buf + off + 16, dst_a)
    safe_wb(buf + off + 17, dst_b)
    safe_wb(buf + off + 18, dst_c)
    safe_wb(buf + off + 19, dst_d)
end

-- Helper: write IPv6 header at offset
local function write_ipv6_hdr(buf, off, next_hdr, payload_len, hop_limit, src_last, dst_last)
    hop_limit = hop_limit or 64
    src_last = src_last or 1
    dst_last = dst_last or 1
    safe_wb(buf + off, 0x60)           -- version=6, tc high
    safe_wb(buf + off + 1, 0)         -- tc low, flow high
    safe_wb(buf + off + 2, 0)         -- flow
    safe_wb(buf + off + 3, 0)         -- flow low
    safe_wb(buf + off + 4, math.floor(payload_len / 256))
    safe_wb(buf + off + 5, payload_len % 256)
    safe_wb(buf + off + 6, next_hdr)
    safe_wb(buf + off + 7, hop_limit)
    -- src: ::src_last
    for i = 8, 22 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 23, src_last)
    -- dst: ::dst_last
    for i = 24, 38 do safe_wb(buf + off + i, 0) end
    safe_wb(buf + off + 39, dst_last)
end

-- Helper: write GRE header at offset
local function write_gre_hdr(buf, off, proto_type, flags, key, seq)
    flags = flags or 0
    safe_wb(buf + off, math.floor(flags / 256))
    safe_wb(buf + off + 1, flags % 256)
    safe_wb(buf + off + 2, math.floor(proto_type / 256))
    safe_wb(buf + off + 3, proto_type % 256)
    local extra = 4
    if key then
        safe_wb(buf + off + extra, math.floor(key / 16777216) % 256)
        safe_wb(buf + off + extra + 1, math.floor(key / 65536) % 256)
        safe_wb(buf + off + extra + 2, math.floor(key / 256) % 256)
        safe_wb(buf + off + extra + 3, key % 256)
        extra = extra + 4
    end
    if seq then
        safe_wb(buf + off + extra, math.floor(seq / 16777216) % 256)
        safe_wb(buf + off + extra + 1, math.floor(seq / 65536) % 256)
        safe_wb(buf + off + extra + 2, math.floor(seq / 256) % 256)
        safe_wb(buf + off + extra + 3, seq % 256)
        extra = extra + 4
    end
    return extra
end

local function send_pkt(buf, len, desc)
    tests = tests + 1
    local ok, r = pcall(function()
        return sc_sendto(uint64(rfd), uint64(buf), uint64(len),
            uint64(0), uint64(dest), uint64(16))
    end)
    local ret = ok and to_num(r) or -999
    if ret >= 0 then sent_ok = sent_ok + 1 end
    print(string.format("  [%d] %s: ret=%d", tests, desc, ret))
end

print("--- Section A: IPv4-in-IPv4 (Proto 4) Tunneling ---")
print("")

-- A1: Basic IPIP tunnel — outer IPv4 wrapping inner IPv4
repeat
    local pkt = memory.alloc(256)
    -- Outer: proto 4 (IPIP), total_len = 20 outer + 20 inner + 8 payload = 48
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner: UDP proto=17, total_len = 28
    write_ipv4_hdr(pkt, 20, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    -- 8 bytes UDP-ish payload
    for i = 40, 47 do safe_wb(pkt + i, 0xAA) end
    send_pkt(pkt, 48, "IPIP basic")
until true

-- A2: IPIP with TTL=1 on outer (should be decremented to 0 → drop)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 1, 127,0,0,1, 127,0,0,1)
    write_ipv4_hdr(pkt, 20, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 40, 47 do safe_wb(pkt + i, 0xBB) end
    send_pkt(pkt, 48, "IPIP TTL=1 outer")
until true

-- A3: IPIP with TTL=0 on inner
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv4_hdr(pkt, 20, 17, 28, 0, 127,0,0,1, 127,0,0,1)
    for i = 40, 47 do safe_wb(pkt + i, 0xCC) end
    send_pkt(pkt, 48, "IPIP TTL=0 inner")
until true

-- A4: IPIP with mismatched inner total_len (claims 200 bytes, only 8 present)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv4_hdr(pkt, 20, 17, 200, 64, 127,0,0,1, 127,0,0,1)
    for i = 40, 47 do safe_wb(pkt + i, 0xDD) end
    send_pkt(pkt, 48, "IPIP inner len mismatch")
until true

-- A5: IPIP recursive — IPv4-in-IPv4-in-IPv4 (3 deep)
repeat
    local pkt = memory.alloc(256)
    -- Outer: proto 4, wrapping another IPIP
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Middle: proto 4, wrapping inner
    write_ipv4_hdr(pkt, 20, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner: proto 17 (UDP)
    write_ipv4_hdr(pkt, 40, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 60, 67 do safe_wb(pkt + i, 0xEE) end
    send_pkt(pkt, 68, "IPIP 3-deep recursive")
until true

-- A6: IPIP 5-deep recursive
repeat
    local pkt = memory.alloc(256)
    for depth = 0, 3 do
        write_ipv4_hdr(pkt, depth * 20, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    end
    write_ipv4_hdr(pkt, 80, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 100, 107 do safe_wb(pkt + i, 0xFF) end
    send_pkt(pkt, 108, "IPIP 5-deep recursive")
until true

-- A7: IPIP with inner IHL > 5 (IP options in inner packet)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner with IHL=15 (max, 60-byte header, 40 bytes of options)
    safe_wb(pkt + 20, 0x4F)  -- ver=4, ihl=15
    safe_wb(pkt + 21, 0)
    safe_wb(pkt + 22, 0)     -- total_len (kernel fills)
    safe_wb(pkt + 23, 0)
    safe_wb(pkt + 28, 64)    -- ttl
    safe_wb(pkt + 29, 17)    -- proto=UDP
    safe_wb(pkt + 32, 127)   -- src
    safe_wb(pkt + 33, 0)
    safe_wb(pkt + 34, 0)
    safe_wb(pkt + 35, 1)
    safe_wb(pkt + 36, 127)   -- dst
    safe_wb(pkt + 37, 0)
    safe_wb(pkt + 38, 0)
    safe_wb(pkt + 39, 1)
    -- 40 bytes of NOP options (type 1)
    for i = 40, 79 do safe_wb(pkt + i, 1) end
    -- 8 bytes payload
    for i = 80, 87 do safe_wb(pkt + i, 0xAB) end
    send_pkt(pkt, 88, "IPIP inner IHL=15")
until true

-- A8: IPIP with different src/dst in inner vs outer
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner claims to be from 10.0.0.1 to 10.0.0.2 (spoofed)
    write_ipv4_hdr(pkt, 20, 17, 28, 64, 10,0,0,1, 10,0,0,2)
    for i = 40, 47 do safe_wb(pkt + i, 0xCD) end
    send_pkt(pkt, 48, "IPIP spoofed inner addrs")
until true

print("")
print("--- Section B: IPv6-in-IPv4 (Proto 41) Tunneling ---")
print("")

-- B1: Basic 6in4 — outer IPv4 wrapping inner IPv6
repeat
    local pkt = memory.alloc(256)
    -- Outer: proto 41, total = 20 + 40 + 8 = 68
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner IPv6: next=59 (no next), payload=8
    write_ipv6_hdr(pkt, 20, 59, 8, 64, 1, 1)
    for i = 60, 67 do safe_wb(pkt + i, 0x11) end
    send_pkt(pkt, 68, "6in4 basic")
until true

-- B2: 6in4 with hop_limit=0 on inner
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 8, 0, 1, 1)
    for i = 60, 67 do safe_wb(pkt + i, 0x22) end
    send_pkt(pkt, 68, "6in4 hop_limit=0 inner")
until true

-- B3: 6in4 with TTL=1 on outer
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 1, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 8, 64, 1, 1)
    for i = 60, 67 do safe_wb(pkt + i, 0x33) end
    send_pkt(pkt, 68, "6in4 TTL=1 outer")
until true

-- B4: 6in4 with inner payload length mismatch
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 500, 64, 1, 1)  -- claims 500 bytes, only 8
    for i = 60, 67 do safe_wb(pkt + i, 0x44) end
    send_pkt(pkt, 68, "6in4 payload len mismatch")
until true

-- B5: 6in4 with inner fragment header (fragmented IPv6 inside IPv4)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner IPv6 with fragment header
    write_ipv6_hdr(pkt, 20, 44, 16, 64, 1, 1) -- next=44 (Fragment)
    -- Fragment header (8 bytes)
    safe_wb(pkt + 60, 59)   -- next = No Next Header
    safe_wb(pkt + 61, 0)    -- reserved
    safe_wb(pkt + 62, 0)    -- offset=0
    safe_wb(pkt + 63, 0)    -- MF=0 (atomic fragment)
    safe_wd(pkt + 64, 0x12345678) -- identification
    -- 8 bytes payload
    for i = 68, 75 do safe_wb(pkt + i, 0x55) end
    send_pkt(pkt, 76, "6in4 inner frag atomic")
until true

-- B6: 6in4 with inner extension header chain
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- IPv6 → HBH → Routing → Destination → No Next Header
    write_ipv6_hdr(pkt, 20, 0, 32, 64, 1, 1) -- next=0 (HBH)
    -- HBH (8 bytes): next=43 (Routing)
    safe_wb(pkt + 60, 43)    -- next hdr
    safe_wb(pkt + 61, 0)     -- len=0 (8 bytes total)
    for i = 62, 67 do safe_wb(pkt + i, 0) end  -- padding
    -- Routing (8 bytes): next=60 (Destination)
    safe_wb(pkt + 68, 60)    -- next hdr
    safe_wb(pkt + 69, 0)     -- len=0
    safe_wb(pkt + 70, 0)     -- routing type
    safe_wb(pkt + 71, 0)     -- segments left
    for i = 72, 75 do safe_wb(pkt + i, 0) end
    -- Destination (8 bytes): next=59 (No Next)
    safe_wb(pkt + 76, 59)    -- next hdr
    safe_wb(pkt + 77, 0)     -- len=0
    for i = 78, 83 do safe_wb(pkt + i, 0) end
    -- 8 bytes payload
    for i = 84, 91 do safe_wb(pkt + i, 0x66) end
    send_pkt(pkt, 92, "6in4 inner ext hdr chain")
until true

-- B7: 6in4 recursive — IPv6-in-IPv4-in-IPv6-in-IPv4
repeat
    local pkt = memory.alloc(256)
    -- Outer IPv4: proto 41
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner IPv6: next=4 (IPv4 tunneled inside IPv6... unusual)
    write_ipv6_hdr(pkt, 20, 4, 28, 64, 1, 1)
    -- Innermost IPv4: proto 17 (UDP)
    write_ipv4_hdr(pkt, 60, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 80, 87 do safe_wb(pkt + i, 0x77) end
    send_pkt(pkt, 88, "6in4 recursive (IPv4-in-IPv6-in-IPv4)")
until true

-- B8: 6in4 with zero payload length in inner IPv6
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 0, 64, 1, 1) -- payload_len=0
    send_pkt(pkt, 60, "6in4 inner payload_len=0")
until true

-- B9: 6in4 with inner IPv6 version != 6
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 8, 64, 1, 1)
    -- Corrupt version field to 0
    safe_wb(pkt + 20, 0x00)
    for i = 60, 67 do safe_wb(pkt + i, 0x88) end
    send_pkt(pkt, 68, "6in4 inner version=0")
until true

-- B10: 6in4 inner version=15
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    write_ipv6_hdr(pkt, 20, 59, 8, 64, 1, 1)
    safe_wb(pkt + 20, 0xF0)  -- version=15
    for i = 60, 67 do safe_wb(pkt + i, 0x99) end
    send_pkt(pkt, 68, "6in4 inner version=15")
until true

print("")
print("--- Section C: GRE Tunnel Decapsulation ---")
print("")

-- C1: GRE with IPv4 payload (standard tunnel)
repeat
    local pkt = memory.alloc(256)
    -- Outer: proto 47 (GRE)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    -- GRE header: flags=0, protocol=0x0800 (IPv4)
    local gre_len = write_gre_hdr(pkt, 20, 0x0800, 0)
    -- Inner IPv4
    write_ipv4_hdr(pkt, 20 + gre_len, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 20 + gre_len + 20, 20 + gre_len + 27 do safe_wb(pkt + i, 0xA1) end
    send_pkt(pkt, 20 + gre_len + 28, "GRE IPv4 payload")
until true

-- C2: GRE with IPv6 payload (0x86DD)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    local gre_len = write_gre_hdr(pkt, 20, 0x86DD, 0)
    write_ipv6_hdr(pkt, 20 + gre_len, 59, 8, 64, 1, 1)
    for i = 20 + gre_len + 40, 20 + gre_len + 47 do safe_wb(pkt + i, 0xB2) end
    send_pkt(pkt, 20 + gre_len + 48, "GRE IPv6 payload")
until true

-- C3: GRE with key flag set
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Key flag = 0x2000
    local gre_len = write_gre_hdr(pkt, 20, 0x0800, 0x2000, 0xDEADBEEF)
    write_ipv4_hdr(pkt, 20 + gre_len, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 20 + gre_len + 20, 20 + gre_len + 27 do safe_wb(pkt + i, 0xC3) end
    send_pkt(pkt, 20 + gre_len + 28, "GRE key flag + IPv4")
until true

-- C4: GRE with sequence flag
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Seq flag = 0x1000
    local gre_len = write_gre_hdr(pkt, 20, 0x0800, 0x1000, nil, 42)
    write_ipv4_hdr(pkt, 20 + gre_len, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 20 + gre_len + 20, 20 + gre_len + 27 do safe_wb(pkt + i, 0xD4) end
    send_pkt(pkt, 20 + gre_len + 28, "GRE seq flag + IPv4")
until true

-- C5: GRE with key + seq
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Key + Seq = 0x3000
    local gre_len = write_gre_hdr(pkt, 20, 0x0800, 0x3000, 0xCAFEBABE, 100)
    write_ipv4_hdr(pkt, 20 + gre_len, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 20 + gre_len + 20, 20 + gre_len + 27 do safe_wb(pkt + i, 0xE5) end
    send_pkt(pkt, 20 + gre_len + 28, "GRE key+seq + IPv4")
until true

-- C6: GRE recursive — GRE-in-GRE-in-GRE (3 levels)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Level 1 GRE: payload = GRE (proto 47 = 0x002F)
    local off = 20
    local g1 = write_gre_hdr(pkt, off, 0x002F, 0)
    off = off + g1
    -- Level 2 GRE: payload = GRE
    local g2 = write_gre_hdr(pkt, off, 0x002F, 0)
    off = off + g2
    -- Level 3 GRE: payload = IPv4
    local g3 = write_gre_hdr(pkt, off, 0x0800, 0)
    off = off + g3
    -- Inner IPv4
    write_ipv4_hdr(pkt, off, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    off = off + 20
    for i = off, off + 7 do safe_wb(pkt + i, 0xF6) end
    send_pkt(pkt, off + 8, "GRE 3-deep recursive")
until true

-- C7: GRE with unknown/reserved protocol type
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    local gre_len = write_gre_hdr(pkt, 20, 0xFFFF, 0) -- unknown ethertype
    for i = 20 + gre_len, 20 + gre_len + 15 do safe_wb(pkt + i, 0xAB) end
    send_pkt(pkt, 20 + gre_len + 16, "GRE unknown proto 0xFFFF")
until true

-- C8: GRE with protocol=0x0000 (should be dropped or passed to raw)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    local gre_len = write_gre_hdr(pkt, 20, 0x0000, 0)
    for i = 20 + gre_len, 20 + gre_len + 7 do safe_wb(pkt + i, 0xCD) end
    send_pkt(pkt, 20 + gre_len + 8, "GRE proto=0x0000")
until true

-- C9: GRE with Transparent Ethernet Bridging (0x6558)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    local gre_len = write_gre_hdr(pkt, 20, 0x6558, 0)
    -- Fake ethernet frame header (14 bytes)
    for i = 20 + gre_len, 20 + gre_len + 5 do safe_wb(pkt + i, 0xFF) end -- dst MAC broadcast
    for i = 20 + gre_len + 6, 20 + gre_len + 11 do safe_wb(pkt + i, 0x01) end -- src MAC
    safe_wb(pkt + 20 + gre_len + 12, 0x08) -- ethertype = IPv4
    safe_wb(pkt + 20 + gre_len + 13, 0x00)
    -- minimal inner
    for i = 20 + gre_len + 14, 20 + gre_len + 21 do safe_wb(pkt + i, 0xEF) end
    send_pkt(pkt, 20 + gre_len + 22, "GRE TEB (ethernet bridging)")
until true

-- C10: GRE truncated — only 2 bytes of GRE header
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    safe_wb(pkt + 20, 0)
    safe_wb(pkt + 21, 0)
    send_pkt(pkt, 22, "GRE truncated 2B")
until true

print("")
print("--- Section D: Deep Nesting Stress ---")
print("")

-- D1: 10-deep IPIP nesting
repeat
    local pkt = memory.alloc(512)
    local depth = 10
    for d = 0, depth - 2 do
        write_ipv4_hdr(pkt, d * 20, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    end
    -- Innermost: UDP
    local inner_off = (depth - 1) * 20
    write_ipv4_hdr(pkt, inner_off, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = inner_off + 20, inner_off + 27 do safe_wb(pkt + i, 0xD1) end
    send_pkt(pkt, inner_off + 28, "IPIP 10-deep nesting")
until true

-- D2: Alternating 4in4 and 6in4 nesting (4 levels)
repeat
    local pkt = memory.alloc(512)
    -- L1: IPv4 proto=41 (6in4)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- L2: IPv6 next=4 (4in6)
    write_ipv6_hdr(pkt, 20, 4, 68, 64, 1, 1)
    -- L3: IPv4 proto=41 (6in4 again)
    write_ipv4_hdr(pkt, 60, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- L4: IPv6 next=59
    write_ipv6_hdr(pkt, 80, 59, 8, 64, 1, 1)
    for i = 120, 127 do safe_wb(pkt + i, 0xD2) end
    send_pkt(pkt, 128, "Alternating 4in6/6in4 4-deep")
until true

-- D3: GRE wrapping IPIP wrapping 6in4
repeat
    local pkt = memory.alloc(512)
    -- Outer: GRE
    write_ipv4_hdr(pkt, 0, 47, 0, 64, 127,0,0,1, 127,0,0,1)
    local gre_len = write_gre_hdr(pkt, 20, 0x0800, 0)
    local off = 20 + gre_len
    -- IPIP layer
    write_ipv4_hdr(pkt, off, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    off = off + 20
    -- Inner IPIP → 6in4
    write_ipv4_hdr(pkt, off, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    off = off + 20
    -- Innermost IPv6
    write_ipv6_hdr(pkt, off, 59, 8, 64, 1, 1)
    off = off + 40
    for i = off, off + 7 do safe_wb(pkt + i, 0xD3) end
    send_pkt(pkt, off + 8, "GRE->IPIP->6in4 3-protocol nest")
until true

print("")
print("--- Section E: Tunnel + Fragment Interaction ---")
print("")

-- E1: Fragmented outer containing complete tunnel packet
-- (outer IPv4 is fragmented, inner is a complete IPv6 packet)
repeat
    local ok2, rfd2 = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(41))
    end)
    if not ok2 or to_num(rfd2) < 0 then
        print("  [E1] SKIP: raw socket for proto 41 failed")
        break
    end
    rfd2 = to_num(rfd2)
    setsockopt_int(rfd2, 0, IP_HDRINCL, 1)

    -- Build the full packet content: IPv4 + inner IPv6 + payload
    local full_pkt = memory.alloc(256)

    -- Fragment 1: IPv4 header + first 24 bytes of inner content
    -- IP flags: MF=1, offset=0
    write_ipv4_hdr(full_pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    safe_wb(full_pkt + 6, 0x20)  -- MF flag
    safe_wb(full_pkt + 7, 0)     -- offset = 0
    -- First part of IPv6 header
    write_ipv6_hdr(full_pkt, 20, 59, 8, 64, 1, 1)
    -- Only send first 44 bytes of data (header + 24 bytes of IPv6 hdr)
    local ok3, r3 = pcall(function()
        return sc_sendto(uint64(rfd2), uint64(full_pkt), uint64(44),
            uint64(0), uint64(dest), uint64(16))
    end)
    tests = tests + 1
    print(string.format("  [%d] Frag tunnel frag1: ret=%s",
        tests, ok3 and tostring(to_num(r3)) or "err"))
    if ok3 and to_num(r3) >= 0 then sent_ok = sent_ok + 1 end

    -- Fragment 2: remaining bytes, MF=0, offset=24/8=3
    local frag2 = memory.alloc(64)
    write_ipv4_hdr(frag2, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    safe_wb(frag2 + 6, 0x00)  -- MF=0
    safe_wb(frag2 + 7, 3)     -- offset=3 (3*8=24 bytes)
    -- Rest of IPv6 header + payload
    for i = 20, 43 do safe_wb(frag2 + i, 0xE1) end
    local ok4, r4 = pcall(function()
        return sc_sendto(uint64(rfd2), uint64(frag2), uint64(44),
            uint64(0), uint64(dest), uint64(16))
    end)
    tests = tests + 1
    print(string.format("  [%d] Frag tunnel frag2: ret=%s",
        tests, ok4 and tostring(to_num(r4)) or "err"))
    if ok4 and to_num(r4) >= 0 then sent_ok = sent_ok + 1 end

    close_fd(rfd2)
    print("  [E1] SURVIVED")
until true

-- E2: Tunnel packet containing fragmented inner IPv6
repeat
    local pkt = memory.alloc(256)
    -- Outer IPv4 → proto 41
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner IPv6 with fragment header — first fragment, MF=1
    write_ipv6_hdr(pkt, 20, 44, 24, 64, 1, 1) -- next=Fragment
    -- Fragment header
    safe_wb(pkt + 60, 17)   -- next = UDP
    safe_wb(pkt + 61, 0)    -- reserved
    safe_wb(pkt + 62, 0)    -- offset=0
    safe_wb(pkt + 63, 1)    -- MF=1
    safe_wd(pkt + 64, 0xAAAABBBB) -- id
    -- 16 bytes of payload
    for i = 68, 83 do safe_wb(pkt + i, 0xE2) end
    send_pkt(pkt, 84, "Tunnel with inner IPv6 frag (MF=1)")
until true

print("")
print("--- Section F: Edge Case Tunnel Payloads ---")
print("")

-- F1: 6in4 with inner IPv6 jumbogram (payload_len=0, HBH with jumbo option)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- IPv6 with payload_len=0 and HBH
    write_ipv6_hdr(pkt, 20, 0, 0, 64, 1, 1) -- next=HBH, payload=0 (jumbogram)
    -- HBH: jumbo payload option
    safe_wb(pkt + 60, 59)   -- next = No Next
    safe_wb(pkt + 61, 0)    -- len=0 (8 bytes)
    safe_wb(pkt + 62, 0xC2) -- option type 0xC2 = Jumbo Payload
    safe_wb(pkt + 63, 4)    -- option len = 4
    -- Jumbo length = 8 (just our tiny payload)
    safe_wb(pkt + 64, 0)
    safe_wb(pkt + 65, 0)
    safe_wb(pkt + 66, 0)
    safe_wb(pkt + 67, 8)
    -- 8 bytes payload
    for i = 68, 75 do safe_wb(pkt + i, 0xF1) end
    send_pkt(pkt, 76, "6in4 inner jumbogram opt")
until true

-- F2: IPIP with inner IPv4 IHL=0 (invalid)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner: IHL=0, invalid
    safe_wb(pkt + 20, 0x40)  -- ver=4, ihl=0
    for i = 21, 39 do safe_wb(pkt + i, 0) end
    safe_wb(pkt + 28, 64)    -- ttl
    safe_wb(pkt + 29, 17)    -- proto
    safe_wb(pkt + 32, 127)
    safe_wb(pkt + 33, 0)
    safe_wb(pkt + 34, 0)
    safe_wb(pkt + 35, 1)
    safe_wb(pkt + 36, 127)
    safe_wb(pkt + 37, 0)
    safe_wb(pkt + 38, 0)
    safe_wb(pkt + 39, 1)
    for i = 40, 47 do safe_wb(pkt + i, 0xF2) end
    send_pkt(pkt, 48, "IPIP inner IHL=0 invalid")
until true

-- F3: IPIP with inner version=6 (IPv6 disguised as IPv4)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Inner starts with version=6 but in proto 4 (IP-in-IP expects v4)
    write_ipv6_hdr(pkt, 20, 59, 8, 64, 1, 1)
    for i = 60, 67 do safe_wb(pkt + i, 0xF3) end
    send_pkt(pkt, 68, "IPIP inner version=6 mismatch")
until true

-- F4: 6in4 where inner is actually IPv4 (version confusion)
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    -- Proto 41 should contain IPv6, but we put IPv4
    write_ipv4_hdr(pkt, 20, 17, 28, 64, 127,0,0,1, 127,0,0,1)
    for i = 40, 47 do safe_wb(pkt + i, 0xF4) end
    send_pkt(pkt, 48, "6in4 inner is actually IPv4")
until true

-- F5: Empty tunnel — outer only, zero-length inner
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 4, 0, 64, 127,0,0,1, 127,0,0,1)
    send_pkt(pkt, 20, "IPIP empty (no inner)")
until true

-- F6: 6in4 empty
repeat
    local pkt = memory.alloc(256)
    write_ipv4_hdr(pkt, 0, 41, 0, 64, 127,0,0,1, 127,0,0,1)
    send_pkt(pkt, 20, "6in4 empty (no inner)")
until true

print("")
print("=== SUMMARY ===")
print(string.format("Total tests: %d", tests))
print(string.format("Successfully sent: %d", sent_ok))
print(string.format("Failed to send: %d", tests - sent_ok))
print("")
print("Cross-protocol tunneling complete. If you're reading this, no crash occurred.")
print("Sections: A(IPIP:8) B(6in4:10) C(GRE:10) D(deep-nest:3) E(tunnel+frag:2) F(edge:6)")
print("Total: 39+ tunnel variants")

close_fd(rfd)
