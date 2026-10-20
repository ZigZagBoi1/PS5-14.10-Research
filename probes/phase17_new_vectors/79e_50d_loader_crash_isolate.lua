-- CRASH_CLASS: HIGH
-- PROBE 79e: Isolate the persistent loader crash from probe 50d
--
-- Context: Probe 50d (cross-protocol tunneling) uniquely kills the Lua loader
-- ACROSS connections. No other probe does this — it's cross-process kernel state
-- corruption. This probe isolates which section of 50d triggers the persistent crash
-- by running ONE section at a time.
--
-- Usage: Set TEST_SECTION = "A" through "F" (one letter per run).
-- After each run, test if the loader is still accepting connections.
-- The section that kills the loader is the one causing kernel corruption.
--
-- Sections from 50d:
--   A: IPv4-in-IPv4 (Proto 4) — 8 tests
--   B: IPv6-in-IPv4 (Proto 41) — 10 tests
--   C: GRE Tunnel (Proto 47) — 10 tests
--   D: Deep Nesting Stress — 3 tests
--   E: Tunnel + Fragment Interaction — 2 tests
--   F: Edge Case Tunnel Payloads — 6 tests

local TEST_SECTION = "A"

print("=== PROBE 79e: 50d LOADER CRASH ISOLATION ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function wb(addr, val) return pcall(function() memory.write_byte(addr, val) end) end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

local sc_getpid = make_syscall(20)
local sc_socket = make_syscall(97)
local sc_setsockopt = make_syscall(105)
local sc_sendto = make_syscall(133)
local sc_close = make_syscall(6)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid))

-- Raw socket setup
local rfd = -1
repeat
    local ok, fd = pcall(function()
        return sc_socket(uint64(2), uint64(3), uint64(255))
    end)
    if not ok or to_num(fd) < 0 then
        print("[!] Cannot create raw socket")
        return
    end
    rfd = to_num(fd)
    local obuf = memory.alloc(4)
    wd(obuf, 1)
    pcall(function() sc_setsockopt(uint64(rfd), uint64(0), uint64(2), uint64(obuf), uint64(4)) end)
until true

print("[0] raw socket fd=" .. rfd)

-- Loopback destination
local dest = memory.alloc(16)
wb(dest, 16); wb(dest+1, 2); wb(dest+2, 0); wb(dest+3, 0)
wb(dest+4, 127); wb(dest+5, 0); wb(dest+6, 0); wb(dest+7, 1)

local tests = 0
local sent_ok = 0

local function write_ipv4_hdr(buf, off, proto, total_len, ttl)
    ttl = ttl or 64
    wb(buf+off, 0x45); wb(buf+off+1, 0)
    wb(buf+off+2, math.floor(total_len/256)); wb(buf+off+3, total_len%256)
    wb(buf+off+4, 0); wb(buf+off+5, 0)
    wb(buf+off+6, 0x40); wb(buf+off+7, 0) -- DF
    wb(buf+off+8, ttl); wb(buf+off+9, proto)
    wb(buf+off+10, 0); wb(buf+off+11, 0) -- checksum (kernel fills)
    wb(buf+off+12, 127); wb(buf+off+13, 0); wb(buf+off+14, 0); wb(buf+off+15, 1)
    wb(buf+off+16, 127); wb(buf+off+17, 0); wb(buf+off+18, 0); wb(buf+off+19, 1)
end

local function write_ipv6_hdr(buf, off, next_hdr, payload_len, hop_limit)
    hop_limit = hop_limit or 64
    wb(buf+off, 0x60); wb(buf+off+1, 0); wb(buf+off+2, 0); wb(buf+off+3, 0)
    wb(buf+off+4, math.floor(payload_len/256)); wb(buf+off+5, payload_len%256)
    wb(buf+off+6, next_hdr); wb(buf+off+7, hop_limit)
    for i = 8, 23 do wb(buf+off+i, 0) end
    wb(buf+off+23, 1) -- ::1
    for i = 24, 39 do wb(buf+off+i, 0) end
    wb(buf+off+39, 1) -- ::1
end

local function send_pkt(buf, len, desc)
    tests = tests + 1
    local ok, ret = pcall(function()
        return sc_sendto(uint64(rfd), uint64(buf), uint64(len), uint64(0), uint64(dest), uint64(16))
    end)
    local rv = ok and to_num(ret) or -999
    if rv >= 0 then sent_ok = sent_ok + 1 end
    print(string.format("  [%d] %s: ret=%d", tests, desc, rv))
    return rv
end

-- ==============================
-- SECTION A: IPv4-in-IPv4 (Proto 4)
-- ==============================
if TEST_SECTION == "A" then
    print("=== SECTION A: IPv4-in-IPv4 (Proto 4) ===")

    -- A1: Basic IPIP
    local buf = memory.alloc(256)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 48, 64)
    write_ipv4_hdr(buf, 20, 59, 28, 64)
    send_pkt(buf, 48, "A1: Basic IPIP")

    -- A2: TTL=1 on outer
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 48, 1)
    write_ipv4_hdr(buf, 20, 59, 28, 64)
    send_pkt(buf, 48, "A2: IPIP outer TTL=1")

    -- A3: TTL=0 inner
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 48, 64)
    write_ipv4_hdr(buf, 20, 59, 28, 0)
    send_pkt(buf, 48, "A3: IPIP inner TTL=0")

    -- A4: Mismatched inner total_len
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 48, 64)
    write_ipv4_hdr(buf, 20, 59, 200, 64) -- claims 200 bytes, only 28 present
    send_pkt(buf, 48, "A4: IPIP inner len mismatch")

    -- A5: 3-deep recursive IPIP
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 68, 64)
    write_ipv4_hdr(buf, 20, 4, 48, 64)
    write_ipv4_hdr(buf, 40, 59, 28, 64)
    send_pkt(buf, 68, "A5: IPIP 3-deep")

    -- A6: 5-deep recursive
    local buf2 = memory.alloc(256)
    for i=0,255 do wb(buf2+i,0) end
    write_ipv4_hdr(buf2, 0, 4, 108, 64)
    write_ipv4_hdr(buf2, 20, 4, 88, 64)
    write_ipv4_hdr(buf2, 40, 4, 68, 64)
    write_ipv4_hdr(buf2, 60, 4, 48, 64)
    write_ipv4_hdr(buf2, 80, 59, 28, 64)
    send_pkt(buf2, 108, "A6: IPIP 5-deep")

    -- A7: Inner with IP options (IHL > 5)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 56, 64)
    wb(buf+20, 0x46) -- inner ver=4, ihl=6 (24 bytes header)
    wb(buf+21, 0); wb(buf+22, 0); wb(buf+23, 36) -- total=36
    wb(buf+28, 64); wb(buf+29, 59) -- ttl=64, proto=59(none)
    wb(buf+32, 127); wb(buf+33, 0); wb(buf+34, 0); wb(buf+35, 1)
    wb(buf+36, 127); wb(buf+37, 0); wb(buf+38, 0); wb(buf+39, 1)
    wb(buf+40, 0x01); wb(buf+41, 0x04); wb(buf+42, 0); wb(buf+43, 0) -- NOP+EOL options
    send_pkt(buf, 56, "A7: IPIP inner with options")

    -- A8: Different src/dst inner vs outer
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 48, 64)
    write_ipv4_hdr(buf, 20, 59, 28, 64)
    wb(buf+32, 10); wb(buf+33, 0); wb(buf+34, 0); wb(buf+35, 1) -- inner src=10.0.0.1
    wb(buf+36, 10); wb(buf+37, 0); wb(buf+38, 0); wb(buf+39, 2) -- inner dst=10.0.0.2
    send_pkt(buf, 48, "A8: IPIP mismatched addrs")

-- ==============================
-- SECTION B: IPv6-in-IPv4 (Proto 41)
-- ==============================
elseif TEST_SECTION == "B" then
    print("=== SECTION B: IPv6-in-IPv4 (Proto 41) ===")

    local buf = memory.alloc(256)

    -- B1: Basic 6in4
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 8, 64)
    send_pkt(buf, 68, "B1: Basic 6in4")

    -- B2: hop_limit=0
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 8, 0)
    send_pkt(buf, 68, "B2: 6in4 hop=0")

    -- B3: Outer TTL=1
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 1)
    write_ipv6_hdr(buf, 20, 59, 8, 64)
    send_pkt(buf, 68, "B3: 6in4 outer TTL=1")

    -- B4: Payload length mismatch
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 200, 64) -- claims 200 bytes
    send_pkt(buf, 68, "B4: 6in4 payload mismatch")

    -- B5: Inner fragment header
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 76, 64)
    write_ipv6_hdr(buf, 20, 44, 16, 64) -- next=44 (Fragment)
    wb(buf+60, 59); wb(buf+61, 0) -- frag hdr: next=59, reserved
    wb(buf+62, 0); wb(buf+63, 1) -- offset=0, MF=1
    wd(buf+64, 0x12345678) -- frag ID
    send_pkt(buf, 76, "B5: 6in4 inner frag hdr")

    -- B6: Inner with extension header chain (HBH + Routing)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 84, 64)
    write_ipv6_hdr(buf, 20, 0, 24, 64) -- next=0 (HBH)
    wb(buf+60, 43); wb(buf+61, 0) -- HBH: next=43(Routing), len=0
    wb(buf+62, 1); wb(buf+63, 4); wb(buf+64, 0); wb(buf+65, 0); wb(buf+66, 0); wb(buf+67, 0)
    wb(buf+68, 59); wb(buf+69, 0) -- Routing: next=59, len=0
    wb(buf+70, 0); wb(buf+71, 0)
    send_pkt(buf, 84, "B6: 6in4 ext hdr chain")

    -- B7: 6in4 recursive (IPv6-in-IPv4-in-IPv6-in-IPv4)
    local buf2 = memory.alloc(256)
    for i=0,255 do wb(buf2+i,0) end
    write_ipv4_hdr(buf2, 0, 41, 128, 64) -- outer IPv4
    write_ipv6_hdr(buf2, 20, 4, 68, 64)  -- IPv6 with next=4 (IPIP)
    write_ipv4_hdr(buf2, 60, 41, 68, 64) -- inner IPv4
    write_ipv6_hdr(buf2, 80, 59, 8, 64)  -- innermost IPv6
    send_pkt(buf2, 128, "B7: 6in4 recursive 4-layer")

    -- B8: Zero payload length
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 60, 64)
    write_ipv6_hdr(buf, 20, 59, 0, 64)
    send_pkt(buf, 60, "B8: 6in4 zero payload")

    -- B9: Inner version != 6
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 8, 64)
    wb(buf+20, 0x40) -- version=4 but in proto-41 tunnel
    send_pkt(buf, 68, "B9: 6in4 inner version=4")

    -- B10: Inner version=15
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 8, 64)
    wb(buf+20, 0xF0) -- version=15
    send_pkt(buf, 68, "B10: 6in4 inner version=15")

-- ==============================
-- SECTION C: GRE Tunnel
-- ==============================
elseif TEST_SECTION == "C" then
    print("=== SECTION C: GRE Tunnel (Proto 47) ===")

    local buf = memory.alloc(256)

    -- C1: Basic GRE with IPv4 payload
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 52, 64)
    wb(buf+20, 0); wb(buf+21, 0) -- GRE flags=0
    wb(buf+22, 0x08); wb(buf+23, 0x00) -- proto=0x0800 (IPv4)
    write_ipv4_hdr(buf, 24, 59, 28, 64) -- inner IPv4
    send_pkt(buf, 52, "C1: GRE+IPv4")

    -- C2: GRE with IPv6 payload
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 72, 64)
    wb(buf+20, 0); wb(buf+21, 0)
    wb(buf+22, 0x86); wb(buf+23, 0xDD) -- proto=0x86DD (IPv6)
    write_ipv6_hdr(buf, 24, 59, 8, 64) -- inner IPv6
    send_pkt(buf, 72, "C2: GRE+IPv6")

    -- C3: GRE with key flag
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 56, 64)
    wb(buf+20, 0x20); wb(buf+21, 0) -- Key flag set
    wb(buf+22, 0x08); wb(buf+23, 0x00)
    wd(buf+24, 0xDEADBEEF) -- key
    write_ipv4_hdr(buf, 28, 59, 28, 64)
    send_pkt(buf, 56, "C3: GRE+key")

    -- C4: GRE with sequence flag
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 56, 64)
    wb(buf+20, 0x10); wb(buf+21, 0) -- Seq flag
    wb(buf+22, 0x08); wb(buf+23, 0x00)
    wd(buf+24, 1) -- sequence number
    write_ipv4_hdr(buf, 28, 59, 28, 64)
    send_pkt(buf, 56, "C4: GRE+seq")

    -- C5: GRE with key+seq
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 60, 64)
    wb(buf+20, 0x30); wb(buf+21, 0) -- Key+Seq
    wb(buf+22, 0x08); wb(buf+23, 0x00)
    wd(buf+24, 0xCAFEBABE) -- key
    wd(buf+28, 42) -- seq
    write_ipv4_hdr(buf, 32, 59, 28, 64)
    send_pkt(buf, 60, "C5: GRE+key+seq")

    -- C6: GRE recursive 3-deep
    local buf2 = memory.alloc(256)
    for i=0,255 do wb(buf2+i,0) end
    write_ipv4_hdr(buf2, 0, 47, 84, 64)
    wb(buf2+20, 0); wb(buf2+21, 0); wb(buf2+22, 0x08); wb(buf2+23, 0x00)
    write_ipv4_hdr(buf2, 24, 47, 60, 64)
    wb(buf2+44, 0); wb(buf2+45, 0); wb(buf2+46, 0x08); wb(buf2+47, 0x00)
    write_ipv4_hdr(buf2, 48, 47, 36, 64)
    wb(buf2+68, 0); wb(buf2+69, 0); wb(buf2+70, 0x08); wb(buf2+71, 0x00)
    send_pkt(buf2, 84, "C6: GRE 3-deep")

    -- C7: GRE unknown proto
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 32, 64)
    wb(buf+20, 0); wb(buf+21, 0)
    wb(buf+22, 0xFF); wb(buf+23, 0xFF) -- proto=0xFFFF
    wd(buf+24, 0x41414141) -- payload
    send_pkt(buf, 32, "C7: GRE unknown proto")

    -- C8: GRE proto=0
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 32, 64)
    wb(buf+20, 0); wb(buf+21, 0)
    wb(buf+22, 0); wb(buf+23, 0) -- proto=0
    send_pkt(buf, 32, "C8: GRE proto=0")

    -- C9: GRE Transparent Ethernet (0x6558)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 38, 64)
    wb(buf+20, 0); wb(buf+21, 0)
    wb(buf+22, 0x65); wb(buf+23, 0x58) -- TEB
    -- Fake ethernet frame
    for i=24,37 do wb(buf+i, 0xFF) end
    send_pkt(buf, 38, "C9: GRE TEB")

    -- C10: Truncated GRE
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 22, 64) -- only 2 bytes of GRE
    wb(buf+20, 0); wb(buf+21, 0)
    send_pkt(buf, 22, "C10: GRE truncated")

-- ==============================
-- SECTION D: Deep Nesting
-- ==============================
elseif TEST_SECTION == "D" then
    print("=== SECTION D: DEEP NESTING ===")

    -- D1: 10-deep IPIP
    local buf = memory.alloc(256)
    for i=0,255 do wb(buf+i,0) end
    local off = 0
    local total = 20*10 + 8
    for depth = 1, 10 do
        local inner_total = total - off
        write_ipv4_hdr(buf, off, (depth < 10) and 4 or 59, inner_total, 64)
        off = off + 20
    end
    send_pkt(buf, total, "D1: IPIP 10-deep")

    -- D2: Alternating 4in4 / 6in4
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 148, 64)   -- v4, next=6in4
    write_ipv6_hdr(buf, 20, 4, 88, 64)    -- v6, next=IPIP
    write_ipv4_hdr(buf, 60, 41, 88, 64)   -- v4, next=6in4
    write_ipv6_hdr(buf, 80, 59, 8, 64)    -- v6, terminal
    send_pkt(buf, 148, "D2: Alternating 4in4/6in4")

    -- D3: GRE wrapping IPIP wrapping 6in4
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 47, 112, 64) -- outer GRE
    wb(buf+20, 0); wb(buf+21, 0); wb(buf+22, 0x08); wb(buf+23, 0x00)
    write_ipv4_hdr(buf, 24, 4, 88, 64)  -- IPIP
    write_ipv4_hdr(buf, 44, 41, 68, 64) -- 6in4
    write_ipv6_hdr(buf, 64, 59, 8, 64)  -- terminal
    send_pkt(buf, 112, "D3: GRE+IPIP+6in4")

-- ==============================
-- SECTION E: Tunnel + Fragment
-- ==============================
elseif TEST_SECTION == "E" then
    print("=== SECTION E: TUNNEL + FRAGMENT ===")

    -- E1: Fragmented outer containing tunnel
    -- Need separate raw socket for proto 41
    local ok41, fd41 = pcall(function()
        return sc_socket(uint64(2), uint64(3), uint64(41))
    end)
    local rfd41 = ok41 and to_num(fd41) or -1
    if rfd41 >= 0 then
        local obuf = memory.alloc(4); wd(obuf, 1)
        pcall(function() sc_setsockopt(uint64(rfd41), uint64(0), uint64(2), uint64(obuf), uint64(4)) end)

        local buf = memory.alloc(256)
        -- Frag 1: outer IPv4 with MF=1
        for i=0,255 do wb(buf+i,0) end
        write_ipv4_hdr(buf, 0, 41, 40, 64)
        wb(buf+6, 0x20); wb(buf+7, 0) -- MF=1, offset=0
        -- First 20 bytes of inner IPv6
        write_ipv6_hdr(buf, 20, 59, 8, 64) -- only first 20 bytes sent
        send_pkt(buf, 40, "E1a: Frag tunnel frag1 (MF=1)")

        -- Frag 2: continuation
        for i=0,255 do wb(buf+i,0) end
        write_ipv4_hdr(buf, 0, 41, 40, 64)
        wb(buf+6, 0x00); wb(buf+7, 0x03) -- MF=0, offset=24 (3*8)
        -- Rest of inner IPv6 header
        for i=20,39 do wb(buf+i, 0) end
        wb(buf+39, 1) -- ::1 last byte
        send_pkt(buf, 40, "E1b: Frag tunnel frag2")

        pcall(function() sc_close(uint64(rfd41)) end)
    else
        print("[E1] SKIP: no raw socket for proto 41")
    end

    -- E2: Tunnel containing fragmented inner IPv6
    local buf = memory.alloc(256)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 76, 64)
    write_ipv6_hdr(buf, 20, 44, 16, 64) -- frag hdr
    wb(buf+60, 59); wb(buf+61, 0)
    wb(buf+62, 0); wb(buf+63, 1) -- offset=0, MF=1
    wd(buf+64, 0xAABBCCDD)
    send_pkt(buf, 76, "E2: 6in4 with inner frag")

-- ==============================
-- SECTION F: Edge Case Payloads
-- ==============================
elseif TEST_SECTION == "F" then
    print("=== SECTION F: EDGE CASE PAYLOADS ===")

    local buf = memory.alloc(256)

    -- F1: 6in4 with jumbogram (payload_len=0 + HBH jumbo option)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 80, 64)
    write_ipv6_hdr(buf, 20, 0, 0, 64) -- next=HBH, payload=0 (jumbogram)
    wb(buf+60, 59); wb(buf+61, 1) -- HBH: next=59, len=1 (16 bytes)
    wb(buf+62, 0xC2); wb(buf+63, 4) -- jumbo option type=0xC2, len=4
    wd(buf+64, 0x00010000) -- jumbo length: 65536
    for i=68,75 do wb(buf+i, 0) end -- padding
    send_pkt(buf, 80, "F1: 6in4 jumbogram")

    -- F2: IPIP with inner IHL=0
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 40, 64)
    wb(buf+20, 0x40) -- version=4, IHL=0 (INVALID)
    wb(buf+21, 0); wb(buf+22, 0); wb(buf+23, 20)
    wb(buf+28, 64); wb(buf+29, 59)
    wb(buf+32, 127); wb(buf+33, 0); wb(buf+34, 0); wb(buf+35, 1)
    wb(buf+36, 127); wb(buf+37, 0); wb(buf+38, 0); wb(buf+39, 1)
    send_pkt(buf, 40, "F2: IPIP inner IHL=0")

    -- F3: IPIP inner version=6 (version confusion)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 68, 64)
    write_ipv6_hdr(buf, 20, 59, 8, 64) -- IPv6 inside proto-4 tunnel
    send_pkt(buf, 68, "F3: IPIP inner version=6")

    -- F4: 6in4 inner is actually IPv4
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 48, 64)
    write_ipv4_hdr(buf, 20, 59, 28, 64) -- IPv4 inside proto-41 tunnel
    send_pkt(buf, 48, "F4: 6in4 inner is IPv4")

    -- F5: Empty tunnel (zero inner)
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 4, 20, 64)
    send_pkt(buf, 20, "F5: IPIP empty inner")

    -- F6: 6in4 empty
    for i=0,255 do wb(buf+i,0) end
    write_ipv4_hdr(buf, 0, 41, 20, 64)
    send_pkt(buf, 20, "F6: 6in4 empty inner")

else
    print("[!] Unknown TEST_SECTION=" .. TEST_SECTION)
    print("    Use A, B, C, D, E, or F")
end

-- Cleanup
pcall(function() sc_close(uint64(rfd)) end)

local cf_ok, cf_pid = canary()
print("")
print("[final] canary ok=" .. tostring(cf_ok) .. " pid=" .. tostring(cf_pid))
print("sent_ok=" .. sent_ok .. "/" .. tests)
print("")
print("=== PROBE 79e SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("Now check if the loader accepts a new connection.")
print("If it doesn't: THIS SECTION caused the persistent loader corruption!")
print("=== PROBE 79e COMPLETE ===")
