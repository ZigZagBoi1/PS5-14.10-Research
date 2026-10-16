-- 14.10 Recon Probe 34: RAW socket + IP_HDRINCL to localhost
-- Test if we can inject crafted IP packets into kernel's ip_input() path
-- This bypasses the syscall sandbox — kernel parses our packet data directly

print("=== 34: RAW HDRINCL LOCALHOST ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socket = 97,
    sc_socketpair = 135,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_bind = 104,
    sc_connect = 98,
    sc_listen = 106,
    sc_poll = 209,
})

local function send_dw(fd, data_buf, data_len, name_buf, name_len)
    local iov = memory.alloc(16)
    memory.write_qword(iov, data_buf)
    memory.write_qword(iov + 8, data_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    if name_buf and name_len then
        memory.write_qword(mh + 0, name_buf)   -- msg_name
        memory.write_qword(mh + 8, name_len)   -- msg_namelen
    end
    memory.write_qword(mh + 16, iov)   -- msg_iov
    memory.write_qword(mh + 24, 1)     -- msg_iovlen
    local ok, ret = pcall(function()
        return syscall.sc_sendmsg(fd, mh, 0x80) -- MSG_DONTWAIT
    end)
    return ok and ret:tonumber() or -999
end

local function recv_dw(fd, buf, buf_len)
    local iov = memory.alloc(16)
    memory.write_qword(iov, buf)
    memory.write_qword(iov + 8, buf_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function()
        return syscall.sc_recvmsg(fd, mh, 0x80)
    end)
    return ok and ret:tonumber() or -999
end

-- Helper: build sockaddr_in (16 bytes)
local function make_sockaddr_in(ip_a, ip_b, ip_c, ip_d, port)
    local sa = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)       -- sin_len
    memory.write_byte(sa + 1, 2)        -- sin_family = AF_INET
    -- port in network byte order (big endian)
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    -- IP address
    memory.write_byte(sa + 4, ip_a)
    memory.write_byte(sa + 5, ip_b)
    memory.write_byte(sa + 6, ip_c)
    memory.write_byte(sa + 7, ip_d)
    return sa
end

-- ============================================================
-- PART 1: Create RAW socket + IP_HDRINCL
-- ============================================================
print("")
print("--- PART 1: RAW socket creation ---")

-- socket(AF_INET, SOCK_RAW, IPPROTO_RAW=255)
local ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw_fd = ok1 and rv1:tonumber() or -1
print("socket(INET,RAW,255): fd=" .. raw_fd)

if raw_fd < 0 then
    -- Try IPPROTO_TCP(6) raw
    ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 6) end)
    raw_fd = ok1 and rv1:tonumber() or -1
    print("socket(INET,RAW,TCP): fd=" .. raw_fd)
end

if raw_fd < 0 then
    -- Try IPPROTO_UDP(17) raw
    ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 17) end)
    raw_fd = ok1 and rv1:tonumber() or -1
    print("socket(INET,RAW,UDP): fd=" .. raw_fd)
end

if raw_fd < 0 then
    -- Try IPPROTO_ICMP(1) raw
    ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 1) end)
    raw_fd = ok1 and rv1:tonumber() or -1
    print("socket(INET,RAW,ICMP): fd=" .. raw_fd)
end

if raw_fd < 0 then
    -- Try protocol 0
    ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 0) end)
    raw_fd = ok1 and rv1:tonumber() or -1
    print("socket(INET,RAW,0): fd=" .. raw_fd)
end

if raw_fd < 0 then
    print("ALL RAW SOCKETS FAILED - trying scan")
    -- Scan protocols 0-20
    for proto = 0, 20 do
        local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 3, proto) end)
        local fd_s = ok_s and rv_s:tonumber() or -1
        if fd_s >= 0 then
            print("  proto " .. proto .. " -> fd=" .. fd_s)
            if raw_fd < 0 then raw_fd = fd_s
            else pcall(function() syscall.sc_close(fd_s) end) end
        end
    end
end

if raw_fd < 0 then
    print("NO RAW SOCKET AVAILABLE")
    print("=== 34 DONE (no raw) ===")
    return
end

print("using raw_fd=" .. raw_fd)

-- Set IP_HDRINCL
local val = memory.alloc(4)
memory.write_dword(val, 1)
local ok_hi, rv_hi = pcall(function()
    return syscall.sc_setsockopt(raw_fd, 0, 2, val, 4) -- IPPROTO_IP=0, IP_HDRINCL=2
end)
print("IP_HDRINCL set: rv=" .. (ok_hi and rv_hi:tonumber() or -999))

-- Verify
local gval = memory.alloc(4)
local glen = memory.alloc(4)
memory.write_dword(glen, 4)
pcall(function() syscall.sc_getsockopt(raw_fd, 0, 2, gval, glen) end)
print("IP_HDRINCL get: " .. memory.read_dword(gval):tonumber())

-- ============================================================
-- PART 2: Set up TCP listener on localhost:31337
-- ============================================================
print("")
print("--- PART 2: TCP listener ---")

local ok_tcp, rv_tcp = pcall(function() return syscall.sc_socket(2, 1, 6) end)
local tcp_fd = ok_tcp and rv_tcp:tonumber() or -1
print("TCP socket: fd=" .. tcp_fd)

if tcp_fd >= 0 then
    local sa_listen = make_sockaddr_in(127, 0, 0, 1, 31337)
    local ok_b, rv_b = pcall(function() return syscall.sc_bind(tcp_fd, sa_listen, 16) end)
    print("bind(127.0.0.1:31337): rv=" .. (ok_b and rv_b:tonumber() or -999))

    local ok_l, rv_l = pcall(function() return syscall.sc_listen(tcp_fd, 5) end)
    print("listen: rv=" .. (ok_l and rv_l:tonumber() or -999))
end

-- ============================================================
-- PART 3: Craft and send raw IP packet (TCP SYN to 127.0.0.1:31337)
-- ============================================================
print("")
print("--- PART 3: send raw IP packet ---")

-- Build a minimal IP header + TCP SYN
-- IP header: 20 bytes (no options)
-- TCP header: 20 bytes (no options)
-- Total: 40 bytes

local pkt = memory.alloc(64)

-- IP header (20 bytes)
memory.write_byte(pkt + 0, 0x45)    -- version=4, IHL=5 (20 bytes)
memory.write_byte(pkt + 1, 0x00)    -- DSCP/ECN
memory.write_byte(pkt + 2, 0x00)    -- total length high (40)
memory.write_byte(pkt + 3, 40)      -- total length low
memory.write_byte(pkt + 4, 0x00)    -- identification high
memory.write_byte(pkt + 5, 0x01)    -- identification low
memory.write_byte(pkt + 6, 0x40)    -- flags=DF, frag offset=0
memory.write_byte(pkt + 7, 0x00)    -- frag offset low
memory.write_byte(pkt + 8, 64)      -- TTL
memory.write_byte(pkt + 9, 6)       -- protocol=TCP
memory.write_byte(pkt + 10, 0x00)   -- checksum (kernel fills)
memory.write_byte(pkt + 11, 0x00)
-- src IP: 127.0.0.1
memory.write_byte(pkt + 12, 127)
memory.write_byte(pkt + 13, 0)
memory.write_byte(pkt + 14, 0)
memory.write_byte(pkt + 15, 1)
-- dst IP: 127.0.0.1
memory.write_byte(pkt + 16, 127)
memory.write_byte(pkt + 17, 0)
memory.write_byte(pkt + 18, 0)
memory.write_byte(pkt + 19, 1)

-- TCP header (20 bytes) at offset 20
-- src port: 12345
memory.write_byte(pkt + 20, 0x30)   -- 12345 >> 8 = 48
memory.write_byte(pkt + 21, 0x39)   -- 12345 & 0xFF = 57
-- dst port: 31337
memory.write_byte(pkt + 22, 0x7A)   -- 31337 >> 8 = 122
memory.write_byte(pkt + 23, 0x69)   -- 31337 & 0xFF = 105
-- seq number: 0x00000001
memory.write_byte(pkt + 24, 0)
memory.write_byte(pkt + 25, 0)
memory.write_byte(pkt + 26, 0)
memory.write_byte(pkt + 27, 1)
-- ack number: 0
memory.write_byte(pkt + 28, 0)
memory.write_byte(pkt + 29, 0)
memory.write_byte(pkt + 30, 0)
memory.write_byte(pkt + 31, 0)
-- data offset (5<<4=0x50) + flags (SYN=0x02)
memory.write_byte(pkt + 32, 0x50)   -- data offset = 5 (20 bytes), no flags high
memory.write_byte(pkt + 33, 0x02)   -- SYN
-- window size: 65535
memory.write_byte(pkt + 34, 0xFF)
memory.write_byte(pkt + 35, 0xFF)
-- checksum: 0 (we'll see if kernel fills or if it matters)
memory.write_byte(pkt + 36, 0)
memory.write_byte(pkt + 37, 0)
-- urgent pointer: 0
memory.write_byte(pkt + 38, 0)
memory.write_byte(pkt + 39, 0)

-- Destination sockaddr for sendmsg
local sa_dst = make_sockaddr_in(127, 0, 0, 1, 0)

-- Send the crafted packet
local rv_send = send_dw(raw_fd, pkt, 40, sa_dst, 16)
print("sendmsg(raw SYN): rv=" .. rv_send)

-- Try without HDRINCL destination port
local sa_dst2 = make_sockaddr_in(127, 0, 0, 1, 31337)
local rv_send2 = send_dw(raw_fd, pkt, 40, sa_dst2, 16)
print("sendmsg(raw SYN, port): rv=" .. rv_send2)

-- ============================================================
-- PART 4: Check if SYN arrived at listener
-- ============================================================
print("")
print("--- PART 4: check listener ---")

if tcp_fd >= 0 then
    -- Poll the listening socket
    local pollfd = memory.alloc(8)
    memory.write_dword(pollfd, tcp_fd)       -- fd
    memory.write_word(pollfd + 4, 0x0001)    -- POLLIN
    memory.write_word(pollfd + 6, 0)         -- revents

    local ok_p, rv_p = pcall(function() return syscall.sc_poll(pollfd, 1, 100) end)
    local revents = memory.read_word(pollfd + 6):tonumber()
    print("poll(listener, 100ms): rv=" .. (ok_p and rv_p:tonumber() or -999) .. " revents=0x" .. string.format("%04x", revents))

    if revents > 0 then
        print("*** PACKET REACHED LISTENER ***")
    else
        print("no connection (packet may not have arrived)")
    end
end

-- ============================================================
-- PART 5: Try sending raw UDP to see if any raw path works
-- ============================================================
print("")
print("--- PART 5: raw UDP test ---")

-- Create UDP listener on 127.0.0.1:31338
local ok_udp, rv_udp = pcall(function() return syscall.sc_socket(2, 2, 17) end)
local udp_fd = ok_udp and rv_udp:tonumber() or -1
print("UDP socket: fd=" .. udp_fd)

if udp_fd >= 0 then
    local sa_udp = make_sockaddr_in(127, 0, 0, 1, 31338)
    local ok_ub, rv_ub = pcall(function() return syscall.sc_bind(udp_fd, sa_udp, 16) end)
    print("bind(UDP 31338): rv=" .. (ok_ub and rv_ub:tonumber() or -999))

    -- Craft raw IP+UDP packet
    local upkt = memory.alloc(48)
    -- IP header
    memory.write_byte(upkt + 0, 0x45)
    memory.write_byte(upkt + 1, 0x00)
    memory.write_byte(upkt + 2, 0x00)
    memory.write_byte(upkt + 3, 32)     -- total len = 20(IP) + 8(UDP) + 4(data) = 32
    memory.write_byte(upkt + 4, 0x00)
    memory.write_byte(upkt + 5, 0x02)
    memory.write_byte(upkt + 6, 0x40)   -- DF
    memory.write_byte(upkt + 7, 0x00)
    memory.write_byte(upkt + 8, 64)     -- TTL
    memory.write_byte(upkt + 9, 17)     -- protocol=UDP
    memory.write_byte(upkt + 10, 0)
    memory.write_byte(upkt + 11, 0)
    -- src 127.0.0.1
    memory.write_byte(upkt + 12, 127)
    memory.write_byte(upkt + 13, 0)
    memory.write_byte(upkt + 14, 0)
    memory.write_byte(upkt + 15, 1)
    -- dst 127.0.0.1
    memory.write_byte(upkt + 16, 127)
    memory.write_byte(upkt + 17, 0)
    memory.write_byte(upkt + 18, 0)
    memory.write_byte(upkt + 19, 1)

    -- UDP header at offset 20
    -- src port: 12345
    memory.write_byte(upkt + 20, 0x30)
    memory.write_byte(upkt + 21, 0x39)
    -- dst port: 31338
    memory.write_byte(upkt + 22, 0x7A)
    memory.write_byte(upkt + 23, 0x6A)  -- 31338
    -- length: 12 (8 header + 4 data)
    memory.write_byte(upkt + 24, 0x00)
    memory.write_byte(upkt + 25, 0x0C)
    -- checksum: 0
    memory.write_byte(upkt + 26, 0)
    memory.write_byte(upkt + 27, 0)
    -- data: BEEF
    memory.write_byte(upkt + 28, 0xBE)
    memory.write_byte(upkt + 29, 0xEF)
    memory.write_byte(upkt + 30, 0xCA)
    memory.write_byte(upkt + 31, 0xFE)

    local sa_udst = make_sockaddr_in(127, 0, 0, 1, 0)
    local rv_us = send_dw(raw_fd, upkt, 32, sa_udst, 16)
    print("sendmsg(raw UDP): rv=" .. rv_us)

    -- Poll UDP listener
    local pollfd2 = memory.alloc(8)
    memory.write_dword(pollfd2, udp_fd)
    memory.write_word(pollfd2 + 4, 0x0001)
    memory.write_word(pollfd2 + 6, 0)

    local ok_p2, rv_p2 = pcall(function() return syscall.sc_poll(pollfd2, 1, 100) end)
    local rev2 = memory.read_word(pollfd2 + 6):tonumber()
    print("poll(UDP, 100ms): rv=" .. (ok_p2 and rv_p2:tonumber() or -999) .. " revents=0x" .. string.format("%04x", rev2))

    if rev2 > 0 then
        print("*** UDP PACKET REACHED LISTENER ***")
        local rbuf = memory.alloc(64)
        local rrv = recv_dw(udp_fd, rbuf, 64)
        print("recv: rv=" .. rrv)
        if rrv > 0 then
            local hex = ""
            for i = 0, math.min(rrv - 1, 15) do
                hex = hex .. string.format("%02x ", memory.read_byte(rbuf + i):tonumber())
            end
            print("data: " .. hex)
        end
    end

    pcall(function() syscall.sc_close(udp_fd) end)
end

-- ============================================================
-- PART 6: Try raw socket bound to loopback
-- ============================================================
print("")
print("--- PART 6: bound raw socket ---")

local ok_r2, rv_r2 = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw2 = ok_r2 and rv_r2:tonumber() or -1
if raw2 >= 0 then
    memory.write_dword(val, 1)
    pcall(function() syscall.sc_setsockopt(raw2, 0, 2, val, 4) end)

    local sa_lo = make_sockaddr_in(127, 0, 0, 1, 0)
    local ok_rb, rv_rb = pcall(function() return syscall.sc_bind(raw2, sa_lo, 16) end)
    print("bind(raw,lo): rv=" .. (ok_rb and rv_rb:tonumber() or -999))

    -- Connect raw to loopback
    local ok_rc, rv_rc = pcall(function() return syscall.sc_connect(raw2, sa_lo, 16) end)
    print("connect(raw,lo): rv=" .. (ok_rc and rv_rc:tonumber() or -999))

    pcall(function() syscall.sc_close(raw2) end)
else
    print("second raw socket failed")
end

-- Cleanup
pcall(function() syscall.sc_close(raw_fd) end)
if tcp_fd >= 0 then pcall(function() syscall.sc_close(tcp_fd) end) end

print("")
print("=== 34 DONE ===")
