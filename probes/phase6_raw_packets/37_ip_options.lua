-- 14.10 Probe 37: IP options injection via RAW + IP_HDRINCL
-- Target: ip_dooptions() — complex option parsing (RR, TS, LSRR, SSRR) runs
-- in kernel context on packet input, OUTSIDE the syscall sandbox.
-- No fragment reassembly needed. Malformed option lengths included.

print("=== 37: IP OPTIONS INJECTION ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socket = 97,
    sc_bind = 104,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_poll = 209,
})

local MSG_DONTWAIT = 0x80

local function make_sockaddr_in(ip_a, ip_b, ip_c, ip_d, port)
    local sa = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    memory.write_byte(sa + 4, ip_a)
    memory.write_byte(sa + 5, ip_b)
    memory.write_byte(sa + 6, ip_c)
    memory.write_byte(sa + 7, ip_d)
    return sa
end

local function send_dw(fd, data_buf, data_len, name_buf, name_len)
    local iov = memory.alloc(16)
    memory.write_qword(iov, data_buf)
    memory.write_qword(iov + 8, data_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    if name_buf and name_len then
        memory.write_qword(mh + 0, name_buf)
        memory.write_qword(mh + 8, name_len)
    end
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function()
        return syscall.sc_sendmsg(fd, mh, MSG_DONTWAIT)
    end)
    return ok and ret:tonumber() or -999
end

-- ---------------------------------------------------------------
-- Setup: RAW socket with HDRINCL
-- ---------------------------------------------------------------
local ok_r, rv_r = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw_fd = ok_r and rv_r:tonumber() or -1
print("raw socket: fd=" .. raw_fd)
if raw_fd < 0 then
    print("=== 37 DONE (no raw) ===")
    return
end
local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(raw_fd, 0, 2, val, 4) end)

-- ---------------------------------------------------------------
-- Setup: UDP listener — try candidate ports until one binds
-- ---------------------------------------------------------------
local udp_fd = -1
local listen_port = 0
for _, p in ipairs({31338, 31337, 9027, 40000, 50000, 1234}) do
    local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
    local fd = ok_s and rv_s:tonumber() or -1
    if fd >= 0 then
        local sa = make_sockaddr_in(127, 0, 0, 1, p)
        local ok_b, rv_b = pcall(function() return syscall.sc_bind(fd, sa, 16) end)
        if ok_b and rv_b:tonumber() == 0 then
            udp_fd = fd
            listen_port = p
            print("UDP listener bound on 127.0.0.1:" .. p .. " fd=" .. fd)
            break
        end
        pcall(function() syscall.sc_close(fd) end)
    end
end
if udp_fd < 0 then
    print("NO BINDABLE UDP PORT — run probe 36 first")
    print("=== 37 DONE (no listener) ===")
    return
end

-- ---------------------------------------------------------------
-- Packet builder: IP header with options + UDP payload to listener
-- opts: array of bytes (must pad total IP header to 4-byte boundary)
-- Returns packet length sent.
-- ---------------------------------------------------------------
local function ip_checksum(buf, len)
    -- one's complement sum over 16-bit words
    local sum = 0
    local i = 0
    while i + 1 < len do
        sum = sum + memory.read_byte(buf + i):tonumber() * 256
              + memory.read_byte(buf + i + 1):tonumber()
        i = i + 2
    end
    while sum > 0xFFFF do
        sum = math.floor(sum / 65536) + (sum % 65536)
    end
    return 0xFFFF - sum
end

local function send_opt_packet(opts, tag)
    local ihl = 5 + math.floor((#opts + 3) / 4)
    local ip_hlen = ihl * 4
    local udp_len = 8 + 4
    local total = ip_hlen + udp_len
    local pkt = memory.alloc(total + 4)
    for i = 0, total + 3 do memory.write_byte(pkt + i, 0) end

    -- IP header
    memory.write_byte(pkt + 0, 0x40 + ihl)      -- version 4, IHL
    memory.write_byte(pkt + 1, 0x00)
    memory.write_byte(pkt + 2, math.floor(total / 256))
    memory.write_byte(pkt + 3, total % 256)
    memory.write_byte(pkt + 4, 0x00)
    memory.write_byte(pkt + 5, 0x37)            -- id
    memory.write_byte(pkt + 6, 0x40)            -- DF
    memory.write_byte(pkt + 7, 0x00)
    memory.write_byte(pkt + 8, 64)              -- TTL
    memory.write_byte(pkt + 9, 17)              -- UDP
    -- checksum at +10 filled below
    memory.write_byte(pkt + 12, 127)            -- src 127.0.0.1
    memory.write_byte(pkt + 15, 1)
    memory.write_byte(pkt + 16, 127)            -- dst 127.0.0.1
    memory.write_byte(pkt + 19, 1)

    -- options (pad with EOL=0)
    for i, b in ipairs(opts) do
        memory.write_byte(pkt + 20 + i - 1, b)
    end

    -- real IP checksum (do not rely on kernel filling it for opt packets)
    local cks = ip_checksum(pkt, ip_hlen)
    memory.write_byte(pkt + 10, math.floor(cks / 256))
    memory.write_byte(pkt + 11, cks % 256)

    -- UDP header
    local u = pkt + ip_hlen
    memory.write_byte(u + 0, 0x30)              -- src port 12345
    memory.write_byte(u + 1, 0x39)
    memory.write_byte(u + 2, math.floor(listen_port / 256))
    memory.write_byte(u + 3, listen_port % 256)
    memory.write_byte(u + 4, 0x00)              -- length 12
    memory.write_byte(u + 5, 0x0C)
    memory.write_byte(u + 6, 0x00)              -- checksum 0 (legal for IPv4)
    memory.write_byte(u + 7, 0x00)
    memory.write_byte(u + 8, 0xC0)              -- payload marker
    memory.write_byte(u + 9, 0xFF)
    memory.write_byte(u + 10, 0xEE)
    memory.write_byte(u + 11, 0x11)

    local sa_dst = make_sockaddr_in(127, 0, 0, 1, 0)
    local rv = send_dw(raw_fd, pkt, total, sa_dst, 16)

    -- drain listener, report whether datagram arrived
    local pollfd = memory.alloc(8)
    memory.write_dword(pollfd, udp_fd)
    memory.write_word(pollfd + 4, 0x0001)
    memory.write_word(pollfd + 6, 0)
    pcall(function() syscall.sc_poll(pollfd, 1, 150) end)
    local rev = memory.read_word(pollfd + 6):tonumber()
    local delivered = "no"
    if rev > 0 then
        local rbuf = memory.alloc(64)
        local iov = memory.alloc(16)
        memory.write_qword(iov, rbuf)
        memory.write_qword(iov + 8, 64)
        local mh = memory.alloc(64)
        for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
        memory.write_qword(mh + 16, iov)
        memory.write_qword(mh + 24, 1)
        local ok_rr, rv_rr = pcall(function() return syscall.sc_recvmsg(udp_fd, mh, MSG_DONTWAIT) end)
        local n = ok_rr and rv_rr:tonumber() or -999
        delivered = "YES (recv=" .. n .. ")"
    end
    print(string.format("%-28s send rv=%3d  delivered=%s", tag, rv, delivered))
end

-- ---------------------------------------------------------------
-- Option test cases
-- ---------------------------------------------------------------
print("")
print("--- baseline + well-formed options ---")

send_opt_packet({}, "baseline no options")

-- NOP x4
send_opt_packet({1, 1, 1, 1}, "NOP x4")

-- Record Route (7), len 7, ptr 4, one slot
send_opt_packet({7, 7, 4, 0, 0, 0, 0, 1}, "RR len7 empty")

-- RR fully populated: len 39, ptr 40 (past end)
send_opt_packet({7, 39, 40,
    127,0,0,1, 127,0,0,1, 127,0,0,1, 127,0,0,1,
    127,0,0,1, 127,0,0,1, 127,0,0,1, 127,0,0,1,
    127,0,0,1, 1,1,1}, "RR len39 full ptr40")

-- Timestamp (68): len 8, ptr 5, flags 0
send_opt_packet({68, 8, 5, 0, 0, 0, 0, 0}, "TS len8 flags0")

-- TS with overflow flag set (flg=15)
send_opt_packet({68, 8, 5, 0xF0, 0, 0, 0, 0}, "TS overflow-flag")

-- LSRR (131) with 127.0.0.1 hop, ptr 4
send_opt_packet({131, 7, 4, 127, 0, 0, 1, 1}, "LSRR loopback")

-- SSRR (137) with 127.0.0.1 hop
send_opt_packet({137, 7, 4, 127, 0, 0, 1, 1}, "SSRR loopback")

print("")
print("--- malformed options (the interesting ones) ---")

-- Option length 0 (classic parser killer)
send_opt_packet({7, 0, 4, 0, 0, 0, 0, 1}, "RR len=0")

-- Option length exceeds remaining header
send_opt_packet({7, 39, 4, 127, 0, 0, 1, 1}, "RR len39 in 8B space")

-- Truncated option: claims 12 bytes, only 8 present
send_opt_packet({68, 12, 5, 0, 0, 0, 0, 0}, "TS len12 truncated")

-- Pointer beyond option data
send_opt_packet({7, 7, 250, 0, 0, 0, 0, 1}, "RR ptr=250")

-- Max-size option field: 40 bytes of RR
send_opt_packet({7, 39, 4,
    127,0,0,1, 127,0,0,1, 127,0,0,1, 127,0,0,1,
    127,0,0,1, 127,0,0,1, 127,0,0,1, 127,0,0,1,
    127,0,0,1, 1,1,1}, "RR max header")

-- CIPSO-style unknown option (134) — exercises default handling
send_opt_packet({134, 8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, "unknown opt 134")

-- EOL (0) immediately followed by garbage (parser should stop at EOL)
send_opt_packet({0, 7, 39, 250, 0x41, 0x41, 0x41, 0x41}, "EOL then garbage")

print("")
print("NOTE: if the loader/console dies on any case above, the LAST printed")
print("tag before silence is the packet class that killed it — retest it")
print("in isolation. A hang/reboot here = kernel path reached.")
print("=== 37 DONE ===")
