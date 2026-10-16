-- 14.10 Recon Probe 31: setsockopt fuzzing
-- Systematically test socket options with crafted values and edge-case lengths
-- Looking for: integer overflows, buffer overreads, type confusion

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SOCKOPT FUZZ ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_close = 6,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_socketpair = 135,
    sc_bind = 104,
    sc_connect = 98,
    sc_listen = 106,
})

-- Helper: try setsockopt, return rv
local function try_set(fd, level, opt, val_buf, val_len)
    local ok, ret = pcall(function()
        return syscall.sc_setsockopt(fd, level, opt, val_buf, val_len)
    end)
    return ok and ret:tonumber() or -999
end

-- Helper: try getsockopt, return rv + first dword
local function try_get(fd, level, opt, buf_len)
    local buf = memory.alloc(256)
    local lenp = memory.alloc(8)
    for i = 0, 255, 8 do memory.write_qword(buf + i, 0xDEADDEADDEADDEAD) end
    memory.write_qword(lenp, buf_len)
    local ok, ret = pcall(function()
        return syscall.sc_getsockopt(fd, level, opt, buf, lenp)
    end)
    local actual_len = memory.read_qword(lenp):tonumber()
    local d0 = memory.read_dword(buf):tonumber()
    local d1 = memory.read_dword(buf + 4):tonumber()
    return ok and ret:tonumber() or -999, actual_len, d0, d1
end

local val = memory.alloc(4096)

-- ============================================================
-- PART 1: TCP socket options (IPPROTO_TCP = 6)
-- ============================================================
log("")
log("--- PART 1: TCP opts (level=6) ---")

local tcp_ok, tcp_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6) -- AF_INET STREAM TCP
end)
local tcp = tcp_ok and tcp_ret:tonumber() or -1
log("  TCP fd=" .. tcp)

if tcp >= 0 then
    -- TCP options to probe
    local tcp_opts = {
        {1, "TCP_NODELAY"},
        {2, "TCP_MAXSEG"},
        {4, "TCP_NOPUSH"},
        {8, "TCP_NOOPT"},
        {16, "TCP_MD5SIG"},
        {32, "TCP_INFO"},
        {64, "TCP_CONGESTION"},
        {128, "TCP_KEEPINIT"},
        {256, "TCP_KEEPIDLE"},
        {512, "TCP_KEEPINTVL"},
        {1024, "TCP_KEEPCNT"},
        {2048, "TCP_FASTOPEN"},
        {4096, "TCP_FUNCTION_BLK"},
    }

    for _, opt in ipairs(tcp_opts) do
        local rv, len, d0, d1 = try_get(tcp, 6, opt[1], 128)
        if rv == 0 then
            log(string.format("  get %-20s rv=0 len=%d val=0x%08x,%08x",
                opt[2], len, d0, d1))
        else
            log(string.format("  get %-20s rv=%d", opt[2], rv))
        end
    end

    -- Set TCP_NODELAY
    memory.write_dword(val, 1)
    log("  set TCP_NODELAY=1: rv=" .. try_set(tcp, 6, 1, val, 4))

    -- Set TCP_MAXSEG to extreme values
    memory.write_dword(val, 0)
    log("  set TCP_MAXSEG=0: rv=" .. try_set(tcp, 6, 2, val, 4))
    memory.write_dword(val, 1)
    log("  set TCP_MAXSEG=1: rv=" .. try_set(tcp, 6, 2, val, 4))
    memory.write_dword(val, 65535)
    log("  set TCP_MAXSEG=65535: rv=" .. try_set(tcp, 6, 2, val, 4))
    memory.write_dword(val, 0x7FFFFFFF)
    log("  set TCP_MAXSEG=MAX: rv=" .. try_set(tcp, 6, 2, val, 4))

    -- Verify what MAXSEG became
    local rv, len, d0 = try_get(tcp, 6, 2, 4)
    log(string.format("  get TCP_MAXSEG: val=%d", d0))

    -- TCP_KEEPINIT/IDLE/INTVL/CNT with extremes
    for _, kopt in ipairs({{128, "KEEPINIT"}, {256, "KEEPIDLE"}, {512, "KEEPINTVL"}, {1024, "KEEPCNT"}}) do
        memory.write_dword(val, 0x7FFFFFFF)
        local srv = try_set(tcp, 6, kopt[1], val, 4)
        local grv, glen, gd0 = try_get(tcp, 6, kopt[1], 4)
        log(string.format("  set %s=MAX: srv=%d get=%d", kopt[2], srv, gd0))
    end

    -- Edge: setsockopt with length 0
    log("  set NODELAY len=0: rv=" .. try_set(tcp, 6, 1, val, 0))

    -- Edge: setsockopt with length 1 (less than int)
    memory.write_byte(val, 1)
    log("  set NODELAY len=1: rv=" .. try_set(tcp, 6, 1, val, 1))

    -- Edge: setsockopt with huge length
    log("  set NODELAY len=4096: rv=" .. try_set(tcp, 6, 1, val, 4096))

    -- Edge: getsockopt with length 0
    local rv0, len0, d00 = try_get(tcp, 6, 1, 0)
    log(string.format("  get NODELAY len=0: rv=%d actual_len=%d", rv0, len0))

    -- Edge: getsockopt with length 1
    local rv1, len1, d01 = try_get(tcp, 6, 1, 1)
    log(string.format("  get NODELAY len=1: rv=%d actual_len=%d val=0x%08x", rv1, len1, d01))

    -- TCP_INFO with various sizes
    local rv_i, len_i, d0_i, d1_i = try_get(tcp, 6, 32, 256)
    log(string.format("  get TCP_INFO(256): rv=%d len=%d", rv_i, len_i))

    -- TCP_FUNCTION_BLK - string option, 32 bytes
    local rv_f, len_f, d0_f = try_get(tcp, 6, 4096, 64)
    log(string.format("  get TCP_FUNCTION_BLK: rv=%d len=%d", rv_f, len_f))

    pcall(function() syscall.sc_close(tcp) end)
end

-- ============================================================
-- PART 2: IP level options (IPPROTO_IP = 0)
-- ============================================================
log("")
log("--- PART 2: IP opts (level=0) ---")

local udp_ok, udp_ret = pcall(function()
    return syscall.sc_socket(2, 2, 17) -- AF_INET DGRAM UDP
end)
local udp = udp_ok and udp_ret:tonumber() or -1
log("  UDP fd=" .. udp)

if udp >= 0 then
    local ip_opts = {
        {1, "IP_OPTIONS"},
        {2, "IP_HDRINCL"},
        {3, "IP_TOS"},
        {4, "IP_TTL"},
        {5, "IP_RECVOPTS"},
        {6, "IP_RECVRETOPTS"},
        {7, "IP_RECVDSTADDR"},
        {9, "IP_MULTICAST_IF"},
        {10, "IP_MULTICAST_TTL"},
        {11, "IP_MULTICAST_LOOP"},
        {21, "IP_RECVTTL"},
        {22, "IP_MINTTL"},
        {23, "IP_DONTFRAG"},
        {24, "IP_RECVTOS"},
        {26, "IP_FLOWID"},
        {27, "IP_FLOWTYPE"},
        {29, "IP_ORIGDSTADDR"},
    }

    for _, opt in ipairs(ip_opts) do
        local rv, len, d0 = try_get(udp, 0, opt[1], 128)
        if rv == 0 then
            log(string.format("  get %-20s rv=0 len=%d val=%d", opt[2], len, d0))
        else
            log(string.format("  get %-20s rv=%d", opt[2], rv))
        end
    end

    -- IP_TTL edge cases
    memory.write_dword(val, 0)
    log("  set IP_TTL=0: rv=" .. try_set(udp, 0, 4, val, 4))
    memory.write_dword(val, 255)
    log("  set IP_TTL=255: rv=" .. try_set(udp, 0, 4, val, 4))
    memory.write_dword(val, 256)
    log("  set IP_TTL=256: rv=" .. try_set(udp, 0, 4, val, 4))
    memory.write_dword(val, -1)
    log("  set IP_TTL=-1: rv=" .. try_set(udp, 0, 4, val, 4))

    local rv_t, _, d0_t = try_get(udp, 0, 4, 4)
    log("  get IP_TTL: val=" .. d0_t)

    -- IP_MINTTL - interesting for filtering
    memory.write_dword(val, 255)
    log("  set IP_MINTTL=255: rv=" .. try_set(udp, 0, 22, val, 4))

    -- IP_HDRINCL on raw socket
    local raw_ok, raw_ret = pcall(function()
        return syscall.sc_socket(2, 3, 255) -- AF_INET RAW IPPROTO_RAW
    end)
    local raw = raw_ok and raw_ret:tonumber() or -1
    log("  RAW socket: fd=" .. raw)
    if raw >= 0 then
        memory.write_dword(val, 1)
        log("  set IP_HDRINCL=1: rv=" .. try_set(raw, 0, 2, val, 4))
        local rv_h, _, d0_h = try_get(raw, 0, 2, 4)
        log("  get IP_HDRINCL: rv=" .. rv_h .. " val=" .. d0_h)
        pcall(function() syscall.sc_close(raw) end)
    end

    -- IP_OPTIONS with crafted data (up to 40 bytes)
    for i = 0, 39 do memory.write_byte(val + i, 0x44) end -- LSRR-like
    log("  set IP_OPTIONS(40): rv=" .. try_set(udp, 0, 1, val, 40))
    log("  set IP_OPTIONS(44): rv=" .. try_set(udp, 0, 1, val, 44))

    pcall(function() syscall.sc_close(udp) end)
end

-- ============================================================
-- PART 3: IPv6 options (IPPROTO_IPV6 = 41)
-- ============================================================
log("")
log("--- PART 3: IPv6 opts (level=41) ---")

local v6_ok, v6_ret = pcall(function()
    return syscall.sc_socket(28, 2, 17) -- AF_INET6 DGRAM UDP
end)
local v6 = v6_ok and v6_ret:tonumber() or -1
log("  UDPv6 fd=" .. v6)

if v6 >= 0 then
    local v6_opts = {
        {1, "IPV6_UNICAST_HOPS"},
        {8, "IPV6_MULTICAST_HOPS"},
        {18, "IPV6_V6ONLY"},
        {21, "IPV6_RECVPKTINFO"},
        {24, "IPV6_CHECKSUM"},
        {26, "IPV6_FAITH"},
        {27, "IPV6_RECVTCLASS"},
        {29, "IPV6_AUTOFLOWLABEL"},
        {36, "IPV6_RECVRTHDR"},
        {37, "IPV6_RECVDSTOPTS"},
        {42, "IPV6_USE_MIN_MTU"},
        {50, "IPV6_TCLASS"},
        {61, "IPV6_ORIGDSTADDR"},
        {63, "IPV6_PKTINFO"},
        {72, "IPV6_FLOWID"},
        {73, "IPV6_FLOWTYPE"},
    }

    for _, opt in ipairs(v6_opts) do
        local rv, len, d0 = try_get(v6, 41, opt[1], 128)
        if rv == 0 then
            log(string.format("  get %-22s rv=0 len=%d val=%d", opt[2], len, d0))
        else
            log(string.format("  get %-22s rv=%d", opt[2], rv))
        end
    end

    -- IPV6_UNICAST_HOPS edge cases
    memory.write_dword(val, -1)
    log("  set UNICAST_HOPS=-1: rv=" .. try_set(v6, 41, 1, val, 4))
    memory.write_dword(val, 256)
    log("  set UNICAST_HOPS=256: rv=" .. try_set(v6, 41, 1, val, 4))

    -- IPV6_PKTINFO with crafted struct (20 bytes: in6_addr + ifindex)
    for i = 0, 19 do memory.write_byte(val + i, 0) end
    memory.write_dword(val + 16, 1) -- ifindex = 1
    log("  set IPV6_PKTINFO(lo): rv=" .. try_set(v6, 41, 63, val, 20))

    -- IPV6_TCLASS extremes
    memory.write_dword(val, 255)
    log("  set IPV6_TCLASS=255: rv=" .. try_set(v6, 41, 50, val, 4))
    memory.write_dword(val, 256)
    log("  set IPV6_TCLASS=256: rv=" .. try_set(v6, 41, 50, val, 4))

    pcall(function() syscall.sc_close(v6) end)
end

-- ============================================================
-- PART 4: SOL_SOCKET level with edge cases
-- ============================================================
log("")
log("--- PART 4: SOL_SOCKET edge cases ---")

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ea = memory.read_dword(sp):tonumber()
local eb = memory.read_dword(sp + 4):tonumber()

-- SO_RCVBUF / SO_SNDBUF extremes
for _, bopt in ipairs({{0x1001, "SNDBUF"}, {0x1002, "RCVBUF"}}) do
    memory.write_dword(val, 0)
    log("  set " .. bopt[2] .. "=0: rv=" .. try_set(ea, 0xFFFF, bopt[1], val, 4))
    memory.write_dword(val, 1)
    log("  set " .. bopt[2] .. "=1: rv=" .. try_set(ea, 0xFFFF, bopt[1], val, 4))
    memory.write_dword(val, 0x7FFFFFFF)
    log("  set " .. bopt[2] .. "=MAX: rv=" .. try_set(ea, 0xFFFF, bopt[1], val, 4))
    memory.write_dword(val, 0x80000000)
    log("  set " .. bopt[2] .. "=NEG: rv=" .. try_set(ea, 0xFFFF, bopt[1], val, 4))
    local rv, _, d0 = try_get(ea, 0xFFFF, bopt[1], 4)
    log("  get " .. bopt[2] .. ": val=" .. d0)
end

-- SO_LINGER with crafted struct {onoff, linger}
memory.write_dword(val, 1)      -- l_onoff = 1
memory.write_dword(val + 4, 0)  -- l_linger = 0
log("  set LINGER(on,0): rv=" .. try_set(ea, 0xFFFF, 0x0080, val, 8))
memory.write_dword(val + 4, 0x7FFFFFFF)
log("  set LINGER(on,MAX): rv=" .. try_set(ea, 0xFFFF, 0x0080, val, 8))
memory.write_dword(val + 4, -1)
log("  set LINGER(on,-1): rv=" .. try_set(ea, 0xFFFF, 0x0080, val, 8))

-- SO_SNDLOWAT / SO_RCVLOWAT
memory.write_dword(val, 0)
log("  set SNDLOWAT=0: rv=" .. try_set(ea, 0xFFFF, 0x1005, val, 4))
memory.write_dword(val, 0x7FFFFFFF)
log("  set SNDLOWAT=MAX: rv=" .. try_set(ea, 0xFFFF, 0x1005, val, 4))
memory.write_dword(val, 1)
log("  set RCVLOWAT=1: rv=" .. try_set(ea, 0xFFFF, 0x1004, val, 4))
memory.write_dword(val, 0x7FFFFFFF)
log("  set RCVLOWAT=MAX: rv=" .. try_set(ea, 0xFFFF, 0x1004, val, 4))
local rv_l, _, d0_l = try_get(ea, 0xFFFF, 0x1004, 4)
log("  get RCVLOWAT: val=" .. d0_l)

-- SO_SNDTIMEO / SO_RCVTIMEO (struct timeval: 16 bytes on 64-bit)
memory.write_qword(val, 0)      -- tv_sec
memory.write_qword(val + 8, 0)  -- tv_usec
log("  set SNDTIMEO(0,0): rv=" .. try_set(ea, 0xFFFF, 0x1005, val, 16))
memory.write_qword(val, 0x7FFFFFFFFFFFFFFF) -- huge sec
memory.write_qword(val + 8, 999999)
log("  set RCVTIMEO(huge): rv=" .. try_set(ea, 0xFFFF, 0x1006, val, 16))

-- SO_ACCEPTFILTER (struct accept_filter_arg: 16+240=256 bytes)
for i = 0, 255 do memory.write_byte(val + i, 0x41) end
memory.write_byte(val + 15, 0)  -- null-terminate name
log("  set ACCEPTFILTER: rv=" .. try_set(ea, 0xFFFF, 0x1000, val, 256))

-- Undocumented/PS5-specific option numbers
for _, unk in ipairs({0x2000, 0x2001, 0x2002, 0x3000, 0x4000, 0x10000}) do
    local rv, len, d0 = try_get(ea, 0xFFFF, unk, 128)
    if rv == 0 then
        log(string.format("  get SOL 0x%x: rv=0 len=%d val=0x%08x", unk, len, d0))
    end
end

pcall(function() syscall.sc_close(ea) end)
pcall(function() syscall.sc_close(eb) end)

log("")
log("=== SOCKOPT FUZZ DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
