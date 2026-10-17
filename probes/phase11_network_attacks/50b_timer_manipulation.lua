-- CRASH_CLASS: MODERATE
-- PROBE 50b: TCP/UDP Timer Manipulation Attacks
--
-- Context: Basic network fuzz is exhausted (584 variants, zero crashes).
-- The kernel handles malformed packets cleanly. But timer-driven code
-- paths are different — they execute ASYNCHRONOUSLY in softclock/callout
-- context, not in the packet processing path. Timer bugs historically
-- produce use-after-free, double-free, and null-deref crashes because
-- the timer callback fires on a connection/socket that's been partially
-- torn down or modified.
--
-- Attack vectors:
--   A) TCP keepalive timer — set SO_KEEPALIVE + extreme TCP_KEEPIDLE/
--      TCP_KEEPINTVL/TCP_KEEPCNT values, then close/half-close during
--      the keepalive window. Race between timer fire and socket teardown.
--   B) TCP persist timer — create zero-window condition, then close
--      the sending side. Persist timer fires on dead/closing socket.
--   C) TCP retransmit timer — send data on loopback connection with
--      artificially small/large retransmit values.
--   D) SO_RCVTIMEO/SO_SNDTIMEO — extreme timeout values (0, 1us,
--      0x7FFFFFFF) on sockets in various states.
--   E) TCP_FASTOPEN + timer interaction — if supported.
--   F) Linger timer — SO_LINGER with extreme values during close races.
--   G) Connect timeout — non-blocking connect + timer manipulation.
--
-- The key insight: timer code paths are harder to audit than packet
-- parsing because they depend on temporal state. A socket that's valid
-- when the timer is armed may be partially freed when it fires.
--
-- FreeBSD kernel timer implementation uses callout(9) framework.
-- tcp_timer.c handles: TCPT_REXMT, TCPT_PERSIST, TCPT_KEEP, TCPT_2MSL.
-- Each has a separate callout that can fire independently.

print("=== PROBE 50b: TCP/UDP TIMER MANIPULATION ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Syscall setup
local sc_socket = make_syscall(97)
local sc_bind = make_syscall(104)
local sc_listen = make_syscall(106)
local sc_accept = make_syscall(30)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_write = make_syscall(4)
local sc_read = make_syscall(3)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_shutdown = make_syscall(134)
local sc_fcntl = make_syscall(92)
local sc_select = make_syscall(93)
local sc_getsockname = make_syscall(32)
local sc_nanosleep = make_syscall(240)

-- Constants
local AF_INET = 2
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local IPPROTO_TCP = 6
local SOL_SOCKET = 0xFFFF
local IPPROTO_IP = 0

local SO_KEEPALIVE = 0x0008
local SO_RCVTIMEO = 0x1006
local SO_SNDTIMEO = 0x1005
local SO_LINGER = 0x0080
local SO_REUSEADDR = 0x0004
local SO_RCVBUF = 0x1002
local SO_SNDBUF = 0x1001

-- TCP options (FreeBSD)
local TCP_NODELAY = 1
local TCP_KEEPIDLE = 256   -- 0x100
local TCP_KEEPINTVL = 512  -- 0x200
local TCP_KEEPCNT = 1024   -- 0x400
local TCP_MAXSEG = 2

local F_SETFL = 4
local O_NONBLOCK = 4

local errors = 0
local tests = 0

-- Helper: create sockaddr_in
local function make_sockaddr(port, ip_a, ip_b, ip_c, ip_d)
    local sa = memory.alloc(16)
    safe_wb(sa, 16)           -- sin_len
    safe_wb(sa + 1, AF_INET)  -- sin_family
    safe_wb(sa + 2, math.floor(port / 256))  -- sin_port high
    safe_wb(sa + 3, port % 256)              -- sin_port low
    safe_wb(sa + 4, ip_a)     -- sin_addr
    safe_wb(sa + 5, ip_b)
    safe_wb(sa + 6, ip_c)
    safe_wb(sa + 7, ip_d)
    return sa
end

-- Helper: set int sockopt
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

-- Helper: set timeval sockopt
local function setsockopt_timeval(fd, level, name, sec, usec)
    local buf = memory.alloc(16)
    safe_wq(buf, uint64(sec))       -- tv_sec (8 bytes on 64-bit)
    safe_wq(buf + 8, uint64(usec))  -- tv_usec
    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(level), uint64(name),
            uint64(buf), uint64(16))
    end)
    if ok then return to_num(ret) end
    return -999
end

-- Helper: create connected TCP pair on loopback
local base_port = 20100

local function make_tcp_pair(port_offset)
    local port = base_port + (port_offset or 0)

    -- Server socket
    local ok, srv = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    if not ok then return nil, nil, nil end
    srv = to_num(srv)
    if srv < 0 then return nil, nil, nil end

    setsockopt_int(srv, SOL_SOCKET, SO_REUSEADDR, 1)

    local sa = make_sockaddr(port, 127, 0, 0, 1)
    local ok2, bret = pcall(function()
        return sc_bind(uint64(srv), uint64(sa), uint64(16))
    end)
    if not ok2 or to_num(bret) ~= 0 then
        pcall(function() sc_close(uint64(srv)) end)
        return nil, nil, nil
    end

    pcall(function() sc_listen(uint64(srv), uint64(5)) end)

    -- Client socket
    local ok3, cli = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    if not ok3 then
        pcall(function() sc_close(uint64(srv)) end)
        return nil, nil, nil
    end
    cli = to_num(cli)

    -- Connect
    local ok4, cret = pcall(function()
        return sc_connect(uint64(cli), uint64(sa), uint64(16))
    end)
    if not ok4 or to_num(cret) ~= 0 then
        pcall(function() sc_close(uint64(cli)) end)
        pcall(function() sc_close(uint64(srv)) end)
        return nil, nil, nil
    end

    -- Accept
    local ok5, acc = pcall(function()
        return sc_accept(uint64(srv), uint64(0), uint64(0))
    end)
    if not ok5 then
        pcall(function() sc_close(uint64(cli)) end)
        pcall(function() sc_close(uint64(srv)) end)
        return nil, nil, nil
    end
    acc = to_num(acc)

    return srv, cli, acc
end

-- Helper: close fd safely
local function close_fd(fd)
    if fd and fd >= 0 then
        pcall(function() sc_close(uint64(fd)) end)
    end
end

-- Helper: brief sleep (milliseconds via nanosleep)
local function msleep(ms)
    local sleepbuf = memory.alloc(16)
    safe_wq(sleepbuf, uint64(0))                    -- seconds
    safe_wq(sleepbuf + 8, uint64(ms * 1000000))     -- nanoseconds
    pcall(function() sc_nanosleep(uint64(sleepbuf), uint64(0)) end)
end

print("--- Section A: TCP Keepalive Timer Abuse ---")
print("")

-- A1: Keepalive with minimum idle time
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(0)
    if not srv then
        print("  [A1] SKIP: pair creation failed")
        errors = errors + 1
        break
    end

    -- Enable keepalive on client
    local r1 = setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    print(string.format("  [A1] SO_KEEPALIVE=1: ret=%d", r1))

    -- Set minimum keepalive idle = 1 second
    local r2 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
    print(string.format("  [A1] TCP_KEEPIDLE=1: ret=%d", r2))

    -- Keepalive interval = 1 second
    local r3 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 1)
    print(string.format("  [A1] TCP_KEEPINTVL=1: ret=%d", r3))

    -- Keepalive count = 1 (drop fast)
    local r4 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPCNT, 1)
    print(string.format("  [A1] TCP_KEEPCNT=1: ret=%d", r4))

    -- Sleep to let keepalive fire
    msleep(200)

    -- Close accepted side first — timer should fire on client with peer gone
    close_fd(acc)
    msleep(500)

    -- Try write on client — should fail or trigger timer path
    local wbuf = memory.alloc(64)
    safe_wd(wbuf, 0x41424344)
    local ok, wret = pcall(function()
        return sc_write(uint64(cli), uint64(wbuf), uint64(16))
    end)
    print(string.format("  [A1] Write after peer close: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(wret)) or "crash"))

    close_fd(cli)
    close_fd(srv)
    print("  [A1] SURVIVED")
until true

-- A2: Keepalive with idle=0 (minimum/error case)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(1)
    if not srv then
        print("  [A2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    local r = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 0)
    print(string.format("  [A2] TCP_KEEPIDLE=0: ret=%d", r))

    local r2 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 0)
    print(string.format("  [A2] TCP_KEEPINTVL=0: ret=%d", r2))

    msleep(200)
    close_fd(acc)
    close_fd(cli)
    close_fd(srv)
    print("  [A2] SURVIVED")
until true

-- A3: Keepalive with maximum values
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(2)
    if not srv then
        print("  [A3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    local r1 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 0x7FFFFFFF)
    local r2 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 0x7FFFFFFF)
    local r3 = setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPCNT, 0x7FFFFFFF)
    print(string.format("  [A3] MAX keepalive: idle=%d intvl=%d cnt=%d", r1, r2, r3))

    close_fd(acc)
    close_fd(cli)
    close_fd(srv)
    print("  [A3] SURVIVED")
until true

-- A4: Enable/disable keepalive rapidly while connection active
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(3)
    if not srv then
        print("  [A4] SKIP: pair failed")
        errors = errors + 1
        break
    end

    for i = 1, 50 do
        setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
        setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
        setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 0)
    end
    print("  [A4] 50x keepalive toggle: done")

    close_fd(acc)
    close_fd(cli)
    close_fd(srv)
    print("  [A4] SURVIVED")
until true

-- A5: Keepalive + shutdown(SHUT_WR) — half-close with timer active
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(4)
    if not srv then
        print("  [A5] SKIP: pair failed")
        errors = errors + 1
        break
    end

    setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPCNT, 1)

    -- Half-close: send FIN but keep receiving
    pcall(function() sc_shutdown(uint64(cli), uint64(1)) end) -- SHUT_WR

    msleep(500)

    -- Timer fires on half-closed socket
    local rbuf = memory.alloc(64)
    local ok, rret = pcall(function()
        return sc_read(uint64(cli), uint64(rbuf), uint64(64))
    end)
    print(string.format("  [A5] Read after SHUT_WR + keepalive: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(rret)) or "crash"))

    close_fd(acc)
    close_fd(cli)
    close_fd(srv)
    print("  [A5] SURVIVED")
until true

-- A6: Keepalive on both sides of connection simultaneously
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(5)
    if not srv then
        print("  [A6] SKIP: pair failed")
        errors = errors + 1
        break
    end

    -- Both sides keepalive with aggressive timers
    setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 1)

    setsockopt_int(acc, SOL_SOCKET, SO_KEEPALIVE, 1)
    setsockopt_int(acc, IPPROTO_TCP, TCP_KEEPIDLE, 1)
    setsockopt_int(acc, IPPROTO_TCP, TCP_KEEPINTVL, 1)

    msleep(500)

    -- Close both rapidly
    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [A6] SURVIVED")
until true

print("")
print("--- Section B: SO_LINGER Timer Abuse ---")
print("")

-- B1: Linger with l_linger=0 (RST on close, no TIME_WAIT)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(10)
    if not srv then
        print("  [B1] SKIP: pair failed")
        errors = errors + 1
        break
    end

    -- Set linger: on, timeout=0 → RST on close
    local lbuf = memory.alloc(8)
    safe_wd(lbuf, 1)       -- l_onoff = 1
    safe_wd(lbuf + 4, 0)   -- l_linger = 0
    local ok, r = pcall(function()
        return sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
            uint64(lbuf), uint64(8))
    end)
    print(string.format("  [B1] SO_LINGER(on,0): ret=%s",
        ok and tostring(to_num(r)) or "err"))

    -- Write some data, then close → should RST immediately
    local wbuf = memory.alloc(256)
    pcall(function() sc_write(uint64(cli), uint64(wbuf), uint64(256)) end)
    close_fd(cli)
    msleep(100)

    close_fd(acc)
    close_fd(srv)
    print("  [B1] SURVIVED")
until true

-- B2: Linger with maximum timeout
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(11)
    if not srv then
        print("  [B2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local lbuf = memory.alloc(8)
    safe_wd(lbuf, 1)             -- l_onoff = 1
    safe_wd(lbuf + 4, 0x7FFF)   -- l_linger = 32767 seconds
    local ok, r = pcall(function()
        return sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
            uint64(lbuf), uint64(8))
    end)
    print(string.format("  [B2] SO_LINGER(on,32767): ret=%s",
        ok and tostring(to_num(r)) or "err"))

    -- Write data and close — linger timer should fire but we move on
    local wbuf = memory.alloc(64)
    pcall(function() sc_write(uint64(cli), uint64(wbuf), uint64(64)) end)

    -- Non-blocking close to avoid blocking on linger
    pcall(function() sc_fcntl(uint64(cli), uint64(F_SETFL), uint64(O_NONBLOCK)) end)
    close_fd(cli)
    msleep(100)

    close_fd(acc)
    close_fd(srv)
    print("  [B2] SURVIVED")
until true

-- B3: Linger with l_linger=negative via unsigned overflow
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(12)
    if not srv then
        print("  [B3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local lbuf = memory.alloc(8)
    safe_wd(lbuf, 1)                 -- l_onoff = 1
    safe_wd(lbuf + 4, 0xFFFFFFFF)   -- l_linger = -1 as unsigned
    local ok, r = pcall(function()
        return sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
            uint64(lbuf), uint64(8))
    end)
    print(string.format("  [B3] SO_LINGER(on,-1): ret=%s",
        ok and tostring(to_num(r)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [B3] SURVIVED")
until true

-- B4: Rapid linger toggle while writing
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(13)
    if not srv then
        print("  [B4] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local lbuf_on = memory.alloc(8)
    safe_wd(lbuf_on, 1)
    safe_wd(lbuf_on + 4, 5)

    local lbuf_off = memory.alloc(8)
    safe_wd(lbuf_off, 0)
    safe_wd(lbuf_off + 4, 0)

    local wbuf = memory.alloc(64)
    for i = 1, 30 do
        pcall(function()
            sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
                uint64(lbuf_on), uint64(8))
        end)
        pcall(function() sc_write(uint64(cli), uint64(wbuf), uint64(32)) end)
        pcall(function()
            sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
                uint64(lbuf_off), uint64(8))
        end)
    end
    print("  [B4] 30x linger toggle+write: done")

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [B4] SURVIVED")
until true

print("")
print("--- Section C: SO_RCVTIMEO/SO_SNDTIMEO Extremes ---")
print("")

-- C1: Zero receive timeout
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(20)
    if not srv then
        print("  [C1] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 0, 0)
    print(string.format("  [C1] SO_RCVTIMEO(0,0): ret=%d", r))

    local rbuf = memory.alloc(64)
    local ok, rr = pcall(function()
        return sc_read(uint64(cli), uint64(rbuf), uint64(64))
    end)
    print(string.format("  [C1] Read with zero timeout: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(rr)) or "crash"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [C1] SURVIVED")
until true

-- C2: 1 microsecond timeout
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(21)
    if not srv then
        print("  [C2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 0, 1)
    print(string.format("  [C2] SO_RCVTIMEO(0,1us): ret=%d", r))

    local rbuf = memory.alloc(64)
    local ok, rr = pcall(function()
        return sc_read(uint64(cli), uint64(rbuf), uint64(64))
    end)
    print(string.format("  [C2] Read with 1us timeout: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(rr)) or "crash"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [C2] SURVIVED")
until true

-- C3: Maximum timeout value
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(22)
    if not srv then
        print("  [C3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 0x7FFFFFFF, 999999)
    print(string.format("  [C3] SO_RCVTIMEO(MAX,999999): ret=%d", r))

    -- Also set send timeout to max
    local r2 = setsockopt_timeval(cli, SOL_SOCKET, SO_SNDTIMEO, 0x7FFFFFFF, 999999)
    print(string.format("  [C3] SO_SNDTIMEO(MAX,999999): ret=%d", r2))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [C3] SURVIVED")
until true

-- C4: Negative-ish timeval (huge unsigned)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(23)
    if not srv then
        print("  [C4] SKIP: pair failed")
        errors = errors + 1
        break
    end

    -- tv_sec as large negative (unsigned 64-bit wrap)
    local buf = memory.alloc(16)
    safe_wq(buf, uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
    safe_wq(buf + 8, uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
    local ok, r = pcall(function()
        return sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_RCVTIMEO),
            uint64(buf), uint64(16))
    end)
    print(string.format("  [C4] SO_RCVTIMEO(-1,-1): ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(r)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [C4] SURVIVED")
until true

-- C5: Invalid usec value (>= 1000000)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(24)
    if not srv then
        print("  [C5] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r1 = setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 1, 1000000)
    local r2 = setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 1, 9999999)
    local r3 = setsockopt_timeval(cli, SOL_SOCKET, SO_SNDTIMEO, 0, 2000000)
    print(string.format("  [C5] Invalid usec: 1M=%d 10M=%d 2M=%d", r1, r2, r3))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [C5] SURVIVED")
until true

print("")
print("--- Section D: TCP Buffer Size Manipulation ---")
print("")

-- D1: Minimum buffer sizes
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(30)
    if not srv then
        print("  [D1] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r1 = setsockopt_int(cli, SOL_SOCKET, SO_RCVBUF, 1)
    local r2 = setsockopt_int(cli, SOL_SOCKET, SO_SNDBUF, 1)
    print(string.format("  [D1] Buffers=1: rcv=%d snd=%d", r1, r2))

    -- Write data into tiny buffer
    local wbuf = memory.alloc(4096)
    local ok, wr = pcall(function()
        return sc_write(uint64(cli), uint64(wbuf), uint64(4096))
    end)
    print(string.format("  [D1] Write 4K into tiny buf: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(wr)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [D1] SURVIVED")
until true

-- D2: Maximum buffer sizes
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(31)
    if not srv then
        print("  [D2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r1 = setsockopt_int(cli, SOL_SOCKET, SO_RCVBUF, 0x7FFFFFFF)
    local r2 = setsockopt_int(cli, SOL_SOCKET, SO_SNDBUF, 0x7FFFFFFF)
    print(string.format("  [D2] Buffers=MAX: rcv=%d snd=%d", r1, r2))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [D2] SURVIVED")
until true

-- D3: Zero buffer size
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(32)
    if not srv then
        print("  [D3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r1 = setsockopt_int(cli, SOL_SOCKET, SO_RCVBUF, 0)
    local r2 = setsockopt_int(cli, SOL_SOCKET, SO_SNDBUF, 0)
    print(string.format("  [D3] Buffers=0: rcv=%d snd=%d", r1, r2))

    -- Write to zero-buffer socket
    local wbuf = memory.alloc(64)
    local ok, wr = pcall(function()
        return sc_write(uint64(cli), uint64(wbuf), uint64(64))
    end)
    print(string.format("  [D3] Write to zero-buf: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(wr)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [D3] SURVIVED")
until true

-- D4: Resize buffers while data in flight
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(33)
    if not srv then
        print("  [D4] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local wbuf = memory.alloc(1024)
    for i = 1, 20 do
        pcall(function() sc_write(uint64(cli), uint64(wbuf), uint64(1024)) end)
        setsockopt_int(cli, SOL_SOCKET, SO_SNDBUF, i * 256)
        setsockopt_int(cli, SOL_SOCKET, SO_RCVBUF, i * 256)
    end
    print("  [D4] 20x write+resize: done")

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [D4] SURVIVED")
until true

print("")
print("--- Section E: Shutdown + Timer Races ---")
print("")

-- E1: SHUT_RD then write
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(40)
    if not srv then
        print("  [E1] SKIP: pair failed")
        errors = errors + 1
        break
    end

    pcall(function() sc_shutdown(uint64(cli), uint64(0)) end) -- SHUT_RD
    local wbuf = memory.alloc(64)
    local ok, wr = pcall(function()
        return sc_write(uint64(cli), uint64(wbuf), uint64(64))
    end)
    print(string.format("  [E1] Write after SHUT_RD: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(wr)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [E1] SURVIVED")
until true

-- E2: SHUT_WR then read (peer still has data)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(41)
    if not srv then
        print("  [E2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    -- Write from accepted side before half-close
    local wbuf = memory.alloc(64)
    safe_wd(wbuf, 0x41424344)
    pcall(function() sc_write(uint64(acc), uint64(wbuf), uint64(64)) end)

    pcall(function() sc_shutdown(uint64(cli), uint64(1)) end) -- SHUT_WR

    -- Read on half-closed socket — peer's data should still arrive
    local rbuf = memory.alloc(64)
    local ok, rr = pcall(function()
        return sc_read(uint64(cli), uint64(rbuf), uint64(64))
    end)
    print(string.format("  [E2] Read after SHUT_WR: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(rr)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [E2] SURVIVED")
until true

-- E3: Double shutdown
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(42)
    if not srv then
        print("  [E3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    pcall(function() sc_shutdown(uint64(cli), uint64(2)) end) -- SHUT_RDWR
    local ok, r = pcall(function()
        return sc_shutdown(uint64(cli), uint64(2))
    end) -- Again
    print(string.format("  [E3] Double SHUT_RDWR: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(r)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [E3] SURVIVED")
until true

-- E4: Shutdown + keepalive + linger race
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(43)
    if not srv then
        print("  [E4] SKIP: pair failed")
        errors = errors + 1
        break
    end

    -- All timers armed
    setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 1)
    setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPCNT, 1)

    local lbuf = memory.alloc(8)
    safe_wd(lbuf, 1)
    safe_wd(lbuf + 4, 1) -- 1 second linger
    pcall(function()
        sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
            uint64(lbuf), uint64(8))
    end)

    setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 0, 1)
    setsockopt_timeval(cli, SOL_SOCKET, SO_SNDTIMEO, 0, 1)

    -- Write data, then shutdown, then close — multiple timers racing
    local wbuf = memory.alloc(256)
    pcall(function() sc_write(uint64(cli), uint64(wbuf), uint64(256)) end)
    pcall(function() sc_shutdown(uint64(cli), uint64(1)) end)
    msleep(100)
    pcall(function() sc_shutdown(uint64(acc), uint64(2)) end)
    close_fd(cli)
    msleep(200)

    close_fd(acc)
    close_fd(srv)
    print("  [E4] SURVIVED")
until true

-- E5: Rapid open/configure/close cycle — timer arm/disarm race
repeat
    tests = tests + 1
    local close_count = 0
    for i = 1, 20 do
        local srv, cli, acc = make_tcp_pair(50 + i)
        if srv then
            setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
            setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
            local lbuf = memory.alloc(8)
            safe_wd(lbuf, 1)
            safe_wd(lbuf + 4, 0)
            pcall(function()
                sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
                    uint64(lbuf), uint64(8))
            end)
            -- Close immediately without sleep — timer armed but socket dying
            close_fd(cli)
            close_fd(acc)
            close_fd(srv)
            close_count = close_count + 1
        end
    end
    print(string.format("  [E5] 20x rapid open/arm/close: %d succeeded", close_count))
    print("  [E5] SURVIVED")
until true

print("")
print("--- Section F: UDP Timer/Timeout Abuse ---")
print("")

-- F1: UDP with extreme timeouts
repeat
    tests = tests + 1
    local ok1, ufd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
    end)
    if not ok1 or to_num(ufd) < 0 then
        print("  [F1] SKIP: UDP socket failed")
        errors = errors + 1
        break
    end
    ufd = to_num(ufd)

    local r1 = setsockopt_timeval(ufd, SOL_SOCKET, SO_RCVTIMEO, 0, 1)
    local r2 = setsockopt_timeval(ufd, SOL_SOCKET, SO_SNDTIMEO, 0, 1)
    print(string.format("  [F1] UDP timeouts 1us: rcv=%d snd=%d", r1, r2))

    local sa = make_sockaddr(20200, 127, 0, 0, 1)
    pcall(function() sc_bind(uint64(ufd), uint64(sa), uint64(16)) end)

    -- Non-blocking read with 1us timeout
    local rbuf = memory.alloc(64)
    local ok, rr = pcall(function()
        return sc_read(uint64(ufd), uint64(rbuf), uint64(64))
    end)
    print(string.format("  [F1] UDP read 1us timeout: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(rr)) or "err"))

    close_fd(ufd)
    print("  [F1] SURVIVED")
until true

-- F2: UDP connect + disconnect cycle
repeat
    tests = tests + 1
    local ok1, ufd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
    end)
    if not ok1 or to_num(ufd) < 0 then
        print("  [F2] SKIP")
        errors = errors + 1
        break
    end
    ufd = to_num(ufd)

    local sa = make_sockaddr(20201, 127, 0, 0, 1)
    for i = 1, 30 do
        -- Connect UDP (sets destination)
        pcall(function() sc_connect(uint64(ufd), uint64(sa), uint64(16)) end)
        -- "Disconnect" by connecting to AF_UNSPEC
        local unspec = memory.alloc(16)
        safe_wb(unspec, 16)
        safe_wb(unspec + 1, 0) -- AF_UNSPEC
        pcall(function() sc_connect(uint64(ufd), uint64(unspec), uint64(16)) end)
    end
    print("  [F2] 30x UDP connect/disconnect: done")

    close_fd(ufd)
    print("  [F2] SURVIVED")
until true

print("")
print("--- Section G: Multiple Simultaneous Connections + Timer Stress ---")
print("")

-- G1: 50 connections all with keepalive, close rapidly
repeat
    tests = tests + 1
    local fds = {}
    local created = 0

    for i = 1, 50 do
        local srv, cli, acc = make_tcp_pair(100 + i)
        if srv then
            setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
            setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
            setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPINTVL, 1)
            table.insert(fds, {srv, cli, acc})
            created = created + 1
        end
    end
    print(string.format("  [G1] Created %d connections with keepalive", created))

    -- Close all at once
    for _, triple in ipairs(fds) do
        close_fd(triple[2]) -- client
        close_fd(triple[3]) -- accepted
        close_fd(triple[1]) -- server
    end
    print("  [G1] SURVIVED")
until true

-- G2: 30 connections with different timer configs, interleaved close
repeat
    tests = tests + 1
    local fds = {}
    local created = 0

    for i = 1, 30 do
        local srv, cli, acc = make_tcp_pair(160 + i)
        if srv then
            -- Alternate timer configs
            if i % 3 == 0 then
                setsockopt_int(cli, SOL_SOCKET, SO_KEEPALIVE, 1)
                setsockopt_int(cli, IPPROTO_TCP, TCP_KEEPIDLE, 1)
            elseif i % 3 == 1 then
                local lbuf = memory.alloc(8)
                safe_wd(lbuf, 1)
                safe_wd(lbuf + 4, 0)
                pcall(function()
                    sc_setsockopt(uint64(cli), uint64(SOL_SOCKET), uint64(SO_LINGER),
                        uint64(lbuf), uint64(8))
                end)
            else
                setsockopt_timeval(cli, SOL_SOCKET, SO_RCVTIMEO, 0, 1)
            end
            table.insert(fds, {srv, cli, acc})
            created = created + 1
        end
    end
    print(string.format("  [G2] Created %d connections with mixed timers", created))

    -- Close in reverse order, client first, with sleeps
    for i = #fds, 1, -1 do
        close_fd(fds[i][2])
    end
    msleep(200)
    for i = 1, #fds do
        close_fd(fds[i][3])
        close_fd(fds[i][1])
    end
    print("  [G2] SURVIVED")
until true

print("")
print("--- Section H: TCP_MAXSEG Manipulation ---")
print("")

-- H1: Set MSS to minimum (1)
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(200)
    if not srv then
        print("  [H1] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_int(cli, IPPROTO_TCP, TCP_MAXSEG, 1)
    print(string.format("  [H1] TCP_MAXSEG=1: ret=%d", r))

    -- Write large data with MSS=1 — forces many segments
    local wbuf = memory.alloc(4096)
    local ok, wr = pcall(function()
        return sc_write(uint64(cli), uint64(wbuf), uint64(4096))
    end)
    print(string.format("  [H1] Write 4K with MSS=1: ok=%s ret=%s",
        tostring(ok), ok and tostring(to_num(wr)) or "err"))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [H1] SURVIVED")
until true

-- H2: Set MSS to 0
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(201)
    if not srv then
        print("  [H2] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_int(cli, IPPROTO_TCP, TCP_MAXSEG, 0)
    print(string.format("  [H2] TCP_MAXSEG=0: ret=%d", r))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [H2] SURVIVED")
until true

-- H3: Set MSS to maximum
repeat
    tests = tests + 1
    local srv, cli, acc = make_tcp_pair(202)
    if not srv then
        print("  [H3] SKIP: pair failed")
        errors = errors + 1
        break
    end

    local r = setsockopt_int(cli, IPPROTO_TCP, TCP_MAXSEG, 65535)
    print(string.format("  [H3] TCP_MAXSEG=65535: ret=%d", r))

    close_fd(cli)
    close_fd(acc)
    close_fd(srv)
    print("  [H3] SURVIVED")
until true

print("")
print("--- Section I: Non-blocking Connect + Timer ---")
print("")

-- I1: Non-blocking connect to loopback (should succeed fast)
repeat
    tests = tests + 1
    local ok1, sfd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    if not ok1 or to_num(sfd) < 0 then
        print("  [I1] SKIP")
        errors = errors + 1
        break
    end
    sfd = to_num(sfd)

    -- Set non-blocking
    pcall(function() sc_fcntl(uint64(sfd), uint64(F_SETFL), uint64(O_NONBLOCK)) end)

    -- Connect to a port nothing listens on → timer-based connection timeout
    local sa = make_sockaddr(29999, 127, 0, 0, 1)
    local ok2, cr = pcall(function()
        return sc_connect(uint64(sfd), uint64(sa), uint64(16))
    end)
    print(string.format("  [I1] NB connect refused port: ok=%s ret=%s",
        tostring(ok2), ok2 and tostring(to_num(cr)) or "err"))

    -- Close while potentially connecting
    close_fd(sfd)
    print("  [I1] SURVIVED")
until true

-- I2: Multiple non-blocking connects, close all
repeat
    tests = tests + 1
    local closed = 0
    for i = 1, 20 do
        local ok1, sfd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok1 and to_num(sfd) >= 0 then
            sfd = to_num(sfd)
            pcall(function() sc_fcntl(uint64(sfd), uint64(F_SETFL), uint64(O_NONBLOCK)) end)
            local sa = make_sockaddr(29998, 127, 0, 0, 1)
            pcall(function() sc_connect(uint64(sfd), uint64(sa), uint64(16)) end)
            close_fd(sfd)
            closed = closed + 1
        end
    end
    print(string.format("  [I2] 20x NB connect+close: %d ok", closed))
    print("  [I2] SURVIVED")
until true

print("")
print("=== SUMMARY ===")
local total = tests
print(string.format("Total tests: %d", total))
print(string.format("Pair creation failures: %d", errors))
print(string.format("Tests completed: %d", total - errors))
print("")
print("Timer manipulation complete. If you're reading this, no crash occurred.")
print("Sections: A(keepalive:6) B(linger:4) C(timeout:5) D(buffer:4) E(shutdown:5)")
print("          F(UDP:2) G(multi-conn:2) H(MSS:3) I(NB-connect:2)")
print("Total: 33 timer/sockopt attack variants")
