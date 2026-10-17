-- CRASH_CLASS: HIGH
-- PROBE 50c: High-Volume Resource Exhaustion
--
-- Context: Basic fuzz (584 variants) showed the kernel handles individual
-- malformed packets cleanly. But resource exhaustion attacks work differently:
-- instead of triggering a parsing bug, they force the kernel to hit memory
-- limits, hash table collisions, or allocation failures. These paths are
-- harder to test and often have subtler bugs:
--   - OOM in kernel zone allocators → panic or corruption
--   - Hash table degradation → O(n) lookups → softlock/watchdog timeout
--   - Incomplete cleanup on allocation failure → leaked references
--   - Counter wraps → negative refcount → use-after-free
--
-- Attack vectors:
--   A) TCP connection flood — exhaust socket/TCB allocations
--   B) TCP listen queue overflow — SYN to a full backlog
--   C) IPv6 fragment queue exhaustion — many incomplete reassemblies
--   D) Socket creation/close flood — exhaust fd table and socket zones
--   E) UDP sendto flood — exhaust mbuf clusters
--   F) Raw socket flood — many raw IPv4 protocol sockets
--   G) Bind collision stress — many sockets racing for same port
--   H) Accept queue drain race — accept during heavy connection load
--
-- This probe runs on-device (loopback) so it's limited by the sandbox's
-- own fd limits and memory. But kernel-side resource pools are shared.

print("=== PROBE 50c: HIGH-VOLUME RESOURCE EXHAUSTION ===")
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

-- Syscalls
local sc_socket = make_syscall(97)
local sc_bind = make_syscall(104)
local sc_listen = make_syscall(106)
local sc_accept = make_syscall(30)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_write = make_syscall(4)
local sc_read = make_syscall(3)
local sc_setsockopt = make_syscall(105)
local sc_sendto = make_syscall(133)
local sc_fcntl = make_syscall(92)
local sc_nanosleep = make_syscall(240)
local sc_shutdown = make_syscall(134)

-- Constants
local AF_INET = 2
local AF_INET6 = 28
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCK_RAW = 3
local SOL_SOCKET = 0xFFFF
local SO_REUSEADDR = 0x0004
local SO_REUSEPORT = 0x0200
local F_SETFL = 4
local O_NONBLOCK = 4
local IP_HDRINCL = 2

local function make_sockaddr(port, a, b, c, d)
    local sa = memory.alloc(16)
    safe_wb(sa, 16)
    safe_wb(sa + 1, AF_INET)
    safe_wb(sa + 2, math.floor(port / 256))
    safe_wb(sa + 3, port % 256)
    safe_wb(sa + 4, a)
    safe_wb(sa + 5, b)
    safe_wb(sa + 6, c)
    safe_wb(sa + 7, d)
    return sa
end

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

local function close_fd(fd)
    if fd and fd >= 0 then
        pcall(function() sc_close(uint64(fd)) end)
    end
end

local function msleep(ms)
    local buf = memory.alloc(16)
    safe_wq(buf, uint64(0))
    safe_wq(buf + 8, uint64(ms * 1000000))
    pcall(function() sc_nanosleep(uint64(buf), uint64(0)) end)
end

print("--- Section A: TCP Connection Flood ---")
print("")

-- A1: Create as many TCP connections as possible to a single listener
repeat
    local lfd = -1
    local ok1, s = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    if not ok1 or to_num(s) < 0 then
        print("  [A1] SKIP: listener socket failed")
        break
    end
    lfd = to_num(s)

    setsockopt_int(lfd, SOL_SOCKET, SO_REUSEADDR, 1)

    local sa = make_sockaddr(21000, 127, 0, 0, 1)
    local ok2, br = pcall(function()
        return sc_bind(uint64(lfd), uint64(sa), uint64(16))
    end)
    if not ok2 or to_num(br) ~= 0 then
        print("  [A1] SKIP: bind failed")
        close_fd(lfd)
        break
    end
    pcall(function() sc_listen(uint64(lfd), uint64(128)) end)

    local conns = {}
    local connected = 0
    local max_target = 200

    for i = 1, max_target do
        local ok3, cfd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if not ok3 or to_num(cfd) < 0 then
            print(string.format("  [A1] Socket creation failed at %d", i))
            break
        end
        cfd = to_num(cfd)

        local ok4, cr = pcall(function()
            return sc_connect(uint64(cfd), uint64(sa), uint64(16))
        end)
        if not ok4 or to_num(cr) ~= 0 then
            close_fd(cfd)
            print(string.format("  [A1] Connect failed at %d", i))
            break
        end

        -- Accept
        local ok5, afd = pcall(function()
            return sc_accept(uint64(lfd), uint64(0), uint64(0))
        end)
        if ok5 and to_num(afd) >= 0 then
            table.insert(conns, {cfd, to_num(afd)})
        else
            table.insert(conns, {cfd, -1})
        end
        connected = connected + 1
    end

    print(string.format("  [A1] Created %d connections (target %d)", connected, max_target))

    -- Close all
    for _, pair in ipairs(conns) do
        close_fd(pair[1])
        close_fd(pair[2])
    end
    close_fd(lfd)
    print("  [A1] SURVIVED — all closed")
until true

print("")

-- A2: Connect flood WITHOUT accept (fill SYN queue / accept queue)
repeat
    local ok1, lfd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)
    if not ok1 or to_num(lfd) < 0 then
        print("  [A2] SKIP")
        break
    end
    lfd = to_num(lfd)

    setsockopt_int(lfd, SOL_SOCKET, SO_REUSEADDR, 1)
    local sa = make_sockaddr(21001, 127, 0, 0, 1)
    pcall(function() sc_bind(uint64(lfd), uint64(sa), uint64(16)) end)

    -- Listen with backlog=1 — accept queue is tiny
    pcall(function() sc_listen(uint64(lfd), uint64(1)) end)

    local cli_fds = {}
    local success = 0

    -- Flood connects without accepting
    for i = 1, 100 do
        local ok2, cfd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if not ok2 or to_num(cfd) < 0 then break end
        cfd = to_num(cfd)

        -- Non-blocking connect
        pcall(function() sc_fcntl(uint64(cfd), uint64(F_SETFL), uint64(O_NONBLOCK)) end)
        pcall(function() sc_connect(uint64(cfd), uint64(sa), uint64(16)) end)
        table.insert(cli_fds, cfd)
        success = success + 1
    end

    print(string.format("  [A2] Flooded %d connects to backlog=1 listener", success))
    msleep(100)

    -- Now rapidly accept+close to drain
    for i = 1, success do
        local ok, afd = pcall(function()
            return sc_accept(uint64(lfd), uint64(0), uint64(0))
        end)
        if ok and to_num(afd) >= 0 then
            close_fd(to_num(afd))
        end
    end

    for _, fd in ipairs(cli_fds) do close_fd(fd) end
    close_fd(lfd)
    print("  [A2] SURVIVED")
until true

print("")
print("--- Section B: Socket Creation/Close Flood ---")
print("")

-- B1: TCP socket create/close cycle — stress zone allocator
repeat
    local count = 0
    for i = 1, 500 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok and to_num(fd) >= 0 then
            close_fd(to_num(fd))
            count = count + 1
        else
            break
        end
    end
    print(string.format("  [B1] TCP create/close: %d cycles", count))
    print("  [B1] SURVIVED")
until true

-- B2: UDP socket create/close cycle
repeat
    local count = 0
    for i = 1, 500 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
        end)
        if ok and to_num(fd) >= 0 then
            close_fd(to_num(fd))
            count = count + 1
        else
            break
        end
    end
    print(string.format("  [B2] UDP create/close: %d cycles", count))
    print("  [B2] SURVIVED")
until true

-- B3: Raw socket create/close with many protocols
repeat
    local count = 0
    for proto = 0, 142 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(proto))
        end)
        if ok and to_num(fd) >= 0 then
            close_fd(to_num(fd))
            count = count + 1
        end
    end
    print(string.format("  [B3] RAW create/close (143 protos): %d ok", count))
    print("  [B3] SURVIVED")
until true

-- B4: IPv6 socket create/close cycle
repeat
    local count = 0
    for i = 1, 200 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET6), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok and to_num(fd) >= 0 then
            close_fd(to_num(fd))
            count = count + 1
        else
            break
        end
    end
    print(string.format("  [B4] IPv6 TCP create/close: %d cycles", count))
    print("  [B4] SURVIVED")
until true

-- B5: Maximum simultaneous open sockets
repeat
    local fds = {}
    local max_open = 0

    for i = 1, 500 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok and to_num(fd) >= 0 then
            table.insert(fds, to_num(fd))
            max_open = max_open + 1
        else
            break
        end
    end

    print(string.format("  [B5] Max simultaneous sockets: %d", max_open))

    -- Close all
    for _, fd in ipairs(fds) do close_fd(fd) end
    print("  [B5] SURVIVED")
until true

print("")
print("--- Section C: UDP Send Flood (mbuf stress) ---")
print("")

-- C1: UDP sendto flood — many small packets to localhost
repeat
    local ok1, ufd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
    end)
    if not ok1 or to_num(ufd) < 0 then
        print("  [C1] SKIP")
        break
    end
    ufd = to_num(ufd)

    local dest = make_sockaddr(21100, 127, 0, 0, 1)
    local wbuf = memory.alloc(64)
    safe_wd(wbuf, 0x41424344)

    local sent = 0
    for i = 1, 1000 do
        local ok, r = pcall(function()
            return sc_sendto(uint64(ufd), uint64(wbuf), uint64(32),
                uint64(0), uint64(dest), uint64(16))
        end)
        if ok and to_num(r) >= 0 then
            sent = sent + 1
        end
    end

    print(string.format("  [C1] UDP sendto flood: %d/1000 sent", sent))
    close_fd(ufd)
    print("  [C1] SURVIVED")
until true

-- C2: UDP large packet flood
repeat
    local ok1, ufd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
    end)
    if not ok1 or to_num(ufd) < 0 then
        print("  [C2] SKIP")
        break
    end
    ufd = to_num(ufd)

    local dest = make_sockaddr(21101, 127, 0, 0, 1)
    local wbuf = memory.alloc(0x4000) -- 16KB

    local sent = 0
    for i = 1, 200 do
        local ok, r = pcall(function()
            return sc_sendto(uint64(ufd), uint64(wbuf), uint64(0x2000),
                uint64(0), uint64(dest), uint64(16))
        end)
        if ok and to_num(r) >= 0 then
            sent = sent + 1
        end
    end

    print(string.format("  [C2] UDP large packet flood: %d/200 sent (8KB each)", sent))
    close_fd(ufd)
    print("  [C2] SURVIVED")
until true

print("")
print("--- Section D: IPv6 Fragment Queue Flooding ---")
print("")

-- D1: Send many incomplete IPv6 fragment reassemblies via raw socket
repeat
    local ok1, rfd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(41))
    end)
    if not ok1 or to_num(rfd) < 0 then
        print("  [D1] SKIP: raw socket failed")
        break
    end
    rfd = to_num(rfd)

    setsockopt_int(rfd, 0, IP_HDRINCL, 1)

    local dest = make_sockaddr(0, 127, 0, 0, 1)
    local pkt_base = memory.alloc(256)

    local sent = 0
    -- Send 200 first-fragments with unique IDs, never completing reassembly
    -- Each creates a kernel reassembly queue entry that times out
    for i = 1, 200 do
        -- IPv4 header (20 bytes)
        safe_wb(pkt_base, 0x45)        -- ver=4, ihl=5
        safe_wb(pkt_base + 1, 0)       -- tos
        safe_wb(pkt_base + 2, 0)       -- total len high (kernel fills)
        safe_wb(pkt_base + 3, 0)       -- total len low
        safe_wb(pkt_base + 4, 0)       -- id high
        safe_wb(pkt_base + 5, 0)       -- id low
        safe_wb(pkt_base + 6, 0)       -- flags/offset
        safe_wb(pkt_base + 7, 0)
        safe_wb(pkt_base + 8, 64)      -- ttl
        safe_wb(pkt_base + 9, 41)      -- proto = IPv6
        safe_wb(pkt_base + 10, 0)      -- checksum (kernel fills)
        safe_wb(pkt_base + 11, 0)
        safe_wb(pkt_base + 12, 127)    -- src
        safe_wb(pkt_base + 13, 0)
        safe_wb(pkt_base + 14, 0)
        safe_wb(pkt_base + 15, 1)
        safe_wb(pkt_base + 16, 127)    -- dst
        safe_wb(pkt_base + 17, 0)
        safe_wb(pkt_base + 18, 0)
        safe_wb(pkt_base + 19, 1)

        -- IPv6 header (40 bytes) — inner packet header for tunneled packet
        safe_wb(pkt_base + 20, 0x60)   -- version=6
        safe_wb(pkt_base + 21, 0)
        safe_wb(pkt_base + 22, 0)
        safe_wb(pkt_base + 23, 0)
        safe_wb(pkt_base + 24, 0)      -- payload length high
        safe_wb(pkt_base + 25, 16)     -- payload length low
        safe_wb(pkt_base + 26, 44)     -- next header = Fragment
        safe_wb(pkt_base + 27, 64)     -- hop limit
        -- src: ::1
        for j = 28, 43 do safe_wb(pkt_base + j, 0) end
        safe_wb(pkt_base + 35, 1)
        -- dst: ::1
        for j = 44, 59 do safe_wb(pkt_base + j, 0) end
        safe_wb(pkt_base + 51, 1)

        -- Fragment header (8 bytes)
        safe_wb(pkt_base + 60, 59)     -- next header = No Next Header
        safe_wb(pkt_base + 61, 0)      -- reserved
        -- frag_offset=0, MF=1 (more fragments) — first fragment, incomplete
        safe_wb(pkt_base + 62, 0)
        safe_wb(pkt_base + 63, 1)      -- MF bit
        -- identification = unique per fragment
        safe_wb(pkt_base + 64, 0)
        safe_wb(pkt_base + 65, 0)
        safe_wb(pkt_base + 66, math.floor(i / 256))
        safe_wb(pkt_base + 67, i % 256)

        -- 8 bytes payload (minimum fragment)
        for j = 68, 75 do safe_wb(pkt_base + j, 0xBB) end

        local ok, r = pcall(function()
            return sc_sendto(uint64(rfd), uint64(pkt_base), uint64(76),
                uint64(0), uint64(dest), uint64(16))
        end)
        if ok and to_num(r) >= 0 then sent = sent + 1 end
    end

    print(string.format("  [D1] Incomplete IPv6-in-IPv4 frags: %d/200 sent", sent))
    msleep(100)
    close_fd(rfd)
    print("  [D1] SURVIVED")
until true

print("")
print("--- Section E: Bind Collision Stress ---")
print("")

-- E1: Many sockets trying to bind same port with SO_REUSEADDR
repeat
    local fds = {}
    local bound = 0
    local sa = make_sockaddr(21200, 127, 0, 0, 1)

    for i = 1, 100 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if not ok or to_num(fd) < 0 then break end
        fd = to_num(fd)

        setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)
        local ok2, br = pcall(function()
            return sc_bind(uint64(fd), uint64(sa), uint64(16))
        end)
        if ok2 and to_num(br) == 0 then
            bound = bound + 1
        end
        table.insert(fds, fd)
    end

    print(string.format("  [E1] SO_REUSEADDR bind flood: %d/100 bound", bound))
    for _, fd in ipairs(fds) do close_fd(fd) end
    print("  [E1] SURVIVED")
until true

-- E2: SO_REUSEPORT binding
repeat
    local fds = {}
    local bound = 0
    local sa = make_sockaddr(21201, 127, 0, 0, 1)

    for i = 1, 50 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if not ok or to_num(fd) < 0 then break end
        fd = to_num(fd)

        setsockopt_int(fd, SOL_SOCKET, SO_REUSEPORT, 1)
        local ok2, br = pcall(function()
            return sc_bind(uint64(fd), uint64(sa), uint64(16))
        end)
        if ok2 and to_num(br) == 0 then
            bound = bound + 1
        end
        table.insert(fds, fd)
    end

    print(string.format("  [E2] SO_REUSEPORT bind flood: %d/50 bound", bound))
    for _, fd in ipairs(fds) do close_fd(fd) end
    print("  [E2] SURVIVED")
until true

-- E3: Bind different ports rapidly (exhaust port space)
repeat
    local fds = {}
    local bound = 0

    for i = 1, 300 do
        local port = 21300 + i
        if port >= 32000 then break end

        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if not ok or to_num(fd) < 0 then break end
        fd = to_num(fd)

        local sa = make_sockaddr(port, 127, 0, 0, 1)
        local ok2, br = pcall(function()
            return sc_bind(uint64(fd), uint64(sa), uint64(16))
        end)
        if ok2 and to_num(br) == 0 then
            bound = bound + 1
        end
        table.insert(fds, fd)
    end

    print(string.format("  [E3] Multi-port bind: %d bound", bound))
    for _, fd in ipairs(fds) do close_fd(fd) end
    print("  [E3] SURVIVED")
until true

print("")
print("--- Section F: Listen + Accept Storm ---")
print("")

-- F1: Multiple listeners on SO_REUSEPORT, flood connects, accept from all
repeat
    local listeners = {}
    local n_listeners = 5
    local sa = make_sockaddr(21500, 127, 0, 0, 1)

    for i = 1, n_listeners do
        local ok, fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok and to_num(fd) >= 0 then
            fd = to_num(fd)
            setsockopt_int(fd, SOL_SOCKET, SO_REUSEPORT, 1)
            pcall(function() sc_bind(uint64(fd), uint64(sa), uint64(16)) end)
            pcall(function() sc_listen(uint64(fd), uint64(10)) end)
            table.insert(listeners, fd)
        end
    end

    print(string.format("  [F1] %d listeners on same port", #listeners))

    -- Connect flood
    local cli_fds = {}
    for i = 1, 50 do
        local ok, cfd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        if ok and to_num(cfd) >= 0 then
            cfd = to_num(cfd)
            pcall(function() sc_fcntl(uint64(cfd), uint64(F_SETFL), uint64(O_NONBLOCK)) end)
            pcall(function() sc_connect(uint64(cfd), uint64(sa), uint64(16)) end)
            table.insert(cli_fds, cfd)
        end
    end

    msleep(50)

    -- Accept from all listeners
    local accepted = 0
    for _, lfd in ipairs(listeners) do
        for j = 1, 20 do
            local ok, afd = pcall(function()
                return sc_accept(uint64(lfd), uint64(0), uint64(0))
            end)
            if ok and to_num(afd) >= 0 then
                close_fd(to_num(afd))
                accepted = accepted + 1
            else
                break
            end
        end
    end

    print(string.format("  [F1] Accepted %d from %d connects", accepted, #cli_fds))
    for _, fd in ipairs(cli_fds) do close_fd(fd) end
    for _, fd in ipairs(listeners) do close_fd(fd) end
    print("  [F1] SURVIVED")
until true

print("")
print("--- Section G: Raw Socket + IP_HDRINCL Packet Flood ---")
print("")

-- G1: Flood raw IP packets (various protocols)
repeat
    local ok1, rfd = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(255))
    end)
    if not ok1 or to_num(rfd) < 0 then
        print("  [G1] SKIP: raw socket failed")
        break
    end
    rfd = to_num(rfd)

    setsockopt_int(rfd, 0, IP_HDRINCL, 1)

    local dest = make_sockaddr(0, 127, 0, 0, 1)
    local pkt = memory.alloc(64)

    local sent = 0
    local protos_to_flood = {2, 6, 17, 41, 47, 50, 51, 89, 103, 112, 132}

    for _, proto in ipairs(protos_to_flood) do
        -- Minimal IP header
        safe_wb(pkt, 0x45)       -- ver=4, ihl=5
        safe_wb(pkt + 1, 0)
        safe_wb(pkt + 2, 0)     -- len (kernel fills)
        safe_wb(pkt + 3, 0)
        safe_wb(pkt + 4, 0)     -- id
        safe_wb(pkt + 5, 0)
        safe_wb(pkt + 6, 0)     -- flags
        safe_wb(pkt + 7, 0)
        safe_wb(pkt + 8, 64)    -- ttl
        safe_wb(pkt + 9, proto)
        safe_wb(pkt + 10, 0)
        safe_wb(pkt + 11, 0)
        safe_wb(pkt + 12, 127)
        safe_wb(pkt + 13, 0)
        safe_wb(pkt + 14, 0)
        safe_wb(pkt + 15, 1)
        safe_wb(pkt + 16, 127)
        safe_wb(pkt + 17, 0)
        safe_wb(pkt + 18, 0)
        safe_wb(pkt + 19, 1)
        -- 8 bytes payload
        for j = 20, 27 do safe_wb(pkt + j, 0xCC) end

        for i = 1, 50 do
            local ok, r = pcall(function()
                return sc_sendto(uint64(rfd), uint64(pkt), uint64(28),
                    uint64(0), uint64(dest), uint64(16))
            end)
            if ok and to_num(r) >= 0 then sent = sent + 1 end
        end
    end

    print(string.format("  [G1] Raw IP flood: %d/%d sent (11 protos x 50)",
        sent, 11 * 50))
    close_fd(rfd)
    print("  [G1] SURVIVED")
until true

print("")
print("--- Section H: Mixed Protocol Socket Stress ---")
print("")

-- H1: Interleaved TCP + UDP + RAW socket creation/use/close
repeat
    local total_ops = 0

    for round = 1, 30 do
        -- TCP
        local ok1, tcp_fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
        end)
        -- UDP
        local ok2, udp_fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
        end)
        -- RAW
        local ok3, raw_fd = pcall(function()
            return sc_socket(uint64(AF_INET), uint64(SOCK_RAW), uint64(round % 143))
        end)

        -- Close in different order each round
        if round % 3 == 0 then
            if ok1 then close_fd(to_num(tcp_fd)) end
            if ok2 then close_fd(to_num(udp_fd)) end
            if ok3 then close_fd(to_num(raw_fd)) end
        elseif round % 3 == 1 then
            if ok3 then close_fd(to_num(raw_fd)) end
            if ok1 then close_fd(to_num(tcp_fd)) end
            if ok2 then close_fd(to_num(udp_fd)) end
        else
            if ok2 then close_fd(to_num(udp_fd)) end
            if ok3 then close_fd(to_num(raw_fd)) end
            if ok1 then close_fd(to_num(tcp_fd)) end
        end
        total_ops = total_ops + 3
    end

    print(string.format("  [H1] Interleaved socket stress: %d ops in 30 rounds", total_ops))
    print("  [H1] SURVIVED")
until true

print("")
print("=== SUMMARY ===")
print("")
print("Resource exhaustion complete. If you're reading this, no crash occurred.")
print("Sections:")
print("  A: TCP connection flood (200 conns + backlog=1 overflow)")
print("  B: Socket create/close (500 TCP + 500 UDP + 143 RAW + 200 IPv6 + max open)")
print("  C: UDP sendto flood (1000 small + 200 large)")
print("  D: IPv6 frag queue flood (200 incomplete reassemblies)")
print("  E: Bind collision (100 REUSEADDR + 50 REUSEPORT + 300 ports)")
print("  F: Listen+accept storm (5 listeners, 50 connects)")
print("  G: Raw IP packet flood (550 packets, 11 protocols)")
print("  H: Mixed protocol interleave (90 sockets)")
