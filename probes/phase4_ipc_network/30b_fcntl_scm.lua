-- 14.10 Recon Probe 30b: fcntl + writev + pipe2 + SCM_RIGHTS
-- Probe 30 crashed at msync. Skip msync/minherit.

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: FCNTL+SCM DEEP ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socketpair = 135,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_writev = 121,
    sc_readv = 120,
    sc_fcntl = 92,
    sc_pipe2 = 542,
    sc_shutdown = 134,
    sc_socket = 97,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_ioctl = 54,
    sc_select = 93,
    sc_poll = 209,
    sc_kqueue = 362,
    sc_kevent = 560,
})

local pid = syscall.sc_getpid():tonumber()
local sp = memory.alloc(8)

-- ============================================================
-- PART 1: writev/readv
-- ============================================================
log("")
log("--- PART 1: writev/readv ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local wa = memory.read_dword(sp):tonumber()
local wb = memory.read_dword(sp + 4):tonumber()
log(string.format("  pair: %d,%d", wa, wb))

-- 16 iovecs
local N = 16
local iovecs = memory.alloc(N * 16)
for i = 0, N - 1 do
    local buf = memory.alloc(64)
    for j = 0, 63, 4 do memory.write_dword(buf + j, 0x50000000 + i * 64 + j) end
    memory.write_qword(iovecs + i * 16, buf)
    memory.write_qword(iovecs + i * 16 + 8, 64)
end

local wv_ok, wv_ret = pcall(function() return syscall.sc_writev(wa, iovecs, N) end)
log("  writev 16x64: " .. (wv_ok and "rv=" .. wv_ret:tonumber() or "ERR"))

local rd_iovecs = memory.alloc(N * 16)
for i = 0, N - 1 do
    local buf = memory.alloc(64)
    memory.write_qword(rd_iovecs + i * 16, buf)
    memory.write_qword(rd_iovecs + i * 16 + 8, 64)
end
local rv_ok, rv_ret = pcall(function() return syscall.sc_readv(wb, rd_iovecs, N) end)
log("  readv 16x64: " .. (rv_ok and "rv=" .. rv_ret:tonumber() or "ERR"))

-- writev with 1024 iovecs (IOV_MAX on FreeBSD)
local tiny = memory.alloc(4)
memory.write_byte(tiny, 0x41)
local big = memory.alloc(1024 * 16)
for i = 0, 1023 do
    memory.write_qword(big + i * 16, tiny)
    memory.write_qword(big + i * 16 + 8, 1)
end
local bv_ok, bv_ret = pcall(function() return syscall.sc_writev(wa, big, 1024) end)
log("  writev 1024x1: " .. (bv_ok and "rv=" .. bv_ret:tonumber() or "ERR"))

local ov_ok, ov_ret = pcall(function() return syscall.sc_writev(wa, big, 1025) end)
log("  writev 1025x1: " .. (ov_ok and "rv=" .. ov_ret:tonumber() or "ERR"))

pcall(function() syscall.sc_close(wa) end)
pcall(function() syscall.sc_close(wb) end)

-- ============================================================
-- PART 2: fcntl deep
-- ============================================================
log("")
log("--- PART 2: fcntl ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ffd = memory.read_dword(sp):tonumber()
local ffb = memory.read_dword(sp + 4):tonumber()

local cmds = {
    {0, 0, "F_DUPFD"},
    {1, 0, "F_GETFD"},
    {2, 1, "F_SETFD(CLOEXEC)"},
    {1, 0, "F_GETFD(verify)"},
    {3, 0, "F_GETFL"},
    {4, 4, "F_SETFL(NONBLK)"},
    {3, 0, "F_GETFL(verify)"},
    {5, 0, "F_GETOWN"},
    {6, pid, "F_SETOWN(self)"},
    {5, 0, "F_GETOWN(verify)"},
    {15, 0, "F_READAHEAD"},
    {16, 1, "F_RDAHEAD(1)"},
    {20, 0, "F_GET_SEALS"},
}

for _, cmd in ipairs(cmds) do
    local fc_ok, fc_ret = pcall(function()
        return syscall.sc_fcntl(ffd, cmd[1], cmd[2])
    end)
    log(string.format("  %-20s %s", cmd[3],
        fc_ok and "rv=" .. fc_ret:tonumber() or "ERR"))
end

-- ioctl on socket
log("")
log("  ioctl:")
-- FIONREAD = 0x4004667F, FIONBIO = 0x8004667E
local ioctl_val = memory.alloc(8)
memory.write_dword(ioctl_val, 0)
local fi_ok, fi_ret = pcall(function()
    return syscall.sc_ioctl(ffd, 0x4004667F, ioctl_val) -- FIONREAD
end)
if fi_ok then
    log(string.format("  FIONREAD: rv=%d bytes=%d", fi_ret:tonumber(),
        memory.read_dword(ioctl_val):tonumber()))
else
    log("  FIONREAD: ERR")
end

memory.write_dword(ioctl_val, 1)
local fb_ok, fb_ret = pcall(function()
    return syscall.sc_ioctl(ffd, 0x8004667E, ioctl_val) -- FIONBIO
end)
log("  FIONBIO(1): " .. (fb_ok and "rv=" .. fb_ret:tonumber() or "ERR"))

-- shutdown
local sh_ok, sh_ret = pcall(function()
    return syscall.sc_shutdown(ffd, 1) -- SHUT_WR
end)
log("  shutdown(WR): " .. (sh_ok and "rv=" .. sh_ret:tonumber() or "ERR"))

pcall(function() syscall.sc_close(ffd) end)
pcall(function() syscall.sc_close(ffb) end)

-- ============================================================
-- PART 3: pipe2
-- ============================================================
log("")
log("--- PART 3: pipe2 ---")

local pfds = memory.alloc(8)
memory.write_dword(pfds, 0xDEAD)
memory.write_dword(pfds + 4, 0xDEAD)

local p2_ok, p2_ret = pcall(function() return syscall.sc_pipe2(pfds, 0) end)
local pr = memory.read_dword(pfds):tonumber()
local pw = memory.read_dword(pfds + 4):tonumber()
log(string.format("  pipe2(0): rv=%d fds=[%d,%d]",
    p2_ok and p2_ret:tonumber() or -999, pr, pw))

-- Check if fds changed from 0xDEAD
if pr == 0xDEAD then
    log("  pipe2 didn't write to pointer (like pipe)")
    -- pipe2 return value is the read fd? Check
    if p2_ok then
        local rv_num = p2_ret:tonumber()
        log(string.format("  return value: %d (may be read fd)", rv_num))
    end
end

-- Try pipe2 with O_NONBLOCK
memory.write_dword(pfds, 0xDEAD)
memory.write_dword(pfds + 4, 0xDEAD)
local p3_ok, p3_ret = pcall(function() return syscall.sc_pipe2(pfds, 4) end) -- O_NONBLOCK=4
local pr2 = memory.read_dword(pfds):tonumber()
local pw2 = memory.read_dword(pfds + 4):tonumber()
log(string.format("  pipe2(NONBLK): rv=%d fds=[%d,%d]",
    p3_ok and p3_ret:tonumber() or -999, pr2, pw2))

-- ============================================================
-- PART 4: SCM_RIGHTS refcount test
-- Send same fd multiple times, close original, check received
-- ============================================================
log("")
log("--- PART 4: SCM_RIGHTS refcount ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

local target_sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, target_sp) end)
local target_fd = memory.read_dword(target_sp):tonumber()
local target_peer = memory.read_dword(target_sp + 4):tonumber()
log(string.format("  target: %d, peer: %d", target_fd, target_peer))

-- Helper: send fd via SCM_RIGHTS
local function send_fd(sock, fd_to_send)
    local cm = memory.alloc(32)
    memory.write_dword(cm, 20)
    memory.write_dword(cm + 4, 0xFFFF)
    memory.write_dword(cm + 8, 1)
    memory.write_dword(cm + 16, fd_to_send)

    local pl = memory.alloc(4)
    memory.write_dword(pl, 0xCC)
    local iv = memory.alloc(16)
    memory.write_qword(iv, pl)
    memory.write_qword(iv + 8, 4)

    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iv)
    memory.write_qword(mh + 24, 1)
    memory.write_qword(mh + 32, cm)
    memory.write_qword(mh + 40, 24)

    local ok, ret = pcall(function() return syscall.sc_sendmsg(sock, mh, 0) end)
    return ok and ret:tonumber() or -1
end

-- Helper: recv fd
local function recv_fd(sock)
    local cm = memory.alloc(64)
    local buf = memory.alloc(16)
    local iv = memory.alloc(16)
    memory.write_qword(iv, buf)
    memory.write_qword(iv + 8, 16)
    for i = 0, 63, 8 do memory.write_qword(cm + i, 0) end

    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iv)
    memory.write_qword(mh + 24, 1)
    memory.write_qword(mh + 32, cm)
    memory.write_qword(mh + 40, 64)

    local ok, ret = pcall(function() return syscall.sc_recvmsg(sock, mh, 0) end)
    if ok then
        return memory.read_dword(cm + 16):tonumber()
    end
    return -1
end

-- Send target_fd 5 times
local sent = 0
for i = 1, 5 do
    local rv = send_fd(sa, target_fd)
    if rv > 0 then sent = sent + 1 end
end
log("  sent target_fd " .. sent .. " times")

-- Close the original fd
pcall(function() syscall.sc_close(target_fd) end)
log("  closed original target_fd")

-- Receive all 5
local received_fds = {}
for i = 1, 5 do
    local rfd = recv_fd(sb)
    received_fds[#received_fds+1] = rfd
end
log("  received fds: " .. table.concat(received_fds, ","))

-- Test each received fd — write to it, read from peer
local working = 0
for i, rfd in ipairs(received_fds) do
    if rfd > 0 then
        local tb = memory.alloc(4)
        memory.write_dword(tb, 0xF000 + i)
        local ok = pcall(function() syscall.sc_write(rfd, tb, 4) end)
        if ok then working = working + 1 end
        pcall(function() syscall.sc_close(rfd) end)
    end
end
log("  working received fds: " .. working .. "/5")

-- Read from peer to verify data arrived
local peer_buf = memory.alloc(256)
local peer_ok, peer_ret = pcall(function()
    return syscall.sc_read(target_peer, peer_buf, 256)
end)
if peer_ok then
    log("  peer read: " .. peer_ret:tonumber() .. " bytes")
end

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)
pcall(function() syscall.sc_close(target_peer) end)

-- ============================================================
-- PART 5: setsockopt on TCP/UDP sockets
-- ============================================================
log("")
log("--- PART 5: socket options ---")

-- TCP socket
local tcp_ok, tcp_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6) -- AF_INET, STREAM, TCP
end)
local tcp_fd = tcp_ok and tcp_ret:tonumber() or -1
log("  TCP socket: fd=" .. tcp_fd)

if tcp_fd >= 0 then
    local optval = memory.alloc(16)
    local optlen = memory.alloc(8)

    -- SO_SNDBUF, SO_RCVBUF, SO_REUSEADDR, SO_KEEPALIVE
    local sol_opts = {
        {0xFFFF, 0x0004, "SO_REUSEADDR"},
        {0xFFFF, 0x0008, "SO_KEEPALIVE"},
        {0xFFFF, 0x1001, "SO_SNDBUF"},
        {0xFFFF, 0x1002, "SO_RCVBUF"},
        {0xFFFF, 0x0080, "SO_LINGER"},
        {0xFFFF, 0x1005, "SO_SNDLOWAT"},
        {0xFFFF, 0x1004, "SO_RCVLOWAT"},
    }

    for _, opt in ipairs(sol_opts) do
        memory.write_qword(optlen, 16)
        for i = 0, 15, 8 do memory.write_qword(optval + i, 0) end
        local g_ok, g_ret = pcall(function()
            return syscall.sc_getsockopt(tcp_fd, opt[1], opt[2], optval, optlen)
        end)
        local val = memory.read_dword(optval):tonumber()
        log(string.format("  %-16s %s val=%d",
            opt[3],
            g_ok and "rv=" .. g_ret:tonumber() or "ERR",
            val))
    end

    -- Set SO_SNDBUF to extreme value
    memory.write_dword(optval, 0x7FFFFFFF)
    local sb_ok, sb_ret = pcall(function()
        return syscall.sc_setsockopt(tcp_fd, 0xFFFF, 0x1001, optval, 4)
    end)
    log("  set SNDBUF=MAX: " .. (sb_ok and "rv=" .. sb_ret:tonumber() or "ERR"))

    -- Read back
    memory.write_qword(optlen, 4)
    pcall(function() syscall.sc_getsockopt(tcp_fd, 0xFFFF, 0x1001, optval, optlen) end)
    log("  SNDBUF now: " .. memory.read_dword(optval):tonumber())

    pcall(function() syscall.sc_close(tcp_fd) end)
end

log("")
log("=== FCNTL+SCM DEEP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
