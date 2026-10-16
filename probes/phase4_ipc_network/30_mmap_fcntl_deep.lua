-- 14.10 Recon Probe 30: mmap deep + fcntl + writev
-- Probe 29 crashed at UAF read (expected). Skip that.
-- Focus on: madvise, minherit, writev, fcntl, pipe2,
-- and SCM_RIGHTS with simultaneous close (refcount bugs)

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: MMAP+FCNTL DEEP ===")
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
    sc_mmap = 477,
    sc_munmap = 73,
    sc_madvise = 75,
    sc_minherit = 250,
    sc_mlock = 203,
    sc_msync = 226,
    sc_writev = 121,
    sc_readv = 120,
    sc_fcntl = 92,
    sc_pipe2 = 542,
    sc_socket = 97,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_shutdown = 134,
    sc_listen = 106,
    sc_accept = 30,
    sc_bind = 104,
    sc_connect = 98,
    sc_select = 93,
    sc_poll = 209,
})

local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: madvise variants
-- ============================================================
log("")
log("--- PART 1: madvise ---")

local page = memory.alloc(4096 * 4)
-- Align to page boundary
local page_addr = page:tonumber()
local aligned = page_addr
if aligned % 4096 ~= 0 then
    aligned = aligned + (4096 - aligned % 4096)
end
-- Use mmap instead for guaranteed page alignment
local mp_ok, mp = pcall(function()
    return syscall.sc_mmap(0, 4096, 3, 0x1002, -1, 0) -- RW PRIV ANON
end)
if mp_ok then
    memory.write_dword(mp, 0xBBBB1111)

    local advices = {
        {0, "MADV_NORMAL"},
        {1, "MADV_RANDOM"},
        {2, "MADV_SEQUENTIAL"},
        {3, "MADV_WILLNEED"},
        {4, "MADV_DONTNEED"},
        {5, "MADV_FREE"},
        {6, "MADV_NOSYNC"},
        {7, "MADV_AUTOSYNC"},
        {8, "MADV_NOCORE"},
        {9, "MADV_CORE"},
        {12, "MADV_PROTECT"},
    }

    for _, adv in ipairs(advices) do
        -- Reset pattern
        memory.write_dword(mp, 0xBBBB1111)
        local a_ok, a_ret = pcall(function()
            return syscall.sc_madvise(mp, 4096, adv[1])
        end)
        local val_after = memory.read_dword(mp):tonumber()
        local info = a_ok and "rv=" .. a_ret:tonumber() or "ERR"
        if val_after ~= 0xBBBB1111 then
            info = info .. string.format(" DATA_CHANGED:0x%08x", val_after)
        end
        log(string.format("  %-20s %s", adv[2], info))
    end

    -- mlock / munlock
    local ml_ok, ml_ret = pcall(function() return syscall.sc_mlock(mp, 4096) end)
    log("  mlock: " .. (ml_ok and "rv=" .. ml_ret:tonumber() or "ERR"))

    -- msync
    local ms_ok, ms_ret = pcall(function()
        return syscall.sc_msync(mp, 4096, 2) -- MS_SYNC
    end)
    log("  msync(SYNC): " .. (ms_ok and "rv=" .. ms_ret:tonumber() or "ERR"))

    -- minherit
    for inherit = 0, 3 do
        local ih_ok, ih_ret = pcall(function()
            return syscall.sc_minherit(mp, 4096, inherit)
        end)
        log("  minherit(" .. inherit .. "): " ..
            (ih_ok and "rv=" .. ih_ret:tonumber() or "ERR"))
    end

    pcall(function() syscall.sc_munmap(mp, 4096) end)
end

-- ============================================================
-- PART 2: writev/readv
-- ============================================================
log("")
log("--- PART 2: writev/readv ---")

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local wa = memory.read_dword(sp):tonumber()
local wb = memory.read_dword(sp + 4):tonumber()

-- writev with 16 iovecs
local N_IOV = 16
local iovecs = memory.alloc(N_IOV * 16)
for i = 0, N_IOV - 1 do
    local buf = memory.alloc(64)
    for j = 0, 63, 4 do memory.write_dword(buf + j, 0x50000000 + i * 64 + j) end
    memory.write_qword(iovecs + i * 16, buf)
    memory.write_qword(iovecs + i * 16 + 8, 64)
end

local wv_ok, wv_ret = pcall(function() return syscall.sc_writev(wa, iovecs, N_IOV) end)
log("  writev 16x64: " .. (wv_ok and "rv=" .. wv_ret:tonumber() or "ERR"))

-- readv
local rd_iovecs = memory.alloc(N_IOV * 16)
for i = 0, N_IOV - 1 do
    local buf = memory.alloc(64)
    memory.write_qword(rd_iovecs + i * 16, buf)
    memory.write_qword(rd_iovecs + i * 16 + 8, 64)
end

local rv_ok, rv_ret = pcall(function() return syscall.sc_readv(wb, rd_iovecs, N_IOV) end)
log("  readv 16x64: " .. (rv_ok and "rv=" .. rv_ret:tonumber() or "ERR"))

-- writev with 1024 iovecs (near IOV_MAX=1024 on FreeBSD)
local BIG_N = 1024
local big_iov = memory.alloc(BIG_N * 16)
local tiny = memory.alloc(8)
memory.write_byte(tiny, 0x41)
for i = 0, BIG_N - 1 do
    memory.write_qword(big_iov + i * 16, tiny)
    memory.write_qword(big_iov + i * 16 + 8, 1)
end

local bv_ok, bv_ret = pcall(function() return syscall.sc_writev(wa, big_iov, BIG_N) end)
log("  writev 1024x1: " .. (bv_ok and "rv=" .. bv_ret:tonumber() or "ERR"))

-- writev with 1025 (over IOV_MAX)
local ov_ok, ov_ret = pcall(function() return syscall.sc_writev(wa, big_iov, 1025) end)
log("  writev 1025x1: " .. (ov_ok and "rv=" .. ov_ret:tonumber() or "ERR"))

pcall(function() syscall.sc_close(wa) end)
pcall(function() syscall.sc_close(wb) end)

-- ============================================================
-- PART 3: fcntl deep
-- ============================================================
log("")
log("--- PART 3: fcntl ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ffd = memory.read_dword(sp):tonumber()
local ffb = memory.read_dword(sp + 4):tonumber()

local fcntl_cmds = {
    {0, 0, "F_DUPFD"},
    {1, 0, "F_GETFD"},
    {2, 1, "F_SETFD(CLOEXEC)"},
    {3, 0, "F_GETFL"},
    {4, 4, "F_SETFL(NONBLOCK)"},
    {3, 0, "F_GETFL(verify)"},
    {5, 0, "F_GETOWN"},
    {6, pid, "F_SETOWN(self)"},
    {5, 0, "F_GETOWN(verify)"},
    {15, 0, "F_READAHEAD"},
    {16, 1, "F_RDAHEAD(1)"},
    {17, 0, "F_DUP2FD"}, -- FreeBSD extension
    {18, 0, "F_DUP2FD_CLOEXEC"},
    {20, 0, "F_GET_SEALS"},
}

for _, cmd in ipairs(fcntl_cmds) do
    local fc_ok, fc_ret = pcall(function()
        return syscall.sc_fcntl(ffd, cmd[1], cmd[2])
    end)
    log(string.format("  %-22s %s", cmd[3],
        fc_ok and "rv=" .. fc_ret:tonumber() or "ERR"))
end

-- ============================================================
-- PART 4: pipe2
-- ============================================================
log("")
log("--- PART 4: pipe2 ---")

local pipe_fds = memory.alloc(8)
-- O_NONBLOCK=4, O_CLOEXEC=0x100000
local p2_ok, p2_ret = pcall(function() return syscall.sc_pipe2(pipe_fds, 0) end)
if p2_ok then
    local pr = memory.read_dword(pipe_fds):tonumber()
    local pw = memory.read_dword(pipe_fds + 4):tonumber()
    log(string.format("  pipe2(0): rv=%d read=%d write=%d", p2_ret:tonumber(), pr, pw))
    if pr > 0 and pw > 0 then
        -- Test the pipe
        local wr_buf = memory.alloc(8)
        memory.write_qword(wr_buf, 0xCAFEBABE)
        pcall(function() syscall.sc_write(pw, wr_buf, 8) end)
        local rd_buf = memory.alloc(8)
        pcall(function() syscall.sc_read(pr, rd_buf, 8) end)
        local rd_val = memory.read_dword(rd_buf):tonumber()
        log(string.format("  pipe data: 0x%08x", rd_val))
        pcall(function() syscall.sc_close(pr) end)
        pcall(function() syscall.sc_close(pw) end)
    else
        log("  pipe2 returned bad fds (same as probe 19)")
    end
else
    log("  pipe2: ERR")
end

-- ============================================================
-- PART 5: SCM_RIGHTS double-receive (refcount inflation)
-- Send fd once, receive it twice (if possible)
-- ============================================================
log("")
log("--- PART 5: SCM_RIGHTS double-recv ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

-- Create a target fd
local tgt = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, tgt) end)
local tgt_fd = memory.read_dword(tgt):tonumber()

-- Send it
local cmsg = memory.alloc(32)
memory.write_dword(cmsg, 20)     -- cmsg_len
memory.write_dword(cmsg + 4, 0xFFFF) -- SOL_SOCKET
memory.write_dword(cmsg + 8, 1)      -- SCM_RIGHTS
memory.write_dword(cmsg + 16, tgt_fd)

local payload = memory.alloc(4)
memory.write_dword(payload, 0xAAAA)
local iov = memory.alloc(16)
memory.write_qword(iov, payload)
memory.write_qword(iov + 8, 4)

local mh = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
memory.write_qword(mh + 16, iov)
memory.write_qword(mh + 24, 1)
memory.write_qword(mh + 32, cmsg)
memory.write_qword(mh + 40, 24)

pcall(function() syscall.sc_sendmsg(sa, mh, 0) end)

-- First receive
local rcmsg1 = memory.alloc(64)
local rbuf1 = memory.alloc(16)
local riov1 = memory.alloc(16)
memory.write_qword(riov1, rbuf1)
memory.write_qword(riov1 + 8, 16)
for i = 0, 63, 8 do memory.write_qword(rcmsg1 + i, 0) end

local rmh1 = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(rmh1 + i, 0) end
memory.write_qword(rmh1 + 16, riov1)
memory.write_qword(rmh1 + 24, 1)
memory.write_qword(rmh1 + 32, rcmsg1)
memory.write_qword(rmh1 + 40, 64)

local r1_ok, r1_ret = pcall(function() return syscall.sc_recvmsg(sb, rmh1, 0) end)
local recv_fd1 = memory.read_dword(rcmsg1 + 16):tonumber()
log(string.format("  recv1: %s fd=%d",
    r1_ok and "rv=" .. r1_ret:tonumber() or "ERR", recv_fd1))

-- Second receive (should be empty — only sent once)
for i = 0, 63, 8 do memory.write_qword(rcmsg1 + i, 0) end
memory.write_qword(rmh1 + 32, rcmsg1)
memory.write_qword(rmh1 + 40, 64)

-- Set socket nonblocking for this
pcall(function() syscall.sc_fcntl(sb, 4, 4) end) -- F_SETFL O_NONBLOCK

local r2_ok, r2_ret = pcall(function() return syscall.sc_recvmsg(sb, rmh1, 0) end)
log("  recv2 (should fail): " .. (r2_ok and "rv=" .. r2_ret:tonumber() or "ERR"))

-- Close original, then use received fd (test if still valid)
pcall(function() syscall.sc_close(tgt_fd) end)
local test_buf = memory.alloc(4)
memory.write_dword(test_buf, 0xDEDE)
local tw_ok, tw_ret = pcall(function() return syscall.sc_write(recv_fd1, test_buf, 4) end)
log("  write to received fd after closing original: " ..
    (tw_ok and "rv=" .. tw_ret:tonumber() or "ERR"))

-- Cleanup
pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)
pcall(function() syscall.sc_close(recv_fd1) end)
pcall(function() syscall.sc_close(ffd) end)
pcall(function() syscall.sc_close(ffb) end)
pcall(function() syscall.sc_close(memory.read_dword(tgt + 4):tonumber()) end)

log("")
log("=== MMAP+FCNTL DEEP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
