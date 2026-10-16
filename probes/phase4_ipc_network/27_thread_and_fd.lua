-- 14.10 Recon Probe 27: Threading + fd attack surface
-- Part 1: Can we create threads? (rfork, thr_new, fork)
-- Part 2: SCM_RIGHTS fd passing via sendmsg/recvmsg
-- Part 3: dup2, fcntl, fstat on various fds
-- Part 4: Socket types (AF_INET, AF_INET6, raw)
-- Part 5: shm_open, mmap shared

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: THREAD + FD SURFACE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_fork = 2,
    sc_rfork = 251,
    sc_thr_new = 455,
    sc_thr_self = 432,
    sc_thr_exit = 431,
    sc_socketpair = 135,
    sc_socket = 97,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_dup2 = 90,
    sc_dup = 41,
    sc_fcntl = 92,
    sc_fstat = 551,
    sc_pipe2 = 542,
    sc_open = 5,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_shm_open2 = 571,
    sc_shm_unlink = 483,
    sc_connect = 98,
    sc_bind = 104,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
})

local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: Threading
-- ============================================================
log("")
log("--- PART 1: threading syscalls ---")

-- thr_self — get current thread ID
local ts_ok, ts_ret = pcall(function()
    local tid_buf = memory.alloc(8)
    local rv = syscall.sc_thr_self(tid_buf)
    local tid = memory.read_qword(tid_buf):tonumber()
    return rv:tonumber(), tid
end)
if ts_ok then
    log(string.format("  thr_self: rv=%d tid=%d", ts_ret, select(2, ts_ret) or 0))
else
    -- try simpler
    local tid_buf = memory.alloc(8)
    local t2_ok, t2_ret = pcall(function() return syscall.sc_thr_self(tid_buf) end)
    if t2_ok then
        local tid = memory.read_qword(tid_buf):tonumber()
        log(string.format("  thr_self: rv=%d tid=%d", t2_ret:tonumber(), tid))
    else
        log("  thr_self: FAIL")
    end
end

-- fork — does it work?
local fork_ok, fork_ret = pcall(function() return syscall.sc_fork() end)
if fork_ok then
    local rv = fork_ret:tonumber()
    log(string.format("  fork: rv=%d %s", rv, rv == 0 and "(CHILD!)" or "(parent, child=" .. rv .. ")"))
    -- If rv > 0 we're the parent and child is running
    -- If rv == 0 we're the child (shouldn't happen in Lua context)
    -- If rv == -1 fork failed
else
    log("  fork: CRASH/ERR")
end

-- rfork with RFPROC|RFMEM (shared memory fork = thread-like)
local RFPROC = 0x10
local RFMEM = 0x20
local RFNOWAIT = 0x40
local RFTHREAD = 0x2000

local rf_ok, rf_ret = pcall(function()
    return syscall.sc_rfork(RFPROC + RFMEM + RFNOWAIT)
end)
if rf_ok then
    local rv = rf_ret:tonumber()
    log(string.format("  rfork(PROC|MEM|NOWAIT): rv=%d", rv))
else
    log("  rfork: CRASH/ERR")
end

-- thr_new — create a new thread
-- Needs a stack and entry point — dangerous without executable memory
-- Just test if the syscall is reachable (will fail with bad args)
local thr_param = memory.alloc(128)
for i = 0, 127, 8 do memory.write_qword(thr_param + i, 0) end
-- Set a minimal param: start_func=1 (will fail but shows if syscall works)
memory.write_qword(thr_param, 1)  -- start_func
memory.write_qword(thr_param + 8, 0)  -- arg
local thr_stack = memory.alloc(4096)
memory.write_qword(thr_param + 16, thr_stack)  -- stack_base
memory.write_qword(thr_param + 24, 4096)  -- stack_size

local tn_ok, tn_ret = pcall(function() return syscall.sc_thr_new(thr_param, 128) end)
if tn_ok then
    log(string.format("  thr_new: rv=%d", tn_ret:tonumber()))
else
    log("  thr_new: CRASH/ERR")
end

-- ============================================================
-- PART 2: SCM_RIGHTS fd passing
-- ============================================================
log("")
log("--- PART 2: SCM_RIGHTS ---")

-- Create two socketpairs: one for communication, one fd to pass
local sp1 = memory.alloc(8)
local sp2 = memory.alloc(8)

pcall(function() syscall.sc_socketpair(1, 1, 0, sp1) end) -- AF_UNIX, SOCK_STREAM
pcall(function() syscall.sc_socketpair(1, 1, 0, sp2) end)

local fd1a = memory.read_dword(sp1):tonumber()
local fd1b = memory.read_dword(sp1 + 4):tonumber()
local fd2a = memory.read_dword(sp2):tonumber()
local fd2b = memory.read_dword(sp2 + 4):tonumber()
log(string.format("  pair1: %d,%d  pair2: %d,%d", fd1a, fd1b, fd2a, fd2b))

-- Build sendmsg with SCM_RIGHTS to pass fd2a over pair1
-- struct msghdr {
--   void *msg_name;        // +0, 8
--   socklen_t msg_namelen; // +8, 4
--   // pad 4
--   struct iovec *msg_iov; // +16, 8
--   int msg_iovlen;        // +24, 4 (size_t on 64-bit = 8)
--   // actually msg_iovlen is size_t = 8 bytes on amd64
--   void *msg_control;     // +32, 8  (offset may vary)
--   socklen_t msg_controllen; // +40, 4 (size_t = 8)
--   int msg_flags;         // +48, 4
-- }
-- FreeBSD amd64 msghdr:
--   msg_name: 8, msg_namelen: 4, pad: 4,
--   msg_iov: 8, msg_iovlen: 8,
--   msg_control: 8, msg_controllen: 8,
--   msg_flags: 4
-- Total: ~52 bytes

local msghdr = memory.alloc(64)
local iov = memory.alloc(16)
local iov_buf = memory.alloc(16)
local cmsg_buf = memory.alloc(64) -- control message buffer

-- IOV: one byte payload
memory.write_byte(iov_buf, 0x42)
memory.write_qword(iov, iov_buf)     -- iov_base
memory.write_qword(iov + 8, 1)       -- iov_len

-- CMSG: SCM_RIGHTS with one fd
-- struct cmsghdr { cmsg_len (8), cmsg_level (4), cmsg_type (4) }
-- followed by data (the fd, 4 bytes)
-- CMSG_LEN for 1 fd = sizeof(cmsghdr) + sizeof(int) = 16 + 4 = 20
-- CMSG_SPACE = aligned = 24
local SCM_RIGHTS = 1
local SOL_SOCKET = 0xFFFF
local CMSG_HDR_SZ = 16  -- FreeBSD amd64: cmsg_len(4 or 8?) + level(4) + type(4)
-- Actually on FreeBSD amd64: cmsg_len is socklen_t = 4 bytes
-- struct cmsghdr { socklen_t cmsg_len; int cmsg_level; int cmsg_type; }
-- = 4 + 4 + 4 = 12 bytes header
-- But CMSG_DATA alignment: CMSG_ALIGN(sizeof(struct cmsghdr)) = 16? or 12?
-- On FreeBSD amd64 with _LP64: cmsg_len is __socklen_t = __uint32_t = 4
-- sizeof(struct cmsghdr) = 12, CMSG_ALIGN(12) = 16 (aligned to 8)
-- Wait, CMSG_ALIGN on FreeBSD rounds up to sizeof(long) = 8
-- CMSG_ALIGN(12) = 16
-- CMSG_LEN(4) = CMSG_ALIGN(sizeof(cmsghdr)) + 4 = 16 + 4 = 20
-- CMSG_SPACE(4) = CMSG_ALIGN(CMSG_LEN(4)) = CMSG_ALIGN(20) = 24

-- Actually let me be more careful. FreeBSD:
-- #define CMSG_ALIGN(n) (((n) + __DARWIN_ALIGNBYTES) & ~__DARWIN_ALIGNBYTES)
-- No that's macOS. FreeBSD:
-- #define _ALIGN(p) (((u_int)(p) + (sizeof(long) - 1)) & ~(sizeof(long) - 1))
-- sizeof(long) on amd64 = 8
-- _ALIGN(12) = (12 + 7) & ~7 = 16
-- CMSG_DATA(cmsg) = (unsigned char *)(cmsg) + _ALIGN(sizeof(struct cmsghdr))
-- = cmsg + 16
-- CMSG_LEN(datalen) = _ALIGN(sizeof(struct cmsghdr)) + datalen = 16 + datalen
-- CMSG_SPACE(datalen) = _ALIGN(_ALIGN(sizeof(struct cmsghdr)) + datalen)
-- = _ALIGN(16 + datalen)

-- For 1 fd (4 bytes):
-- cmsg_len = 16 + 4 = 20
-- CMSG_SPACE = _ALIGN(20) = 24

for i = 0, 63, 8 do memory.write_qword(cmsg_buf + i, 0) end
memory.write_dword(cmsg_buf, 20)            -- cmsg_len = 20
memory.write_dword(cmsg_buf + 4, 0xFFFF)    -- cmsg_level = SOL_SOCKET
memory.write_dword(cmsg_buf + 8, 1)         -- cmsg_type = SCM_RIGHTS
-- fd at offset 16 (CMSG_DATA)
memory.write_dword(cmsg_buf + 16, fd2a)     -- the fd to pass

-- Fill msghdr
for i = 0, 63, 8 do memory.write_qword(msghdr + i, 0) end
memory.write_qword(msghdr, 0)               -- msg_name = NULL
memory.write_dword(msghdr + 8, 0)           -- msg_namelen = 0
memory.write_qword(msghdr + 16, iov)        -- msg_iov
memory.write_qword(msghdr + 24, 1)          -- msg_iovlen = 1
memory.write_qword(msghdr + 32, cmsg_buf)   -- msg_control
memory.write_qword(msghdr + 40, 24)         -- msg_controllen = CMSG_SPACE(4)
memory.write_dword(msghdr + 48, 0)          -- msg_flags = 0

-- Send fd over pair1
local sm_ok, sm_ret = pcall(function() return syscall.sc_sendmsg(fd1a, msghdr, 0) end)
log("  sendmsg(SCM_RIGHTS): " ..
    (sm_ok and "rv=" .. sm_ret:tonumber() or "ERR"))

-- Receive on the other end
local recv_cmsg = memory.alloc(64)
local recv_iov_buf = memory.alloc(16)
local recv_iov = memory.alloc(16)
memory.write_qword(recv_iov, recv_iov_buf)
memory.write_qword(recv_iov + 8, 16)

local recv_hdr = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(recv_hdr + i, 0) end
for i = 0, 63, 8 do memory.write_qword(recv_cmsg + i, 0) end
memory.write_qword(recv_hdr + 16, recv_iov)
memory.write_qword(recv_hdr + 24, 1)
memory.write_qword(recv_hdr + 32, recv_cmsg)
memory.write_qword(recv_hdr + 40, 64)

local rm_ok, rm_ret = pcall(function() return syscall.sc_recvmsg(fd1b, recv_hdr, 0) end)
if rm_ok then
    local received_fd = memory.read_dword(recv_cmsg + 16):tonumber()
    local cmsg_len = memory.read_dword(recv_cmsg):tonumber()
    local cmsg_level = memory.read_dword(recv_cmsg + 4):tonumber()
    local cmsg_type = memory.read_dword(recv_cmsg + 8):tonumber()
    log(string.format("  recvmsg: rv=%d cmsg_len=%d level=0x%x type=%d fd=%d",
        rm_ret:tonumber(), cmsg_len, cmsg_level, cmsg_type, received_fd))

    -- Test if the received fd works (write to it, read from its pair)
    if received_fd > 0 then
        local test_data = memory.alloc(8)
        memory.write_qword(test_data, 0xDEADBEEFCAFE1234)
        local wr_ok, wr_ret = pcall(function()
            return syscall.sc_write(received_fd, test_data, 8)
        end)
        log("  write to passed fd: " ..
            (wr_ok and "rv=" .. wr_ret:tonumber() or "ERR"))

        -- Read from fd2b (the other end of the passed fd's pair)
        local rd_buf = memory.alloc(8)
        local rd_ok, rd_ret = pcall(function()
            return syscall.sc_read(fd2b, rd_buf, 8)
        end)
        if rd_ok then
            local lo = memory.read_dword(rd_buf):tonumber()
            local hi = memory.read_dword(rd_buf + 4):tonumber()
            log(string.format("  read from pair: rv=%d data=0x%08x%08x",
                rd_ret:tonumber(), hi, lo))
        end
        pcall(function() syscall.sc_close(received_fd) end)
    end
else
    log("  recvmsg: ERR")
end

-- ============================================================
-- PART 3: dup2, fcntl, fstat
-- ============================================================
log("")
log("--- PART 3: fd operations ---")

-- dup
local dup_ok, dup_ret = pcall(function() return syscall.sc_dup(fd1a) end)
log("  dup(" .. fd1a .. "): " .. (dup_ok and "fd=" .. dup_ret:tonumber() or "ERR"))
if dup_ok then pcall(function() syscall.sc_close(dup_ret:tonumber()) end) end

-- dup2
local dup2_ok, dup2_ret = pcall(function() return syscall.sc_dup2(fd1a, 100) end)
log("  dup2(" .. fd1a .. ",100): " .. (dup2_ok and "rv=" .. dup2_ret:tonumber() or "ERR"))
if dup2_ok then pcall(function() syscall.sc_close(100) end) end

-- fcntl F_GETFL
local fcntl_ok, fcntl_ret = pcall(function() return syscall.sc_fcntl(fd1a, 3, 0) end) -- F_GETFL=3
log("  fcntl(GETFL): " .. (fcntl_ok and "flags=" .. fcntl_ret:tonumber() or "ERR"))

-- fcntl F_GETFD
local fcntl2_ok, fcntl2_ret = pcall(function() return syscall.sc_fcntl(fd1a, 1, 0) end) -- F_GETFD=1
log("  fcntl(GETFD): " .. (fcntl2_ok and "flags=" .. fcntl2_ret:tonumber() or "ERR"))

-- fstat
local stat_buf = memory.alloc(256)
local fstat_ok, fstat_ret = pcall(function() return syscall.sc_fstat(fd1a, stat_buf) end)
if fstat_ok then
    local dev = memory.read_dword(stat_buf):tonumber()
    local ino = memory.read_qword(stat_buf + 8):tonumber()
    local mode = memory.read_dword(stat_buf + 24):tonumber()
    log(string.format("  fstat: rv=%d dev=%d ino=%d mode=0x%x",
        fstat_ret:tonumber(), dev, ino, mode))
end

-- ============================================================
-- PART 4: Socket types
-- ============================================================
log("")
log("--- PART 4: socket types ---")

local sock_types = {
    {1, 1, 0, "AF_UNIX STREAM"},
    {1, 2, 0, "AF_UNIX DGRAM"},
    {2, 1, 0, "AF_INET STREAM"},
    {2, 2, 0, "AF_INET DGRAM"},
    {2, 3, 0, "AF_INET RAW"},
    {28, 1, 0, "AF_INET6 STREAM"},
    {28, 2, 0, "AF_INET6 DGRAM"},
    {28, 3, 0, "AF_INET6 RAW"},
    {18, 1, 0, "AF_LINK STREAM"},   -- link-layer
    {34, 2, 0, "AF_NETGRAPH DGRAM"}, -- netgraph
}

for _, st in ipairs(sock_types) do
    local s_ok, s_ret = pcall(function()
        return syscall.sc_socket(st[1], st[2], st[3])
    end)
    if s_ok then
        local fd = s_ret:tonumber()
        if fd >= 0 then
            log(string.format("  %-20s fd=%d", st[4], fd))
            pcall(function() syscall.sc_close(fd) end)
        else
            log(string.format("  %-20s rv=%d", st[4], fd))
        end
    else
        log(string.format("  %-20s ERR", st[4]))
    end
end

-- ============================================================
-- PART 5: shm_open, open special files
-- ============================================================
log("")
log("--- PART 5: shm + special files ---")

-- shm_open2 (FreeBSD 13+)
local shm_name = memory.alloc(32)
-- Write "/test_shm\0"
local name = "/test_shm"
for i = 1, #name do memory.write_byte(shm_name + i - 1, name:byte(i)) end
memory.write_byte(shm_name + #name, 0)

local shm_ok, shm_ret = pcall(function()
    return syscall.sc_shm_open2(shm_name, 0x0602, 0x1FF, 0, 0) -- O_RDWR|O_CREAT, 0777
end)
log("  shm_open2: " .. (shm_ok and "fd=" .. shm_ret:tonumber() or "ERR"))
if shm_ok and shm_ret:tonumber() >= 0 then
    pcall(function() syscall.sc_close(shm_ret:tonumber()) end)
    pcall(function() syscall.sc_shm_unlink(shm_name) end)
end

-- open /dev/null
local devnull = memory.alloc(16)
for i = 1, 9 do memory.write_byte(devnull + i - 1, ("/dev/null"):byte(i)) end
memory.write_byte(devnull + 9, 0)

local dn_ok, dn_ret = pcall(function() return syscall.sc_open(devnull, 2, 0) end) -- O_RDWR
log("  /dev/null: " .. (dn_ok and "fd=" .. dn_ret:tonumber() or "ERR"))
if dn_ok and dn_ret:tonumber() >= 0 then
    pcall(function() syscall.sc_close(dn_ret:tonumber()) end)
end

-- open /dev/zero
local devzero = memory.alloc(16)
for i = 1, 9 do memory.write_byte(devzero + i - 1, ("/dev/zero"):byte(i)) end
memory.write_byte(devzero + 9, 0)

local dz_ok, dz_ret = pcall(function() return syscall.sc_open(devzero, 0, 0) end) -- O_RDONLY
log("  /dev/zero: " .. (dz_ok and "fd=" .. dz_ret:tonumber() or "ERR"))
if dz_ok and dz_ret:tonumber() >= 0 then
    pcall(function() syscall.sc_close(dz_ret:tonumber()) end)
end

-- Cleanup
pcall(function() syscall.sc_close(fd1a) end)
pcall(function() syscall.sc_close(fd1b) end)
pcall(function() syscall.sc_close(fd2a) end)
pcall(function() syscall.sc_close(fd2b) end)

log("")
log("=== THREAD+FD DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
