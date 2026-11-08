-- CRASH_CLASS: MODERATE
-- PROBE 1101a: pipe2 + sendfile race — untested syscalls and concurrent fd operations
--
-- Context: pipe(42) via make_syscall returns fds 0,0 (dead). pipe2(542) was never
-- tested. If pipe2 works, we get kernel pipe buffer objects. Combined with sendfile
-- racing ftruncate on a shm fd, we stress the vnode pager and pipe buffer paths.
--
-- Tests:
-- A) pipe2(542) basic functionality
-- B) sendfile(393) with connected TCP socket (previous tests used unconnected)
-- C) sendfile racing ftruncate on same shm fd from child thread

print("=== PROBE 1101a: PIPE2 + SENDFILE RACE ===")
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

local sc_pid = make_syscall(20)
local pid = to_num(sc_pid())
print(string.format("[0] pid=%d", pid))

-- ============================================================
-- SECTION A: pipe2(542) test
-- ============================================================
print("")
print("--- SECTION A: pipe2(542) ---")

local pipe_buf = memory.alloc(16)
safe_wd(pipe_buf, 0)
safe_wd(pipe_buf + 4, 0)

-- pipe2(int fildes[2], int flags)
-- flags: O_CLOEXEC=0x100000, O_NONBLOCK=4
local sc_pipe2 = make_syscall(542)

-- Try with flags=0
local ret = to_num(sc_pipe2(uint64(to_num(pipe_buf)), uint64(0)))
local fd_r = safe_rd(pipe_buf)
local fd_w = safe_rd(pipe_buf + 4)
print(string.format("[A1] pipe2(0): ret=%d fds=[%d, %d]", ret, fd_r or -1, fd_w or -1))

if ret == 0 and (fd_r or 0) > 0 and (fd_w or 0) > 0 then
    print("[A1] pipe2 WORKS!")

    -- Test write/read on the pipe
    local wbuf = memory.alloc(64)
    safe_wq(wbuf, uint64(0xDEADBEEFCAFE1234))
    local sc_write = make_syscall(4)
    local sc_read = make_syscall(3)

    local wret = to_num(sc_write(uint64(fd_w), uint64(to_num(wbuf)), uint64(8)))
    print(string.format("[A2] write(%d, 8): ret=%d", fd_w, wret))

    local rbuf = memory.alloc(64)
    safe_wq(rbuf, uint64(0))
    local rret = to_num(sc_read(uint64(fd_r), uint64(to_num(rbuf)), uint64(8)))
    local rval = safe_rq(rbuf)
    local rh, rl = get_hi_lo(rval)
    print(string.format("[A3] read(%d, 8): ret=%d val=0x%08X%08X", fd_r, rret, rh, rl))

    if rh == 0xDEADBEEF and rl == 0xCAFE1234 then
        print("[A3] pipe data round-trip CONFIRMED")
    end

    -- Try O_NONBLOCK
    safe_wd(pipe_buf, 0)
    safe_wd(pipe_buf + 4, 0)
    local ret2 = to_num(sc_pipe2(uint64(to_num(pipe_buf)), uint64(4)))
    local fd_r2 = safe_rd(pipe_buf)
    local fd_w2 = safe_rd(pipe_buf + 4)
    print(string.format("[A4] pipe2(O_NONBLOCK): ret=%d fds=[%d, %d]", ret2, fd_r2 or -1, fd_w2 or -1))

    -- Close test fds
    local sc_close = make_syscall(6)
    sc_close(uint64(fd_r))
    sc_close(uint64(fd_w))
    if ret2 == 0 then
        sc_close(uint64(fd_r2))
        sc_close(uint64(fd_w2))
    end
else
    print("[A1] pipe2 failed or returned bad fds")
end

-- ============================================================
-- SECTION B: sendfile with connected loopback socket
-- ============================================================
print("")
print("--- SECTION B: sendfile with connected socket ---")

-- Create shm object as sendfile source
local sc_shm = make_syscall(482)
local SHM_ANON = uint64(1)
local shm_fd = to_num(sc_shm(SHM_ANON, uint64(0x602), uint64(0x1FF)))
print(string.format("[B1] shm_open fd=%d", shm_fd))

if shm_fd >= 0 then
    -- ftruncate to 64KB (4 pages)
    local sc_ftrunc = make_syscall(480)
    local tr = to_num(sc_ftrunc(uint64(shm_fd), uint64(0x10000)))
    print(string.format("[B2] ftruncate ret=%d", tr))

    -- mmap and write pattern
    local sc_mmap = make_syscall(477)
    local shm_map = sc_mmap(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    print(string.format("[B3] mmap=%s", tostring(shm_map)))

    for i = 0, 3 do
        safe_wd(shm_map + uint64(i * 0x4000), 0xBEEF0000 + i)
    end

    -- Create loopback socketpair for sendfile destination
    local sc_socketpair = make_syscall(135)
    local spair = memory.alloc(16)
    safe_wd(spair, 0)
    safe_wd(spair + 4, 0)
    local sp_ret = to_num(sc_socketpair(uint64(1), uint64(2), uint64(0), uint64(to_num(spair))))
    -- AF_UNIX=1, SOCK_DGRAM=2
    local sock_a = safe_rd(spair)
    local sock_b = safe_rd(spair + 4)
    print(string.format("[B4] socketpair: ret=%d fds=[%d, %d]", sp_ret, sock_a or -1, sock_b or -1))

    if sp_ret == 0 then
        -- sendfile(shm_fd -> sock_a)
        local sc_sendfile = make_syscall(393)
        local sbytes_ptr = memory.alloc(8)
        safe_wq(sbytes_ptr, uint64(0))

        -- sendfile(fd, s, offset, nbytes, hdtr, sbytes, flags)
        -- fd = source file fd, s = socket fd
        local sf_ret = to_num(sc_sendfile(uint64(shm_fd), uint64(sock_a), uint64(0), uint64(0x4000), uint64(0), uint64(to_num(sbytes_ptr))))
        local sbytes = safe_rq(sbytes_ptr)
        local sb_h, sb_l = get_hi_lo(sbytes)
        print(string.format("[B5] sendfile(shm->sock, 0x4000): ret=%d sbytes=0x%08X%08X", sf_ret, sb_h, sb_l))

        -- Read from other end
        if sf_ret == 0 or sb_l > 0 then
            local recv_buf = memory.alloc(0x4000)
            for i = 0, 0xFFF do safe_wd(recv_buf + i*4, 0) end
            local sc_read = make_syscall(3)
            local rr = to_num(sc_read(uint64(sock_b), uint64(to_num(recv_buf)), uint64(0x4000)))
            local first_word = safe_rd(recv_buf)
            print(string.format("[B6] read(sock_b): ret=%d first_dword=0x%08X", rr, first_word or 0))

            -- Scan received data for kernel pointers
            local kptrs = 0
            for i = 0, (rr or 0) / 8 - 1 do
                local val = safe_rq(recv_buf + uint64(i * 8))
                if val then
                    local h, l = get_hi_lo(val)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        print(string.format("  [KPTR!] offset %d: 0x%08X%08X", i*8, h, l))
                    end
                end
            end
            print(string.format("[B7] kptrs in sendfile data: %d", kptrs))
        end

        local sc_close = make_syscall(6)
        sc_close(uint64(sock_a))
        sc_close(uint64(sock_b))
    end

    -- Unmap and close shm
    local sc_munmap = make_syscall(73)
    sc_munmap(uint64(to_num(shm_map)), uint64(0x10000))
    local sc_close = make_syscall(6)
    sc_close(uint64(shm_fd))
end

-- ============================================================
-- SECTION C: writev with large iovec
-- ============================================================
print("")
print("--- SECTION C: writev with large iovec ---")

-- writev(fd, iov, iovcnt) - syscall 121
-- Large iovcnt values may trigger kernel stack allocation vs heap allocation
-- FreeBSD IOV_MAX is 1024; values above that should fail, values near the
-- boundary may trigger different allocation paths

local sc_writev = make_syscall(121)
local sc_socketpair2 = make_syscall(135)
local spair2 = memory.alloc(16)
safe_wd(spair2, 0)
safe_wd(spair2 + 4, 0)
local sp2_ret = to_num(sc_socketpair2(uint64(1), uint64(1), uint64(0), uint64(to_num(spair2))))
local s2a = safe_rd(spair2)
local s2b = safe_rd(spair2 + 4)
print(string.format("[C1] socketpair: ret=%d fds=[%d, %d]", sp2_ret, s2a or -1, s2b or -1))

if sp2_ret == 0 then
    -- Build iovec array: each entry is {base, len} = 16 bytes
    local data_buf = memory.alloc(0x1000)
    safe_wq(data_buf, uint64(0x4141414141414141))

    local test_counts = {1, 16, 128, 512, 1024, 1025, 2048, 4096}
    for _, cnt in ipairs(test_counts) do
        -- Allocate iovec array
        local iov_size = cnt * 16
        if iov_size <= 0x100000 then -- max 1MB for iovec array
            local iov = memory.alloc(iov_size)
            for i = 0, cnt - 1 do
                safe_wq(iov + uint64(i * 16), uint64(to_num(data_buf)))
                safe_wq(iov + uint64(i * 16 + 8), uint64(1))
            end

            local ok, wret = pcall(function()
                return to_num(sc_writev(uint64(s2a), uint64(to_num(iov)), uint64(cnt)))
            end)
            if ok then
                print(string.format("[C2] writev(iovcnt=%d): ret=%d", cnt, wret))
            else
                print(string.format("[C2] writev(iovcnt=%d): PCALL_FAIL", cnt))
            end
        end
    end

    local sc_close = make_syscall(6)
    sc_close(uint64(s2a))
    sc_close(uint64(s2b))
end

-- ============================================================
-- SECTION D: Device read/write quick sweep
-- ============================================================
print("")
print("--- SECTION D: device read/write ---")

local sc_open = make_syscall(5)
local sc_read = make_syscall(3)
local sc_close = make_syscall(6)

local devices = {"/dev/rng", "/dev/urandom", "/dev/random", "/dev/notification0", "/dev/notification1"}
local read_buf = memory.alloc(0x1000)

for _, dev in ipairs(devices) do
    -- Write device path
    local path_buf = memory.alloc(64)
    for i = 1, #dev do
        safe_wd(path_buf + (i-1), string.byte(dev, i))
    end
    safe_wd(path_buf + #dev, 0)

    local fd = to_num(sc_open(uint64(to_num(path_buf)), uint64(0), uint64(0)))
    if fd >= 0 then
        -- Zero read buffer
        for i = 0, 0xFF do safe_wd(read_buf + i*4, 0) end

        local ok, rr = pcall(function()
            return to_num(sc_read(uint64(fd), uint64(to_num(read_buf)), uint64(256)))
        end)

        if ok then
            -- Check for kernel pointers in output
            local kptrs = 0
            local nonzero = 0
            for i = 0, 31 do
                local val = safe_rq(read_buf + uint64(i * 8))
                if val then
                    local h, l = get_hi_lo(val)
                    if h ~= 0 or l ~= 0 then nonzero = nonzero + 1 end
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptrs = kptrs + 1
                    end
                end
            end
            print(string.format("[D] %s fd=%d read=%d nonzero_qwords=%d kptrs=%d", dev, fd, rr, nonzero, kptrs))
        else
            print(string.format("[D] %s fd=%d read=PCALL_FAIL", dev, fd))
        end
        sc_close(uint64(fd))
    else
        print(string.format("[D] %s open=%d", dev, fd))
    end
end

-- Alive check
local alive = to_num(sc_pid())
print(string.format("\n[E] alive pid=%d", alive))
print("")
print("=== PROBE 1101a COMPLETE ===")
