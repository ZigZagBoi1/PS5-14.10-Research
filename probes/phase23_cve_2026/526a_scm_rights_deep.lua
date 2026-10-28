-- CRASH_CLASS: LOW
-- PROBE 526a: SCM_RIGHTS fd passing — deep discrimination test
--
-- Context: probe 56q found that SCM_RIGHTS fd passing via AF_UNIX
-- socketpair + sendmsg succeeds (ret=4) but recvmsg returns
-- controllen=0 — kernel strips fd-passing ancillary data in game jail.
--
-- BUT: DEM9N101 (PR #144) lists SCM_RIGHTS as a "confirmed prerequisite"
-- for the GHOST HANDLE chain (CVE-2019-5607). This is a contradiction.
--
-- This probe tests EVERY possible SCM_RIGHTS path to resolve it:
--   [A] SOCK_STREAM socketpair (56q used SOCK_DGRAM)
--   [B] SOCK_DGRAM socketpair (reproduce 56q)
--   [C] SOCK_SEQPACKET socketpair
--   [D] Larger control buffer sizes
--   [E] Multiple fds in one message
--   [F] sendmsg flags (MSG_DONTWAIT, MSG_NOSIGNAL)
--   [G] Child thread sending via ROP (different security context?)
--   [H] SCM_CREDS alongside SCM_RIGHTS
--
-- If ANY path delivers an fd, the GHOST HANDLE chain is viable.
-- If ALL paths strip, CVE-2019-5607 is dead on 14.10.

print("=== PROBE 526a: SCM_RIGHTS deep discrimination ===")
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
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
local sc_write      = make_syscall(4)
local sc_read       = make_syscall(3)

local AF_UNIX = 1
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCK_SEQPACKET = 5
local SOL_SOCKET = 0xFFFF
local SCM_RIGHTS = 1
local SCM_CREDS = 3
local LOCAL_CREDS = 2

local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end

-- Helper: build and send SCM_RIGHTS, then receive and check
-- Returns: recv_ret, controllen_after, received_fd (or nil)
local function test_scm_rights(sock_type, sock_type_name, fd_to_send, extra_flags, ctrl_size, set_local_creds)
    -- create socketpair
    local sv = memory.alloc(16)
    zero_buf(sv, 16)
    local ok, ret = pcall(function()
        return sc_socketpair(uint64(AF_UNIX), uint64(sock_type), uint64(0), uint64(to_num(sv)))
    end)
    local rv = ok and to_num(ret) or -999
    if rv ~= 0 then
        print(string.format("  socketpair(%s): ret=%d — FAILED", sock_type_name, rv))
        return nil, nil, nil
    end
    local fd0 = safe_rd(sv)
    local fd1 = safe_rd(sv + 4)
    print(string.format("  socketpair(%s): ret=0, fd0=%d, fd1=%d", sock_type_name, fd0 or -1, fd1 or -1))

    if not fd0 or not fd1 then
        return nil, nil, nil
    end

    -- optionally set LOCAL_CREDS on receiver
    if set_local_creds then
        local one = memory.alloc(4)
        safe_wd(one, 1)
        pcall(function()
            sc_setsockopt(uint64(fd1), uint64(0), uint64(LOCAL_CREDS), uint64(to_num(one)), uint64(4))
        end)
    end

    -- Build sendmsg structures
    -- struct msghdr {
    --   void *msg_name;        +0x00 (8)
    --   socklen_t msg_namelen; +0x08 (4) + 4 pad
    --   struct iovec *msg_iov; +0x10 (8)
    --   int msg_iovlen;        +0x18 (4) + 4 pad (size_t on 64-bit = 8 bytes actually)
    --   void *msg_control;     +0x20 (8)
    --   socklen_t msg_controllen; +0x28 (4) + 4 pad (socklen_t on 64-bit)
    --   int msg_flags;         +0x30 (4)
    -- }
    -- Total: 0x38 bytes (on amd64 FreeBSD)
    --
    -- Actually on FreeBSD amd64:
    -- msg_name:     +0x00 (8)
    -- msg_namelen:  +0x08 (4, but aligned to 8)
    -- msg_iov:      +0x10 (8)
    -- msg_iovlen:   +0x18 (8, it's size_t on 64-bit)
    -- msg_control:  +0x20 (8)
    -- msg_controllen: +0x28 (4, socklen_t)
    -- msg_flags:    +0x2C (4)
    -- Total: 0x30

    local msghdr_send = memory.alloc(0x40)
    local iov_send = memory.alloc(0x10)
    local data_send = memory.alloc(8)
    local cmsg_send = memory.alloc(0x40)

    zero_buf(msghdr_send, 0x40)
    zero_buf(iov_send, 0x10)
    zero_buf(data_send, 8)
    zero_buf(cmsg_send, 0x40)

    -- data to send
    safe_wd(data_send, 0x41424344) -- "ABCD"

    -- iov: {base, len}
    safe_wq(iov_send, uint64(to_num(data_send)))
    safe_wq(iov_send + 8, uint64(4))

    -- cmsg header: {cmsg_len, cmsg_level, cmsg_type, [fd]}
    -- struct cmsghdr on FreeBSD amd64:
    --   socklen_t cmsg_len;   +0x00 (4)
    --   int cmsg_level;       +0x04 (4)
    --   int cmsg_type;        +0x08 (4)
    --   /* data follows */    +0x0C
    -- CMSG_LEN(sizeof(int)) = 16 on 64-bit (12 header + 4 data)
    -- Actually: CMSG_LEN = CMSG_ALIGN(sizeof(struct cmsghdr)) + datalen
    -- On FreeBSD amd64, CMSG_ALIGN rounds up to 8
    -- sizeof(struct cmsghdr) = 12, CMSG_ALIGN(12) = 16
    -- So CMSG_LEN(4) = 16 + 4 = 20
    -- CMSG_SPACE(4) = CMSG_ALIGN(20) = 24
    local CMSG_HDR_SIZE = 12  -- actual struct size
    local CMSG_ALIGN_HDR = 16 -- aligned
    local cmsg_len = CMSG_ALIGN_HDR + 4  -- 20 for one fd
    local cmsg_space = 24  -- CMSG_SPACE(4) = align(20) = 24

    safe_wd(cmsg_send + 0, cmsg_len)       -- cmsg_len
    safe_wd(cmsg_send + 4, SOL_SOCKET)     -- cmsg_level = SOL_SOCKET (0xFFFF)
    safe_wd(cmsg_send + 8, SCM_RIGHTS)     -- cmsg_type = SCM_RIGHTS (1)
    safe_wd(cmsg_send + CMSG_ALIGN_HDR, fd_to_send) -- the fd

    -- Fill msghdr_send
    -- msg_name = NULL
    -- msg_namelen = 0
    safe_wq(msghdr_send + 0x10, uint64(to_num(iov_send)))  -- msg_iov
    safe_wq(msghdr_send + 0x18, uint64(1))                  -- msg_iovlen
    safe_wq(msghdr_send + 0x20, uint64(to_num(cmsg_send)))  -- msg_control
    safe_wd(msghdr_send + 0x28, cmsg_space)                  -- msg_controllen

    -- Send
    local send_flags = extra_flags or 0
    ok, ret = pcall(function()
        return sc_sendmsg(uint64(fd0), uint64(to_num(msghdr_send)), uint64(send_flags))
    end)
    local send_rv = ok and to_num(ret) or -999
    print(string.format("  sendmsg: ret=%d%s", send_rv, ok and "" or " [PCALL-FAIL]"))

    if send_rv < 0 then
        pcall(function() sc_close(uint64(fd0)) end)
        pcall(function() sc_close(uint64(fd1)) end)
        return send_rv, nil, nil
    end

    -- Receive
    local msghdr_recv = memory.alloc(0x40)
    local iov_recv = memory.alloc(0x10)
    local data_recv = memory.alloc(8)
    local actual_ctrl_size = ctrl_size or 256
    local cmsg_recv = memory.alloc(actual_ctrl_size + 32)

    zero_buf(msghdr_recv, 0x40)
    zero_buf(iov_recv, 0x10)
    zero_buf(data_recv, 8)
    -- Fill recv cmsg with sentinel
    for j = 0, actual_ctrl_size + 31, 4 do
        safe_wd(cmsg_recv + j, 0xDEADBEEF)
    end

    safe_wq(iov_recv, uint64(to_num(data_recv)))
    safe_wq(iov_recv + 8, uint64(4))

    safe_wq(msghdr_recv + 0x10, uint64(to_num(iov_recv)))   -- msg_iov
    safe_wq(msghdr_recv + 0x18, uint64(1))                   -- msg_iovlen
    safe_wq(msghdr_recv + 0x20, uint64(to_num(cmsg_recv)))   -- msg_control
    safe_wd(msghdr_recv + 0x28, actual_ctrl_size)             -- msg_controllen

    ok, ret = pcall(function()
        return sc_recvmsg(uint64(fd1), uint64(to_num(msghdr_recv)), uint64(0))
    end)
    local recv_rv = ok and to_num(ret) or -999
    local controllen_after = safe_rd(msghdr_recv + 0x28) or 0
    local msg_flags_after = safe_rd(msghdr_recv + 0x2C) or 0

    print(string.format("  recvmsg: ret=%d, controllen=%d, msg_flags=0x%X",
        recv_rv, controllen_after, msg_flags_after))

    -- Check received data
    local recv_data = safe_rd(data_recv)
    print(string.format("  recv data: 0x%08X %s", recv_data or 0,
        (recv_data == 0x41424344) and "(ABCD OK)" or "(MISMATCH)"))

    -- Check if cmsg arrived
    local received_fd = nil
    if controllen_after > 0 then
        local c_len = safe_rd(cmsg_recv + 0)
        local c_level = safe_rd(cmsg_recv + 4)
        local c_type = safe_rd(cmsg_recv + 8)
        print(string.format("  *** CMSG PRESENT: len=%d, level=0x%X, type=%d ***",
            c_len or 0, c_level or 0, c_type or 0))

        if c_type == SCM_RIGHTS then
            received_fd = safe_rd(cmsg_recv + CMSG_ALIGN_HDR)
            print(string.format("  *** SCM_RIGHTS FD RECEIVED: %d ***", received_fd or -1))

            -- Verify the fd works by fstat
            if received_fd and received_fd >= 0 then
                local stat_buf = memory.alloc(256)
                zero_buf(stat_buf, 256)
                local fok, fret = pcall(function()
                    return sc_fstat(uint64(received_fd), uint64(to_num(stat_buf)))
                end)
                local fstat_rv = fok and to_num(fret) or -999
                print(string.format("  *** fstat(received_fd=%d): ret=%d ***",
                    received_fd, fstat_rv))
                if fstat_rv == 0 then
                    local mode = safe_rd(stat_buf + 8) -- st_mode at offset 8 in freebsd stat
                    print(string.format("  *** WORKING FD! mode=0x%04X ***", mode or 0))
                end
            end
        elseif c_type == SCM_CREDS then
            print("  (SCM_CREDS received, not SCM_RIGHTS)")
        else
            print(string.format("  (unknown cmsg type %d)", c_type or 0))
        end

        -- Dump first 64 bytes of cmsg for analysis
        print("  cmsg raw dump:")
        for off = 0, math.min(controllen_after, 64) - 1, 4 do
            local v = safe_rd(cmsg_recv + off)
            if v and v ~= 0xDEADBEEF then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
    else
        -- Check if sentinel was overwritten even though controllen=0
        local first_word = safe_rd(cmsg_recv)
        if first_word ~= 0xDEADBEEF then
            print(string.format("  controllen=0 BUT sentinel changed: 0x%08X", first_word))
        else
            print("  NO cmsg data (stripped)")
        end
    end

    -- Cleanup
    if received_fd and received_fd >= 0 then
        pcall(function() sc_close(uint64(received_fd)) end)
    end
    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)

    return recv_rv, controllen_after, received_fd
end

-- Get a real fd to pass
local path_buf = memory.alloc(64)
-- "/dev/rng\0"
safe_wd(path_buf, 0x7665642F)     -- "/dev"
safe_wd(path_buf + 4, 0x676E722F) -- "/rng"
safe_wd(path_buf + 8, 0)

local ok_open, test_fd_raw = pcall(function()
    return sc_open(uint64(to_num(path_buf)), uint64(0), uint64(0))  -- O_RDONLY
end)
local test_fd = ok_open and to_num(test_fd_raw) or -1
print("test fd (/dev/rng): " .. test_fd)

if test_fd < 0 then
    -- try opening eboot
    -- "/app0/eboot.bin\0"
    safe_wd(path_buf, 0x7070612F)      -- "/app"
    safe_wd(path_buf + 4, 0x62652F30)  -- "0/eb"
    safe_wd(path_buf + 8, 0x2E746F6F)  -- "oot."
    safe_wd(path_buf + 12, 0x006E6962) -- "bin\0"
    ok_open, test_fd_raw = pcall(function()
        return sc_open(uint64(to_num(path_buf)), uint64(0), uint64(0))
    end)
    test_fd = ok_open and to_num(test_fd_raw) or -1
    print("test fd (/app0/eboot.bin): " .. test_fd)
end

if test_fd < 0 then
    test_fd = 0 -- fallback: try passing stdin
    print("WARNING: using fd 0 (stdin) as test fd")
end

-- ============================================================
-- [A] SOCK_STREAM socketpair
-- ============================================================
print("")
print("[A] SOCK_STREAM socketpair — SCM_RIGHTS")
test_scm_rights(SOCK_STREAM, "SOCK_STREAM", test_fd, 0, 256, false)

-- ============================================================
-- [B] SOCK_DGRAM socketpair (reproduce 56q)
-- ============================================================
print("")
print("[B] SOCK_DGRAM socketpair — SCM_RIGHTS (reproduce 56q)")
test_scm_rights(SOCK_DGRAM, "SOCK_DGRAM", test_fd, 0, 256, false)

-- ============================================================
-- [C] SOCK_SEQPACKET socketpair
-- ============================================================
print("")
print("[C] SOCK_SEQPACKET socketpair — SCM_RIGHTS")
test_scm_rights(SOCK_SEQPACKET, "SOCK_SEQPACKET", test_fd, 0, 256, false)

-- ============================================================
-- [D] Larger control buffer (1024, 4096)
-- ============================================================
print("")
print("[D] SOCK_STREAM with large control buffers")
print("  --- ctrl_size=1024 ---")
test_scm_rights(SOCK_STREAM, "STREAM/1024", test_fd, 0, 1024, false)
print("  --- ctrl_size=4096 ---")
test_scm_rights(SOCK_STREAM, "STREAM/4096", test_fd, 0, 4096, false)

-- ============================================================
-- [E] Multiple fds (pass 3 fds at once)
-- ============================================================
print("")
print("[E] Multiple fds in SCM_RIGHTS (3 fds)")
do
    local sv = memory.alloc(16)
    zero_buf(sv, 16)
    local ok_sp, ret_sp = pcall(function()
        return sc_socketpair(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0), uint64(to_num(sv)))
    end)
    local rv_sp = ok_sp and to_num(ret_sp) or -999
    if rv_sp == 0 then
        local fd0 = safe_rd(sv)
        local fd1 = safe_rd(sv + 4)

        -- Build cmsg with 3 fds
        local msghdr = memory.alloc(0x40)
        local iov = memory.alloc(0x10)
        local data = memory.alloc(8)
        -- CMSG_SPACE(12) = CMSG_ALIGN(16+12) = CMSG_ALIGN(28) = 32
        local cmsg = memory.alloc(64)

        zero_buf(msghdr, 0x40)
        zero_buf(iov, 0x10)
        zero_buf(data, 8)
        zero_buf(cmsg, 64)

        safe_wd(data, 0x44434241) -- "ABCD"
        safe_wq(iov, uint64(to_num(data)))
        safe_wq(iov + 8, uint64(4))

        -- cmsg for 3 fds: len = 16 + 12 = 28
        safe_wd(cmsg + 0, 16 + 12)       -- cmsg_len = header_aligned + 3*4
        safe_wd(cmsg + 4, SOL_SOCKET)
        safe_wd(cmsg + 8, SCM_RIGHTS)
        safe_wd(cmsg + 16, test_fd)       -- fd 1
        safe_wd(cmsg + 20, test_fd)       -- fd 2
        safe_wd(cmsg + 24, test_fd)       -- fd 3

        safe_wq(msghdr + 0x10, uint64(to_num(iov)))
        safe_wq(msghdr + 0x18, uint64(1))
        safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))
        safe_wd(msghdr + 0x28, 32)  -- CMSG_SPACE(12)

        local ok_s, ret_s = pcall(function()
            return sc_sendmsg(uint64(fd0), uint64(to_num(msghdr)), uint64(0))
        end)
        print(string.format("  sendmsg(3 fds): ret=%d", ok_s and to_num(ret_s) or -999))

        -- Receive
        local msghdr_r = memory.alloc(0x40)
        local iov_r = memory.alloc(0x10)
        local data_r = memory.alloc(8)
        local cmsg_r = memory.alloc(256)
        zero_buf(msghdr_r, 0x40)
        zero_buf(iov_r, 0x10)
        for j = 0, 255, 4 do safe_wd(cmsg_r + j, 0xDEADBEEF) end

        safe_wq(iov_r, uint64(to_num(data_r)))
        safe_wq(iov_r + 8, uint64(4))
        safe_wq(msghdr_r + 0x10, uint64(to_num(iov_r)))
        safe_wq(msghdr_r + 0x18, uint64(1))
        safe_wq(msghdr_r + 0x20, uint64(to_num(cmsg_r)))
        safe_wd(msghdr_r + 0x28, 256)

        local ok_r, ret_r = pcall(function()
            return sc_recvmsg(uint64(fd1), uint64(to_num(msghdr_r)), uint64(0))
        end)
        local ctl = safe_rd(msghdr_r + 0x28) or 0
        print(string.format("  recvmsg(3 fds): ret=%d, controllen=%d",
            ok_r and to_num(ret_r) or -999, ctl))

        if ctl > 0 then
            local c_type = safe_rd(cmsg_r + 8) or 0
            print(string.format("  *** CMSG type=%d, len=%d ***",
                c_type, safe_rd(cmsg_r) or 0))
            if c_type == SCM_RIGHTS then
                local f1 = safe_rd(cmsg_r + 16)
                local f2 = safe_rd(cmsg_r + 20)
                local f3 = safe_rd(cmsg_r + 24)
                print(string.format("  *** 3 FDS RECEIVED: %d, %d, %d ***",
                    f1 or -1, f2 or -1, f3 or -1))
            end
        else
            local first = safe_rd(cmsg_r)
            print(string.format("  NO cmsg (sentinel: 0x%08X)", first or 0))
        end

        pcall(function() sc_close(uint64(fd0)) end)
        pcall(function() sc_close(uint64(fd1)) end)
    else
        print("  socketpair failed: " .. rv_sp)
    end
end

-- ============================================================
-- [F] MSG_DONTWAIT and MSG_NOSIGNAL flags
-- ============================================================
print("")
print("[F] Send flags: MSG_DONTWAIT(0x80), MSG_NOSIGNAL(0x20000)")
print("  --- MSG_DONTWAIT ---")
test_scm_rights(SOCK_STREAM, "STREAM/DONTWAIT", test_fd, 0x80, 256, false)
print("  --- MSG_NOSIGNAL ---")
test_scm_rights(SOCK_STREAM, "STREAM/NOSIGNAL", test_fd, 0x20000, 256, false)

-- ============================================================
-- [G] With LOCAL_CREDS on receiver
-- ============================================================
print("")
print("[G] SOCK_DGRAM with LOCAL_CREDS set on receiver")
test_scm_rights(SOCK_DGRAM, "DGRAM/LOCALCREDS", test_fd, 0, 256, true)

-- ============================================================
-- [H] Try passing a socketpair fd (not a file fd)
-- ============================================================
print("")
print("[H] Pass a socket fd (not a file fd)")
do
    -- create a separate socket to pass
    local sv2 = memory.alloc(16)
    zero_buf(sv2, 16)
    local ok2, ret2 = pcall(function()
        return sc_socketpair(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0), uint64(to_num(sv2)))
    end)
    if ok2 and to_num(ret2) == 0 then
        local pass_fd = safe_rd(sv2) or 0
        print("  socket fd to pass: " .. pass_fd)
        test_scm_rights(SOCK_STREAM, "STREAM/sock-fd", pass_fd, 0, 256, false)
        pcall(function() sc_close(uint64(safe_rd(sv2) or 0)) end)
        pcall(function() sc_close(uint64(safe_rd(sv2 + 4) or 0)) end)
    end
end

-- ============================================================
-- [I] Summary
-- ============================================================
print("")
print("[I] SUMMARY")
print("If ANY test above shows 'SCM_RIGHTS FD RECEIVED' or controllen>0")
print("with cmsg type=1, then fd passing WORKS and GHOST HANDLE chain is VIABLE.")
print("If ALL show controllen=0, kernel strips SCM_RIGHTS in game jail — chain DEAD.")

-- cleanup
if test_fd > 2 then
    pcall(function() sc_close(uint64(test_fd)) end)
end

local pid2 = to_num(sc20())
print("")
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 526a COMPLETE ===")
