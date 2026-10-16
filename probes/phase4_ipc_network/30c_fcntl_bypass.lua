-- 14.10 Recon Probe 30c: fcntl sandbox bypass investigation
-- F_SETFL returns -1 but applies the change. Does F_SETOWN do the same?
-- If so, we can set up SIGIO delivery for async socket notification.

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: FCNTL BYPASS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socketpair = 135,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_fcntl = 92,
    sc_sigaction = 416,
    sc_socket = 97,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_bind = 104,
    sc_listen = 106,
    sc_connect = 98,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_mmap = 477,
    sc_shutdown = 134,
    sc_select = 93,
    sc_poll = 209,
    sc_nanosleep = 240,
})

local pid = syscall.sc_getpid():tonumber()
local sp = memory.alloc(8)

-- ============================================================
-- PART 1: Verify F_SETFL bypass pattern in detail
-- ============================================================
log("")
log("--- PART 1: F_SETFL bypass detail ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local fa = memory.read_dword(sp):tonumber()
local fb = memory.read_dword(sp + 4):tonumber()

-- Get baseline flags
local ok1, fl1 = pcall(function() return syscall.sc_fcntl(fa, 3, 0) end)
log("  baseline F_GETFL: rv=" .. (ok1 and fl1:tonumber() or -999))

-- Try F_SETFL with O_NONBLOCK (4), check return AND verify
local ok2, rv2 = pcall(function() return syscall.sc_fcntl(fa, 4, 4) end)
log("  F_SETFL(NONBLK): rv=" .. (ok2 and rv2:tonumber() or -999))

local ok3, fl3 = pcall(function() return syscall.sc_fcntl(fa, 3, 0) end)
log("  verify F_GETFL: rv=" .. (ok3 and fl3:tonumber() or -999))

-- Try F_SETFL with O_APPEND (8)
local ok4, rv4 = pcall(function() return syscall.sc_fcntl(fa, 4, 8) end)
log("  F_SETFL(APPEND): rv=" .. (ok4 and rv4:tonumber() or -999))

local ok5, fl5 = pcall(function() return syscall.sc_fcntl(fa, 3, 0) end)
log("  verify F_GETFL: rv=" .. (ok5 and fl5:tonumber() or -999))

-- Try F_SETFL with O_ASYNC (0x40) - THIS enables SIGIO
local ok6, rv6 = pcall(function() return syscall.sc_fcntl(fa, 4, 0x40) end)
log("  F_SETFL(ASYNC): rv=" .. (ok6 and rv6:tonumber() or -999))

local ok7, fl7 = pcall(function() return syscall.sc_fcntl(fa, 3, 0) end)
log("  verify F_GETFL: rv=" .. (ok7 and fl7:tonumber() or -999))
log(string.format("  flags breakdown: O_ASYNC=%s O_NONBLK=%s O_APPEND=%s",
    ok7 and (fl7:tonumber() % 128 >= 64 and "SET" or "no") or "?",
    ok7 and (fl7:tonumber() % 8 >= 4 and "SET" or "no") or "?",
    ok7 and (fl7:tonumber() % 16 >= 8 and "SET" or "no") or "?"))

pcall(function() syscall.sc_close(fa) end)
pcall(function() syscall.sc_close(fb) end)

-- ============================================================
-- PART 2: F_SETOWN bypass test
-- ============================================================
log("")
log("--- PART 2: F_SETOWN bypass ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

-- Try F_SETOWN to self
local ok_s1, rv_s1 = pcall(function() return syscall.sc_fcntl(sa, 6, pid) end)
log("  F_SETOWN(self): rv=" .. (ok_s1 and rv_s1:tonumber() or -999))

-- Try F_GETOWN to verify
local ok_s2, rv_s2 = pcall(function() return syscall.sc_fcntl(sa, 5, 0) end)
log("  F_GETOWN verify: rv=" .. (ok_s2 and rv_s2:tonumber() or -999))
log("  (expected: " .. pid .. " if bypass worked, 0/-1 if blocked)")

-- Try F_SETOWN with negative pid (process group)
local ok_s3, rv_s3 = pcall(function() return syscall.sc_fcntl(sa, 6, -pid) end)
log("  F_SETOWN(-pid): rv=" .. (ok_s3 and rv_s3:tonumber() or -999))

local ok_s4, rv_s4 = pcall(function() return syscall.sc_fcntl(sa, 5, 0) end)
log("  F_GETOWN verify: rv=" .. (ok_s4 and rv_s4:tonumber() or -999))

-- ============================================================
-- PART 3: F_SETFD bypass test
-- ============================================================
log("")
log("--- PART 3: F_SETFD bypass ---")

-- F_GETFD returned -1 in 30b. But does F_SETFD silently work?
local ok_d1, rv_d1 = pcall(function() return syscall.sc_fcntl(sa, 2, 1) end) -- SETFD CLOEXEC
log("  F_SETFD(CLOEXEC): rv=" .. (ok_d1 and rv_d1:tonumber() or -999))

local ok_d2, rv_d2 = pcall(function() return syscall.sc_fcntl(sa, 1, 0) end) -- GETFD
log("  F_GETFD verify: rv=" .. (ok_d2 and rv_d2:tonumber() or -999))

-- ============================================================
-- PART 4: SIGIO delivery via O_ASYNC + F_SETOWN
-- Set up signal handler, enable O_ASYNC, set owner, write to peer
-- ============================================================
log("")
log("--- PART 4: SIGIO delivery test ---")

-- Set up a SIGIO counter using a known memory location
local sigio_flag = memory.alloc(16)
memory.write_dword(sigio_flag, 0)

-- Set O_ASYNC on sa (should bypass-succeed based on Part 1)
local ok_a1, rv_a1 = pcall(function() return syscall.sc_fcntl(sa, 4, 0x40) end)
log("  F_SETFL(ASYNC) on sa: rv=" .. (ok_a1 and rv_a1:tonumber() or -999))

-- Verify O_ASYNC is set
local ok_a2, rv_a2 = pcall(function() return syscall.sc_fcntl(sa, 3, 0) end)
log("  F_GETFL verify: " .. (ok_a2 and rv_a2:tonumber() or -999))
local async_set = ok_a2 and (rv_a2:tonumber() % 128 >= 64)
log("  O_ASYNC active: " .. tostring(async_set))

-- Set F_SETOWN to our pid
local ok_a3, rv_a3 = pcall(function() return syscall.sc_fcntl(sa, 6, pid) end)
log("  F_SETOWN(self): rv=" .. (ok_a3 and rv_a3:tonumber() or -999))

-- Install SIGIO handler (signal 23 on FreeBSD)
-- Use SIG_IGN first to see if signal arrives without crashing
-- sigaction(23, {SIG_IGN, ...}, NULL)
local sa_struct = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(sa_struct + i, 0) end
memory.write_qword(sa_struct, 1) -- SIG_IGN = 1

local ok_sig, rv_sig = pcall(function()
    return syscall.sc_sigaction(23, sa_struct, 0) -- SIGIO=23
end)
log("  sigaction(SIGIO, SIG_IGN): rv=" .. (ok_sig and rv_sig:tonumber() or -999))

-- Also try SIGURG (signal 16) - used by OOB data
memory.write_qword(sa_struct, 1) -- SIG_IGN
local ok_urg, rv_urg = pcall(function()
    return syscall.sc_sigaction(16, sa_struct, 0) -- SIGURG=16
end)
log("  sigaction(SIGURG, SIG_IGN): rv=" .. (ok_urg and rv_urg:tonumber() or -999))

-- Write data to sb (peer) — should trigger SIGIO on sa if O_ASYNC+SETOWN worked
local test_buf = memory.alloc(8)
memory.write_qword(test_buf, 0xDEADBEEFCAFE0001)
local ok_w, rv_w = pcall(function() return syscall.sc_write(sb, test_buf, 8) end)
log("  write to peer: rv=" .. (ok_w and rv_w:tonumber() or -999))

-- Small delay to let signal deliver
local ts = memory.alloc(16)
memory.write_qword(ts, 0)         -- tv_sec = 0
memory.write_qword(ts + 8, 50000000) -- tv_nsec = 50ms
pcall(function() syscall.sc_nanosleep(ts, 0) end)

-- If we're still alive, SIG_IGN worked (signal was delivered and ignored)
-- or signal was never sent
log("  survived after write (SIG_IGN caught or no signal)")

-- Now test: set O_ASYNC + NONBLOCK together
local ok_a4, rv_a4 = pcall(function() return syscall.sc_fcntl(sa, 4, 0x44) end) -- ASYNC|NONBLOCK
log("  F_SETFL(ASYNC|NONBLK): rv=" .. (ok_a4 and rv_a4:tonumber() or -999))
local ok_a5, rv_a5 = pcall(function() return syscall.sc_fcntl(sa, 3, 0) end)
log("  verify: " .. (ok_a5 and rv_a5:tonumber() or -999))

-- ============================================================
-- PART 5: poll/select on sockets
-- ============================================================
log("")
log("--- PART 5: poll/select ---")

-- poll: check if sa has data ready (we wrote 8 bytes to sb earlier)
-- struct pollfd { int fd; short events; short revents; }
local pollfd = memory.alloc(8)
memory.write_dword(pollfd, sa)           -- fd
memory.write_word(pollfd + 4, 0x0001)    -- POLLIN
memory.write_word(pollfd + 6, 0)         -- revents

local ok_p, rv_p = pcall(function()
    return syscall.sc_poll(pollfd, 1, 100) -- 100ms timeout
end)
local revents = memory.read_word(pollfd + 6):tonumber()
log(string.format("  poll(sa, POLLIN, 100ms): rv=%d revents=0x%04x",
    ok_p and rv_p:tonumber() or -999, revents))

-- Read the pending data
local rd_buf = memory.alloc(16)
local ok_r, rv_r = pcall(function() return syscall.sc_read(sa, rd_buf, 16) end)
log("  read from sa: rv=" .. (ok_r and rv_r:tonumber() or -999))

-- Poll again — should be empty now
memory.write_word(pollfd + 6, 0)
local ok_p2, rv_p2 = pcall(function()
    return syscall.sc_poll(pollfd, 1, 50)
end)
local rev2 = memory.read_word(pollfd + 6):tonumber()
log(string.format("  poll(sa, empty): rv=%d revents=0x%04x",
    ok_p2 and rv_p2:tonumber() or -999, rev2))

-- ============================================================
-- PART 6: kqueue
-- ============================================================
log("")
log("--- PART 6: kqueue ---")

local ok_kq, rv_kq = pcall(function() return syscall.sc_kqueue() end)
local kq_fd = ok_kq and rv_kq:tonumber() or -1
log("  kqueue(): fd=" .. kq_fd)

if kq_fd >= 0 then
    -- struct kevent {
    --   uintptr_t ident;    // 8 bytes
    --   short     filter;   // 2 bytes
    --   u_short   flags;    // 2 bytes
    --   u_int     fflags;   // 4 bytes
    --   intptr_t  data;     // 8 bytes
    --   void     *udata;    // 8 bytes
    -- } = 32 bytes
    local kev = memory.alloc(64)
    -- Watch sa for read events
    -- EVFILT_READ = -1, EV_ADD = 0x0001, EV_ENABLE = 0x0004
    memory.write_qword(kev, sa)              -- ident = sa fd
    memory.write_word(kev + 8, 0xFFFF)       -- filter = EVFILT_READ (-1 as uint16)
    memory.write_word(kev + 10, 0x0001)      -- flags = EV_ADD
    memory.write_dword(kev + 12, 0)          -- fflags
    memory.write_qword(kev + 16, 0)          -- data
    memory.write_qword(kev + 24, 0)          -- udata

    -- Write something to sb first so there's data ready
    memory.write_qword(test_buf, 0xAAAABBBB)
    pcall(function() syscall.sc_write(sb, test_buf, 8) end)

    -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
    -- timeout struct: {tv_sec, tv_nsec} 16 bytes
    local timeout = memory.alloc(16)
    memory.write_qword(timeout, 0)
    memory.write_qword(timeout + 8, 100000000) -- 100ms

    local out_kev = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(out_kev + i, 0) end

    local ok_ke, rv_ke = pcall(function()
        return syscall.sc_kevent(kq_fd, kev, 1, out_kev, 1, timeout)
    end)
    log("  kevent(add+poll): rv=" .. (ok_ke and rv_ke:tonumber() or -999))

    if ok_ke and rv_ke:tonumber() > 0 then
        local ev_ident = memory.read_qword(out_kev):tonumber()
        local ev_filter = memory.read_word(out_kev + 8):tonumber()
        local ev_flags = memory.read_word(out_kev + 10):tonumber()
        local ev_data = memory.read_qword(out_kev + 16):tonumber()
        log(string.format("  event: ident=%d filter=0x%x flags=0x%x data=%d",
            ev_ident, ev_filter, ev_flags, ev_data))
    end

    pcall(function() syscall.sc_close(kq_fd) end)
end

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

log("")
log("=== FCNTL BYPASS DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
