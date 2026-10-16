-- 14.10 Recon Probe 32: buffer stress + SETFIB/USER_COOKIE fuzz
-- SO_SNDBUF=1 with large writev, poll edge cases, nonblocking overflow

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: BUF STRESS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_socketpair = 135,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_writev = 121,
    sc_readv = 120,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_fcntl = 92,
    sc_poll = 209,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_shutdown = 134,
})

local val = memory.alloc(16)
local sp = memory.alloc(8)

local function try_set(fd, level, opt, v, len)
    memory.write_dword(val, v)
    local ok, ret = pcall(function()
        return syscall.sc_setsockopt(fd, level, opt, val, len or 4)
    end)
    return ok and ret:tonumber() or -999
end

local function try_get_val(fd, level, opt)
    local buf = memory.alloc(8)
    local lenp = memory.alloc(8)
    memory.write_qword(lenp, 4)
    memory.write_dword(buf, 0)
    local ok, ret = pcall(function()
        return syscall.sc_getsockopt(fd, level, opt, buf, lenp)
    end)
    return ok and ret:tonumber() or -999, memory.read_dword(buf):tonumber()
end

-- ============================================================
-- PART 1: SO_SNDBUF=1 + massive writev
-- ============================================================
log("")
log("--- PART 1: SNDBUF=1 stress ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

-- Set SNDBUF=1 on sa
log("  set SNDBUF=1: rv=" .. try_set(sa, 0xFFFF, 0x1001, 1))
local _, sndbuf = try_get_val(sa, 0xFFFF, 0x1001)
log("  actual SNDBUF: " .. sndbuf)

-- Set NONBLOCK via F_SETFL bypass
pcall(function() syscall.sc_fcntl(sa, 4, 4) end) -- O_NONBLOCK

-- Try write of various sizes
for _, sz in ipairs({1, 4, 64, 256, 1024, 4096, 8192}) do
    local wbuf = memory.alloc(sz)
    for i = 0, sz - 1, 4 do memory.write_dword(wbuf + i, 0xAA000000 + i) end
    local ok, ret = pcall(function() return syscall.sc_write(sa, wbuf, sz) end)
    local rv = ok and ret:tonumber() or -999
    log(string.format("  write(%d): rv=%d", sz, rv))
end

-- Drain some from sb
local drain = memory.alloc(65536)
local ok_d, rv_d = pcall(function() return syscall.sc_read(sb, drain, 65536) end)
log("  drain: " .. (ok_d and rv_d:tonumber() or -999))

-- Now writev with 1024 iovecs of 1 byte each, SNDBUF still =1
local tiny = memory.alloc(4)
memory.write_byte(tiny, 0x42)
local iovecs = memory.alloc(1024 * 16)
for i = 0, 1023 do
    memory.write_qword(iovecs + i * 16, tiny)
    memory.write_qword(iovecs + i * 16 + 8, 1)
end
local ok_wv, rv_wv = pcall(function() return syscall.sc_writev(sa, iovecs, 1024) end)
log("  writev(1024x1, SNDBUF=1): rv=" .. (ok_wv and rv_wv:tonumber() or -999))

-- Drain again
ok_d, rv_d = pcall(function() return syscall.sc_read(sb, drain, 65536) end)
log("  drain2: " .. (ok_d and rv_d:tonumber() or -999))

-- Set RCVBUF=1 on sb
log("  set RCVBUF=1 on sb: rv=" .. try_set(sb, 0xFFFF, 0x1002, 1))

-- Write to sa when receiver has RCVBUF=1
for _, sz in ipairs({1, 64, 1024, 4096}) do
    local wbuf = memory.alloc(sz)
    memory.write_dword(wbuf, 0xBB000000 + sz)
    local ok, ret = pcall(function() return syscall.sc_write(sa, wbuf, sz) end)
    log(string.format("  write(%d, RCVBUF=1): rv=%d", sz, ok and ret:tonumber() or -999))
end

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- ============================================================
-- PART 2: Poll edge cases
-- ============================================================
log("")
log("--- PART 2: poll edge cases ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

-- Poll on closed peer
pcall(function() syscall.sc_shutdown(sb, 2) end) -- SHUT_RDWR
pcall(function() syscall.sc_close(sb) end)

local pollfd = memory.alloc(8)
memory.write_dword(pollfd, sa)
memory.write_word(pollfd + 4, 0x0045) -- POLLIN|POLLPRI|POLLHUP
memory.write_word(pollfd + 6, 0)
local ok_p, rv_p = pcall(function() return syscall.sc_poll(pollfd, 1, 50) end)
local rev = memory.read_word(pollfd + 6):tonumber()
log(string.format("  poll(closed peer): rv=%d revents=0x%04x",
    ok_p and rv_p:tonumber() or -999, rev))

-- Read from socket with closed peer
local rbuf = memory.alloc(16)
local ok_r, rv_r = pcall(function() return syscall.sc_read(sa, rbuf, 16) end)
log("  read(closed peer): rv=" .. (ok_r and rv_r:tonumber() or -999))

pcall(function() syscall.sc_close(sa) end)

-- Poll with nfds=0
local ok_p0, rv_p0 = pcall(function() return syscall.sc_poll(pollfd, 0, 10) end)
log("  poll(nfds=0): rv=" .. (ok_p0 and rv_p0:tonumber() or -999))

-- Poll on invalid fd
memory.write_dword(pollfd, 9999)
memory.write_word(pollfd + 4, 0x0001)
memory.write_word(pollfd + 6, 0)
local ok_pi, rv_pi = pcall(function() return syscall.sc_poll(pollfd, 1, 10) end)
local rev_i = memory.read_word(pollfd + 6):tonumber()
log(string.format("  poll(fd=9999): rv=%d revents=0x%04x",
    ok_pi and rv_pi:tonumber() or -999, rev_i))

-- Poll with negative fd (FreeBSD ignores negative fds)
memory.write_dword(pollfd, 0xFFFFFFFF) -- -1
memory.write_word(pollfd + 4, 0x0001)
memory.write_word(pollfd + 6, 0)
local ok_pn, rv_pn = pcall(function() return syscall.sc_poll(pollfd, 1, 10) end)
local rev_n = memory.read_word(pollfd + 6):tonumber()
log(string.format("  poll(fd=-1): rv=%d revents=0x%04x",
    ok_pn and rv_pn:tonumber() or -999, rev_n))

-- Multiple pollfds: mix of valid and invalid
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

-- Write data so sa has something to poll
local wbuf = memory.alloc(8)
memory.write_qword(wbuf, 0xDEADBEEF)
pcall(function() syscall.sc_write(sb, wbuf, 8) end)

local pollfds = memory.alloc(24) -- 3 pollfds
memory.write_dword(pollfds, sa)         -- valid, has data
memory.write_word(pollfds + 4, 0x0001)
memory.write_word(pollfds + 6, 0)
memory.write_dword(pollfds + 8, 9999)   -- invalid
memory.write_word(pollfds + 12, 0x0001)
memory.write_word(pollfds + 14, 0)
memory.write_dword(pollfds + 16, sb)    -- valid, no data
memory.write_word(pollfds + 20, 0x0001)
memory.write_word(pollfds + 22, 0)

local ok_pm, rv_pm = pcall(function() return syscall.sc_poll(pollfds, 3, 50) end)
log(string.format("  poll(3 mixed): rv=%d rev=[0x%04x,0x%04x,0x%04x]",
    ok_pm and rv_pm:tonumber() or -999,
    memory.read_word(pollfds + 6):tonumber(),
    memory.read_word(pollfds + 14):tonumber(),
    memory.read_word(pollfds + 22):tonumber()))

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- ============================================================
-- PART 3: SO_SETFIB (0x1011) fuzzing
-- ============================================================
log("")
log("--- PART 3: SO_SETFIB ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local fa = memory.read_dword(sp):tonumber()
local fab = memory.read_dword(sp + 4):tonumber()

-- Read default
local rv_f, val_f = try_get_val(fa, 0xFFFF, 0x1011)
log(string.format("  default: rv=%d val=%d", rv_f, val_f))

-- Set various FIB values
for _, fib in ipairs({0, 1, 2, 15, 16, 31, 32, 255, 256, 0xFFFF, 0x7FFFFFFF, -1}) do
    local srv = try_set(fa, 0xFFFF, 0x1011, fib)
    local grv, gval = try_get_val(fa, 0xFFFF, 0x1011)
    log(string.format("  set(%d): srv=%d get=%d", fib, srv, gval))
end

pcall(function() syscall.sc_close(fa) end)
pcall(function() syscall.sc_close(fab) end)

-- ============================================================
-- PART 4: SO_USER_COOKIE (0x1012) fuzzing
-- ============================================================
log("")
log("--- PART 4: SO_USER_COOKIE ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ca = memory.read_dword(sp):tonumber()
local cab = memory.read_dword(sp + 4):tonumber()

local rv_c, val_c = try_get_val(ca, 0xFFFF, 0x1012)
log(string.format("  default: rv=%d val=%d", rv_c, val_c))

for _, cookie in ipairs({0, 1, 0xDEADBEEF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}) do
    local srv = try_set(ca, 0xFFFF, 0x1012, cookie)
    local grv, gval = try_get_val(ca, 0xFFFF, 0x1012)
    log(string.format("  set(0x%x): srv=%d get=0x%08x", cookie, srv, gval))
end

pcall(function() syscall.sc_close(ca) end)
pcall(function() syscall.sc_close(cab) end)

-- ============================================================
-- PART 5: SO_TS_CLOCK (0x1013) + timestamp probing
-- ============================================================
log("")
log("--- PART 5: SO_TS_CLOCK ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ta = memory.read_dword(sp):tonumber()
local tab = memory.read_dword(sp + 4):tonumber()

local rv_t, val_t = try_get_val(ta, 0xFFFF, 0x1013)
log(string.format("  default: rv=%d val=%d", rv_t, val_t))

-- SO_TIMESTAMP = 0x0400, SO_BINTIME = 0x2000 (wait, 0x2000 is PS5 flag)
-- Enable SO_TIMESTAMP
log("  set SO_TIMESTAMP(0x0400)=1: rv=" .. try_set(ta, 0xFFFF, 0x0400, 1))
local _, ts_val = try_get_val(ta, 0xFFFF, 0x0400)
log("  get SO_TIMESTAMP: " .. ts_val)

-- Set clock types
for _, clk in ipairs({0, 1, 2, 3, 4, 255}) do
    local srv = try_set(ta, 0xFFFF, 0x1013, clk)
    local grv, gval = try_get_val(ta, 0xFFFF, 0x1013)
    log(string.format("  TS_CLOCK=%d: srv=%d get=%d", clk, srv, gval))
end

-- Receive with timestamp enabled — write then recvmsg
pcall(function() syscall.sc_write(tab, wbuf, 8) end)

local cmsg_buf = memory.alloc(128)
local recv_buf = memory.alloc(64)
local iov = memory.alloc(16)
memory.write_qword(iov, recv_buf)
memory.write_qword(iov + 8, 64)
for i = 0, 127, 8 do memory.write_qword(cmsg_buf + i, 0) end

local mh = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
memory.write_qword(mh + 16, iov)
memory.write_qword(mh + 24, 1)
memory.write_qword(mh + 32, cmsg_buf)
memory.write_qword(mh + 40, 128)

local ok_rm, rv_rm = pcall(function() return syscall.sc_recvmsg(ta, mh, 0) end)
log("  recvmsg: rv=" .. (ok_rm and rv_rm:tonumber() or -999))
local cmsg_len = memory.read_dword(cmsg_buf):tonumber()
local cmsg_level = memory.read_dword(cmsg_buf + 4):tonumber()
local cmsg_type = memory.read_dword(cmsg_buf + 8):tonumber()
log(string.format("  cmsg: len=%d level=0x%x type=%d", cmsg_len, cmsg_level, cmsg_type))
if cmsg_len > 12 then
    local ts_sec = memory.read_qword(cmsg_buf + 16):tonumber()
    local ts_usec = memory.read_qword(cmsg_buf + 24):tonumber()
    log(string.format("  timestamp: sec=%d usec=%d", ts_sec, ts_usec))
end

pcall(function() syscall.sc_close(ta) end)
pcall(function() syscall.sc_close(tab) end)

log("")
log("=== BUF STRESS DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
