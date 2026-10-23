-- CRASH_CLASS: MODERATE
-- PROBE 67b: CVE-2026-45251 poll/select fd UAF with threads
--
-- Context: FreeBSD-SA-26:19.file — closing an fd while another thread
-- is blocked in poll(2) or select(2) on it. The blocked thread doesn't
-- hold a reference to the underlying object. For some fd types, blocked
-- threads are not unlinked before the object is freed. On wake, the
-- thread touches freed memory → UAF.
--
-- Gate: verify poll(2) and select(2) work. Then test with threads:
-- Thread A blocks in poll(), Thread B closes the fd.
-- Candidate fd types: socket, shm, kqueue, /dev/gc, /dev/notification0

print("=== PROBE 67b: CVE-2026-45251 POLL FD UAF ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc_getpid = make_syscall(20)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_poll = make_syscall(209)
local sc_select = make_syscall(93)
local sc_socket = make_syscall(97)
local sc_socketpair = make_syscall(135)
local sc_kqueue = make_syscall(362)
local sc_kevent = make_syscall(363)
local sc_shm_open = make_syscall(482)
local sc_ftruncate = make_syscall(480)
local sc_mmap = make_syscall(477)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_pipe = make_syscall(542)  -- pipe2

local function alive()
    local ok, v = pcall(function() return sc_getpid() end)
    return ok
end

local pid = to_num(sc_getpid())
print("PID: " .. pid)

local function write_str(str)
    local buf = memory.alloc(#str + 8)
    for i = 0, math.floor(#str / 4) do
        local dw = 0
        for j = 0, 3 do
            local idx = i * 4 + j + 1
            if idx <= #str then dw = dw + string.byte(str, idx) * (256 ^ j) end
        end
        safe_wd(buf + i * 4, dw)
    end
    return buf
end

-- [A] poll(2) availability test
print("[A] poll(2) availability")

-- Create a socketpair for testing
local sp_buf = memory.alloc(16)
safe_wd(sp_buf, 0)
safe_wd(sp_buf + 4, 0)
local sp_ok, sp_ret = pcall(function()
    return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sp_buf))  -- AF_UNIX, SOCK_STREAM
end)
local sp_rv = sp_ok and to_num(sp_ret) or -1
local fd_a = safe_rd(sp_buf)
local fd_b = safe_rd(sp_buf + 4)
print("  socketpair = " .. sp_rv .. " fds=" .. (fd_a or -1) .. "," .. (fd_b or -1))

if sp_rv == 0 and fd_a and fd_b and fd_a > 0 then
    -- struct pollfd { int fd; short events; short revents; }
    -- sizeof = 8
    local pollfd = memory.alloc(16)
    safe_wd(pollfd, fd_a)           -- fd
    safe_wd(pollfd + 4, 0x0001)     -- events = POLLIN (1)

    -- Poll with 0 timeout (immediate return)
    local poll_ok, poll_ret = pcall(function()
        return sc_poll(uint64(pollfd), uint64(1), uint64(0))  -- nfds=1, timeout=0ms
    end)
    local poll_rv = poll_ok and to_num(poll_ret) or -999
    local revents = safe_rd(pollfd + 4) or 0
    local rev_hi = math.floor(revents / 65536) % 65536  -- revents is in upper 16 bits
    print(string.format("  poll(fd=%d, POLLIN, timeout=0) = %d revents=0x%04X",
        fd_a, poll_rv, rev_hi))
    if not alive() then print("  DEAD after poll") return end

    -- Write something to fd_b so fd_a becomes readable
    local wbuf = memory.alloc(8)
    safe_wd(wbuf, 0x41424344)
    pcall(function() sc_write(uint64(fd_b), uint64(wbuf), uint64(4)) end)

    -- Poll again — should now show POLLIN
    safe_wd(pollfd + 4, 0x0001)  -- reset events
    local poll2_ok, poll2_ret = pcall(function()
        return sc_poll(uint64(pollfd), uint64(1), uint64(0))
    end)
    local poll2_rv = poll2_ok and to_num(poll2_ret) or -999
    local revents2 = safe_rd(pollfd + 4) or 0
    local rev2_hi = math.floor(revents2 / 65536) % 65536
    print(string.format("  poll(fd=%d, POLLIN, timeout=0) after write = %d revents=0x%04X",
        fd_a, poll2_rv, rev2_hi))

    -- Drain the data
    local rbuf = memory.alloc(8)
    pcall(function() sc_read(uint64(fd_a), uint64(rbuf), uint64(4)) end)

    -- Poll with short timeout (100ms) — should return 0 (no events)
    safe_wd(pollfd + 4, 0x0001)
    local poll3_ok, poll3_ret = pcall(function()
        return sc_poll(uint64(pollfd), uint64(1), uint64(100))
    end)
    local poll3_rv = poll3_ok and to_num(poll3_ret) or -999
    print("  poll(timeout=100ms, no data) = " .. poll3_rv .. " (0 = timed out correctly)")

    -- [A2] select(2) test
    print("")
    print("[A2] select(2) availability")
    -- FreeBSD select: int select(int nfds, fd_set *readfds, ...)
    -- fd_set is a bitmask: sizeof depends on FD_SETSIZE
    -- For our purposes, fd_set for fd<32 is a single uint32
    local fdset = memory.alloc(128)  -- oversized fd_set
    for i = 0, 124, 4 do safe_wd(fdset + i, 0) end

    -- Set the bit for fd_a
    local fd_word = math.floor(fd_a / 32)
    local fd_bit = fd_a % 32
    safe_wd(fdset + fd_word * 4, 2 ^ fd_bit)

    -- timeval: 8 bytes tv_sec + 8 bytes tv_usec (FreeBSD uses 64-bit time_t)
    local tv = memory.alloc(16)
    safe_wd(tv, 0)       -- tv_sec = 0
    safe_wd(tv + 4, 0)
    safe_wd(tv + 8, 0)   -- tv_usec = 0
    safe_wd(tv + 12, 0)

    local sel_ok, sel_ret = pcall(function()
        return sc_select(uint64(fd_a + 1), uint64(fdset), uint64(0), uint64(0), uint64(tv))
    end)
    print("  select(readfds, timeout=0) = " .. (sel_ok and to_num(sel_ret) or -999))
    if not alive() then print("  DEAD after select") return end

    print("")
    print("  *** poll(2) CONFIRMED WORKING ***")

    -- Clean up socketpair
    pcall(function() sc_close(uint64(fd_a)) end)
    pcall(function() sc_close(uint64(fd_b)) end)
else
    print("  socketpair failed — trying with kqueue fd")
end

if not alive() then print("DEAD after section A") return end

-- [B] Different fd types for the race
print("")
print("[B] Test fd types for poll")

-- B1: kqueue fd
local kq_ok, kq_ret = pcall(function() return sc_kqueue() end)
local kq_fd = kq_ok and to_num(kq_ret) or -1
print("  kqueue fd = " .. kq_fd)
if kq_fd >= 0 then
    local pollfd_kq = memory.alloc(8)
    safe_wd(pollfd_kq, kq_fd)
    safe_wd(pollfd_kq + 4, 0x0001)  -- POLLIN
    local pk_ok, pk_ret = pcall(function()
        return sc_poll(uint64(pollfd_kq), uint64(1), uint64(0))
    end)
    local pk_rev = (safe_rd(pollfd_kq + 4) or 0)
    local pk_rev_hi = math.floor(pk_rev / 65536) % 65536
    print(string.format("  poll(kqueue, POLLIN, 0) = %d revents=0x%04X",
        pk_ok and to_num(pk_ret) or -999, pk_rev_hi))
    pcall(function() sc_close(uint64(kq_fd)) end)
end

-- B2: /dev/gc fd
local gc_str = write_str("/dev/gc")
local gc_ok2, gc_ret2 = pcall(function()
    return sc_open(uint64(gc_str), uint64(6), uint64(0))  -- O_RDWR|O_NONBLOCK
end)
local gc_fd = gc_ok2 and to_num(gc_ret2) or -1
print("  /dev/gc fd = " .. gc_fd)
if gc_fd >= 0 then
    local pollfd_gc = memory.alloc(8)
    safe_wd(pollfd_gc, gc_fd)
    safe_wd(pollfd_gc + 4, 0x0001)
    local pg_ok, pg_ret = pcall(function()
        return sc_poll(uint64(pollfd_gc), uint64(1), uint64(0))
    end)
    local pg_rev = (safe_rd(pollfd_gc + 4) or 0)
    local pg_rev_hi = math.floor(pg_rev / 65536) % 65536
    print(string.format("  poll(/dev/gc, POLLIN, 0) = %d revents=0x%04X",
        pg_ok and to_num(pg_ret) or -999, pg_rev_hi))
    pcall(function() sc_close(uint64(gc_fd)) end)
end

-- B3: /dev/notification0 fd
local notif_str = write_str("/dev/notification0")
local notif_ok, notif_ret = pcall(function()
    return sc_open(uint64(notif_str), uint64(6), uint64(0))
end)
local notif_fd = notif_ok and to_num(notif_ret) or -1
print("  /dev/notification0 fd = " .. notif_fd)
if notif_fd >= 0 then
    local pollfd_n = memory.alloc(8)
    safe_wd(pollfd_n, notif_fd)
    safe_wd(pollfd_n + 4, 0x0001)
    local pn_ok, pn_ret = pcall(function()
        return sc_poll(uint64(pollfd_n), uint64(1), uint64(0))
    end)
    local pn_rev = (safe_rd(pollfd_n + 4) or 0)
    local pn_rev_hi = math.floor(pn_rev / 65536) % 65536
    print(string.format("  poll(/dev/notification0, POLLIN, 0) = %d revents=0x%04X",
        pn_ok and to_num(pn_ret) or -999, pn_rev_hi))
    pcall(function() sc_close(uint64(notif_fd)) end)
end

-- B4: shm fd
local shm_str = write_str("/poll_test_67b")
local shm_ok, shm_ret = pcall(function()
    return sc_shm_open(uint64(shm_str), uint64(0x602), uint64(0x1FF))
end)
local shm_fd = shm_ok and to_num(shm_ret) or -1
print("  shm fd = " .. shm_fd)
if shm_fd >= 0 then
    local pollfd_s = memory.alloc(8)
    safe_wd(pollfd_s, shm_fd)
    safe_wd(pollfd_s + 4, 0x0001)
    local ps_ok, ps_ret = pcall(function()
        return sc_poll(uint64(pollfd_s), uint64(1), uint64(0))
    end)
    local ps_rev = (safe_rd(pollfd_s + 4) or 0)
    local ps_rev_hi = math.floor(ps_rev / 65536) % 65536
    print(string.format("  poll(shm, POLLIN, 0) = %d revents=0x%04X",
        ps_ok and to_num(ps_ret) or -999, ps_rev_hi))
    pcall(function() sc_close(uint64(shm_fd)) end)
end

if not alive() then print("DEAD after section B") return end

-- [C] UMTX_OP_SHM test (CVE-2024-43102)
print("")
print("[C] UMTX_OP_SHM availability (CVE-2024-43102)")
local sc_umtx = make_syscall(454)  -- _umtx_op
-- UMTX_OP_SHM = 23
local umtx_buf = memory.alloc(16)
safe_wd(umtx_buf, 0)
local um_ok, um_ret = pcall(function()
    return sc_umtx(uint64(umtx_buf), uint64(23), uint64(0), uint64(0), uint64(0))
end)
print("  UMTX_OP_SHM(23) = " .. (um_ok and to_num(um_ret) or -999))
if not alive() then print("  *** DEAD (lethal?) ***") return end

-- Also try UMTX_OP_SHM with different sub-commands
-- val: UMTX_SHM_CREAT(1), UMTX_SHM_LOOKUP(2), UMTX_SHM_DESTROY(3), UMTX_SHM_ALIVE(4)
for _, subcmd in ipairs({1, 2, 3, 4}) do
    local u2_ok, u2_ret = pcall(function()
        return sc_umtx(uint64(umtx_buf), uint64(23), uint64(subcmd), uint64(0), uint64(0))
    end)
    print(string.format("  UMTX_OP_SHM subcmd=%d = %d", subcmd,
        u2_ok and to_num(u2_ret) or -999))
    if not alive() then print("  *** DEAD ***") return end
end

print("")
print("=== PROBE 67b COMPLETE ===")
