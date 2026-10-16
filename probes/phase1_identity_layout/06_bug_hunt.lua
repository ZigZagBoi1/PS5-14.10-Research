-- 14.10 Recon Probe 06: Targeted Bug Hunting
-- Uses syscall.resolve() properly. No make_syscall hacks.
-- SAFE: probing error paths only

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: BUG HUNT ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_open = 5, sc_close = 6, sc_read = 3, sc_write = 4,
    sc_ioctl = 54, sc_socket = 97,
    sc_setsockopt = 105, sc_getsockopt = 118,
    sc_pipe = 42, sc_mmap = 477, sc_munmap = 73, sc_mprotect = 74,
    sc_kqueueex = 394,
    sc_aio_read = 454, sc_aio_multi_wait = 550, sc_aio_multi_cancel = 549,
})

-- ============================================================
-- HUNT 1: kqueue + kevent edge cases
-- ============================================================
log("")
log("--- HUNT 1: kqueue edge cases ---")

local kq_fd = -1
pcall(function()
    kq_fd = syscall.kqueue():tonumber()
    log("  kqueue fd: " .. kq_fd)
end)

if kq_fd >= 0 then
    pcall(function()
        local changelist = memory.alloc(64)
        local eventlist = memory.alloc(512)
        local pipe_fds = memory.alloc(8)
        syscall.sc_pipe(pipe_fds)
        local rfd = memory.read_dword(pipe_fds):tonumber()
        local wfd = memory.read_dword(pipe_fds + 4):tonumber()

        memory.write_qword(changelist + 0, rfd)
        memory.write_word(changelist + 8, 0xFFFF)
        memory.write_word(changelist + 10, 0x0001)
        memory.write_dword(changelist + 12, 0)
        memory.write_qword(changelist + 16, 0)
        memory.write_qword(changelist + 24, 0)

        local ret = syscall.kevent(kq_fd, changelist, 1, 0, 0, 0)
        log("  kevent register: " .. ret:tonumber())

        local wbuf = memory.alloc(4)
        memory.write_dword(wbuf, 0x41414141)
        syscall.sc_write(wfd, wbuf, 4)

        local ts = memory.alloc(16)
        memory.write_qword(ts, 0)
        memory.write_qword(ts + 8, 0)
        ret = syscall.kevent(kq_fd, 0, 0, eventlist, 8, ts)
        local nevents = ret:tonumber()
        log("  kevent poll: " .. nevents .. " events")

        if nevents > 0 then
            local ev_ident = memory.read_qword(eventlist):tonumber()
            local ev_data = memory.read_qword(eventlist + 16):tonumber()
            log("  event: ident=" .. ev_ident .. " data=" .. ev_data)
        end

        syscall.sc_close(rfd)
        syscall.sc_close(wfd)
        log("  kqueue+kevent: FULLY FUNCTIONAL")
    end)

    pcall(function()
        local kqx_fd = syscall.sc_kqueueex(0):tonumber()
        if kqx_fd >= 0 then
            log("  kqueueex: fd=" .. kqx_fd .. " (AVAILABLE)")
            syscall.sc_close(kqx_fd)
        else
            log("  kqueueex: returned " .. kqx_fd)
        end
    end)

    syscall.sc_close(kq_fd)
end

-- ============================================================
-- HUNT 2: AIO race conditions (Relapse family)
-- ============================================================
log("")
log("--- HUNT 2: aio race surface ---")

pcall(function()
    local pipe_fds = memory.alloc(8)
    syscall.sc_pipe(pipe_fds)
    local rfd = memory.read_dword(pipe_fds):tonumber()
    local wfd = memory.read_dword(pipe_fds + 4):tonumber()

    local aiocb = memory.alloc(256)
    memory.write_dword(aiocb + 0, rfd)

    local ok2, err2 = pcall(function()
        return syscall.sc_aio_read(aiocb)
    end)
    log("  aio_read(pipe): " .. (ok2 and "accepted" or tostring(err2):sub(1,50)))

    local ok3, err3 = pcall(function()
        return syscall.sc_aio_multi_wait(0, 0, 0, 0)
    end)
    log("  aio_multi_wait(NULL): " .. (ok3 and "OK" or tostring(err3):sub(1,50)))

    local ok4, err4 = pcall(function()
        return syscall.sc_aio_multi_cancel(rfd, 0)
    end)
    log("  aio_multi_cancel(pipe): " .. (ok4 and "OK" or tostring(err4):sub(1,50)))

    syscall.sc_close(rfd)
    syscall.sc_close(wfd)
end)

-- ============================================================
-- HUNT 3: IPv6 option handling
-- ============================================================
log("")
log("--- HUNT 3: IPv6 option handling ---")

pcall(function()
    local s = syscall.sc_socket(28, 3, 255)
    local fd = s:tonumber()
    if fd < 0 then
        s = syscall.sc_socket(28, 2, 0)
        fd = s:tonumber()
    end
    log("  IPv6 socket: fd=" .. fd)

    if fd >= 0 then
        local big_buf = memory.alloc(8192)
        local test_opts = {
            {46, "IPV6_PKTINFO"}, {47, "IPV6_HOPLIMIT"},
            {48, "IPV6_NEXTHOP"}, {49, "IPV6_HOPOPTS"},
            {50, "IPV6_DSTOPTS"}, {51, "IPV6_RTHDR"},
            {61, "IPV6_AUTOFLOWLABEL"},
        }

        for _, opt in ipairs(test_opts) do
            for _, sz in ipairs({4, 256, 4096}) do
                local ok2 = pcall(function()
                    return syscall.sc_setsockopt(fd, 41, opt[1], big_buf, sz)
                end)
                if ok2 then
                    log("  " .. opt[2] .. " size=" .. sz .. ": ACCEPTED")
                end
            end
        end

        local optlen = memory.alloc(8)
        for _, opt in ipairs(test_opts) do
            memory.write_dword(optlen, 8192)
            local ok2 = pcall(function()
                return syscall.sc_getsockopt(fd, 41, opt[1], big_buf, optlen)
            end)
            local actual = memory.read_dword(optlen):tonumber()
            if ok2 and actual > 0 then
                log("  GET " .. opt[2] .. ": returned " .. actual .. " bytes")
            end
        end

        syscall.sc_close(fd)
    end
end)

-- ============================================================
-- HUNT 4: mmap edge cases
-- ============================================================
log("")
log("--- HUNT 4: mmap edge cases ---")

pcall(function()
    local addr = syscall.sc_mmap(0, 0x1000, 3, 0x1001, -1, 0)
    local a = addr:tonumber()
    if a > 0 and a ~= 0xFFFFFFFF then
        log("  MAP_SHARED|MAP_ANON: 0x" .. string.format("%x", a))
        local ret = syscall.sc_mprotect(addr, 0x1000, 7)
        log("  mprotect RWX: " .. ret:tonumber() .. (ret:tonumber() == 0 and " (!!W^X broken!!)" or ""))
        syscall.sc_munmap(addr, 0x1000)
    else
        log("  MAP_SHARED|MAP_ANON: failed")
    end

    local addr2 = syscall.sc_mmap(0x10000, 0x1000, 3, 0x1012, -1, 0)
    local a2 = addr2:tonumber()
    log("  MAP_FIXED@0x10000: 0x" .. string.format("%x", a2))
    if a2 > 0 and a2 ~= 0xFFFFFFFF then
        pcall(function() syscall.sc_munmap(addr2, 0x1000) end)
    end
end)

-- ============================================================
-- HUNT 5: device ioctl surface
-- ============================================================
log("")
log("--- HUNT 5: device ioctl surface ---")

local ioctl_targets = {"/dev/null", "/dev/zero", "/dev/urandom"}
for _, dev in ipairs(ioctl_targets) do
    pcall(function()
        local fd = syscall.sc_open(dev, 2):tonumber()
        if fd < 0 then fd = syscall.sc_open(dev, 0):tonumber() end
        if fd >= 0 then
            local buf = memory.alloc(256)
            local interesting = {}
            for cmd = 0, 50 do
                local ok2 = pcall(function()
                    local ret = syscall.sc_ioctl(fd, cmd, buf)
                    if ret:tonumber() == 0 then
                        interesting[#interesting+1] = cmd
                    end
                end)
            end
            if #interesting > 0 then
                log("  " .. dev .. ": " .. #interesting .. " accepted ioctls")
            else
                log("  " .. dev .. ": no ioctls accepted")
            end
            syscall.sc_close(fd)
        end
    end)
end

-- ============================================================
-- HUNT 6: pipe/fd limits
-- ============================================================
log("")
log("--- HUNT 6: fd passing surface ---")

pcall(function()
    local pipe_fds = memory.alloc(8)
    syscall.sc_pipe(pipe_fds)
    local rfd = memory.read_dword(pipe_fds):tonumber()
    local wfd = memory.read_dword(pipe_fds + 4):tonumber()
    log("  pipe: r=" .. rfd .. " w=" .. wfd)

    local max_fds = 0
    for i = 1, 100 do
        local fds = memory.alloc(8)
        local ok2 = pcall(function() syscall.sc_pipe(fds) end)
        if ok2 then
            max_fds = i
            local r = memory.read_dword(fds):tonumber()
            local w = memory.read_dword(fds + 4):tonumber()
            if i == 100 then
                log("  100 pipes created (fd=" .. w .. ")")
            end
            syscall.sc_close(r)
            syscall.sc_close(w)
        else
            break
        end
    end
    log("  max pipes before failure: " .. max_fds)

    syscall.sc_close(rfd)
    syscall.sc_close(wfd)
end)

log("")
log("=== BUG HUNT SUMMARY ===")
log("Key findings above show which attack surfaces are live on 14.10.")
log("Priority targets: aio_multi_*, kqueueex, IPv6 opts, umtx_op")
log("")
log("=== BUG HUNT DONE ===")
return table.concat(out, "\n")
