-- CRASH_CLASS: LOW
-- PROBE 143p: IPv6 pktopts overlap — full option scan + errno
--
-- Context: 143o showed setsockopt(IPV6_PKTINFO=46) returns -1.
-- Need to test ALL relevant IPv6 options to find one that allocates pktopts.
-- The classic PS4/PS5 exploit uses pktopts overlap for kernel R/W.
-- Also test: use loader's built-in syscall wrappers (syscall.socket etc)

print("=== PROBE 143p: IPV6 PKTOPTS + ERRNO ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

--------------------------------------------------------------------
-- [A] Check available syscall wrappers
--------------------------------------------------------------------
print("--- [A] Syscall wrappers ---")
local sc_names = {
    "socket", "setsockopt", "getsockopt", "close", "getpid",
    "pipe", "read", "write", "dup", "dup2", "mmap", "munmap",
    "sysctl", "ioctl", "fcntl", "connect", "bind", "listen",
    "accept", "sendto", "recvfrom", "setsockopt", "getsockopt",
    "socketpair", "mprotect", "sigaction",
}
for _, name in ipairs(sc_names) do
    if syscall[name] then
        print("[A] syscall." .. name .. " = " .. type(syscall[name]))
    end
end

--------------------------------------------------------------------
-- [B] Create IPv6 socket using loader's syscall wrapper
--------------------------------------------------------------------
print("")
print("--- [B] IPv6 socket ---")

-- Use loader's socket wrapper if available
local sock_fd
if syscall.socket then
    local ok, fd = pcall(function()
        return syscall.socket(uint64(28), uint64(2), uint64(0))  -- AF_INET6, SOCK_DGRAM
    end)
    if ok then
        sock_fd = to_num(fd)
        print("[B] socket(AF_INET6, SOCK_DGRAM) fd=" .. sock_fd)
    else
        print("[B] socket FAIL: " .. tostring(fd))
    end
end

if not sock_fd or sock_fd < 0 then
    -- Fallback: try SOCK_STREAM
    if syscall.socket then
        local ok, fd = pcall(function()
            return syscall.socket(uint64(28), uint64(1), uint64(0))  -- SOCK_STREAM
        end)
        if ok then
            sock_fd = to_num(fd)
            print("[B] socket(AF_INET6, SOCK_STREAM) fd=" .. sock_fd)
        end
    end
end

if not sock_fd or sock_fd < 0 then
    print("[B] Cannot create IPv6 socket!")
    print("=== PROBE 143p COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- [C] Check errno using get_error_string
--------------------------------------------------------------------
print("")
print("--- [C] Errno check ---")

if get_error_string then
    print("[C] get_error_string available")

    -- Try a known failure to test errno
    local ok_e, err_str = pcall(function()
        syscall.setsockopt(uint64(sock_fd), uint64(41), uint64(99999), uint64(0), uint64(0))
        return get_error_string()
    end)
    if ok_e then
        print("[C] errno after bad setsockopt: " .. tostring(err_str))
    else
        print("[C] get_error_string fail: " .. tostring(err_str))
    end
else
    print("[C] get_error_string not available")
end

--------------------------------------------------------------------
-- [D] Scan ALL relevant IPv6 socket options
-- FreeBSD IPv6 options range from 1-80+
--------------------------------------------------------------------
print("")
print("--- [D] IPv6 option scan ---")

local IPPROTO_IPV6 = 41
local optval = memory.alloc(64)
memory.write_dword(optval, 1)  -- enable

-- Key IPv6 options to test
local ipv6_opts = {
    {1, "IPV6_UNICAST_HOPS"},
    {6, "IPV6_CHECKSUM"},
    {8, "IPV6_V6ONLY"},
    {18, "IPV6_MULTICAST_LOOP"},
    {19, "IPV6_2292PKTINFO"},
    {20, "IPV6_2292HOPLIMIT"},
    {21, "IPV6_2292NEXTHOP"},
    {22, "IPV6_2292HOPOPTS"},
    {23, "IPV6_2292DSTOPTS"},
    {24, "IPV6_2292RTHDR"},
    {25, "IPV6_2292PKTOPTIONS"},
    {26, "IPV6_RECVPKTINFO_old"},
    {27, "IPV6_MULTICAST_IF"},
    {36, "IPV6_RECVRTHDR_old"},
    {46, "IPV6_PKTINFO"},
    {47, "IPV6_HOPLIMIT"},
    {48, "IPV6_NEXTHOP"},
    {49, "IPV6_HOPOPTS"},
    {50, "IPV6_DSTOPTS"},
    {51, "IPV6_RTHDR"},
    {52, "IPV6_RECVPKTINFO"},
    {53, "IPV6_RECVHOPLIMIT"},
    {54, "IPV6_RECVRTHDR"},
    {55, "IPV6_RECVHOPOPTS"},
    {57, "IPV6_RECVDSTOPTS"},
    {61, "IPV6_USE_MIN_MTU"},
    {62, "IPV6_RECVPATHMTU"},
    {67, "IPV6_TCLASS"},
    {68, "IPV6_RECVTCLASS"},
    {69, "IPV6_DONTFRAG"},
    {73, "IPV6_ORIGDSTADDR"},
    {74, "IPV6_RECVORIGDSTADDR"},
}

local working_opts = {}

for _, opt in ipairs(ipv6_opts) do
    memory.write_dword(optval, 1)
    local ok, rv = pcall(function()
        return syscall.setsockopt(uint64(sock_fd), uint64(IPPROTO_IPV6), uint64(opt[1]), uint64(optval), uint64(4))
    end)

    if ok then
        local rv_n = to_num(rv)
        if rv_n == 0 then
            print("[D] " .. opt[2] .. "(" .. opt[1] .. ") = OK")
            table.insert(working_opts, opt)
        end
    end
end

print("[D] Working options: " .. #working_opts)

--------------------------------------------------------------------
-- [E] Try getsockopt on working options — look for leaked data
--------------------------------------------------------------------
print("")
print("--- [E] Getsockopt scan ---")

local optbuf = memory.alloc(0x200)
local optlenp = memory.alloc(8)

for _, opt in ipairs(working_opts) do
    for off = 0, 0x1FF, 4 do memory.write_dword(optbuf + off, 0xAAAAAAAA) end
    memory.write_qword(optlenp, uint64(0x200))

    local ok, rv = pcall(function()
        return syscall.getsockopt(uint64(sock_fd), uint64(IPPROTO_IPV6), uint64(opt[1]), uint64(optbuf), uint64(optlenp))
    end)

    if ok and to_num(rv) == 0 then
        local gotlen = to_num(memory.read_qword(optlenp))
        local kptrs = 0
        local interesting = false

        for off = 0, math.min(gotlen - 4, 0x1FC), 4 do
            local dw = memory.read_dword(optbuf + off)
            if dw and dw ~= 0xAAAAAAAA and dw ~= 0 and dw ~= 1 then
                interesting = true
            end
        end

        for off = 0, math.min(gotlen - 8, 0x1F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    print("[E] !!! KPTR " .. opt[2] .. " +" .. off .. "=" .. hex(q))
                end
            end
        end

        if interesting or gotlen > 8 then
            print("[E] " .. opt[2] .. " len=" .. gotlen)
            if gotlen <= 32 then
                for off = 0, gotlen - 4, 4 do
                    local dw = memory.read_dword(optbuf + off)
                    if dw and dw ~= 0xAAAAAAAA then
                        print("[E]   +" .. off .. "=0x" .. string.format("%08X", dw))
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [F] Create pipe pair for buffer manipulation
-- The ipv6 overlap technique needs pipe buffers
--------------------------------------------------------------------
print("")
print("--- [F] Pipe creation ---")

if syscall.pipe then
    local pipefds = memory.alloc(16)
    local ok, rv = pcall(function()
        return syscall.pipe(uint64(pipefds))
    end)
    if ok then
        local rv_n = to_num(rv)
        print("[F] pipe() ret=" .. rv_n)
        if rv_n == 0 then
            local rfd = memory.read_dword(pipefds)
            local wfd = memory.read_dword(pipefds + 4)
            print("[F] pipe fds: read=" .. rfd .. " write=" .. wfd)

            -- Write to pipe
            local wbuf = memory.alloc(256)
            memory.write_qword(wbuf, uint64("0xDEADBEEFCAFEBABE"))
            local ok_w, rv_w = pcall(function()
                return syscall.write(uint64(wfd), uint64(wbuf), uint64(8))
            end)
            print("[F] write(pipe) ret=" .. tostring(rv_w))

            -- Read from pipe
            local rbuf = memory.alloc(256)
            local ok_r, rv_r = pcall(function()
                return syscall.read(uint64(rfd), uint64(rbuf), uint64(8))
            end)
            print("[F] read(pipe) ret=" .. tostring(rv_r))
            if ok_r and to_num(rv_r) > 0 then
                print("[F] pipe data=" .. hex(memory.read_qword(rbuf)))
            end

            syscall.close(uint64(rfd))
            syscall.close(uint64(wfd))
        end
    else
        print("[F] pipe FAIL: " .. tostring(rv))
    end
else
    print("[F] syscall.pipe not available")
    -- Try via fcall
    local pipe_fn = fcall(syscall.syscall_address, 42)
    local pipefds = memory.alloc(16)
    local ok, rv = pcall(function()
        return pipe_fn(uint64(pipefds))
    end)
    print("[F] pipe via fcall ret=" .. tostring(rv))
end

--------------------------------------------------------------------
-- [G] socketpair for kernel object spray
--------------------------------------------------------------------
print("")
print("--- [G] Socketpair ---")

if syscall.socketpair then
    local spfds = memory.alloc(16)
    local ok, rv = pcall(function()
        return syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(spfds))
    end)
    if ok then
        local rv_n = to_num(rv)
        print("[G] socketpair(AF_LOCAL, SOCK_STREAM) ret=" .. rv_n)
        if rv_n == 0 then
            local fd0 = memory.read_dword(spfds)
            local fd1 = memory.read_dword(spfds + 4)
            print("[G] fds: " .. fd0 .. ", " .. fd1)
            syscall.close(uint64(fd0))
            syscall.close(uint64(fd1))
        end
    else
        print("[G] FAIL: " .. tostring(rv))
    end
else
    print("[G] syscall.socketpair not available")
end

-- Close the IPv6 socket
syscall.close(uint64(sock_fd))

print("")
print("=== PROBE 143p COMPLETE ===")
