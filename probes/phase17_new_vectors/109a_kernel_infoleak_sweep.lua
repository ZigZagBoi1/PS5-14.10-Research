-- CRASH_CLASS: LOW
-- PROBE 109a: Kernel info leak sweep — fstat + getsockopt + sockaddr + kevent data
--
-- Context: No systematic scan for kernel pointer leaks through STANDARD
-- FreeBSD APIs has been done. Many kernel copyout paths have padding bytes
-- that may not be zeroed. Previous scans focused on Sony syscalls and sysctl;
-- this probe targets the mundane paths that are often overlooked:
--
-- 1. fstat on pseudo-fds (kqueue, socket, socketpair) — stat struct padding
-- 2. getsockopt sweep — LOCAL_PEERCRED, SO_PEERLABEL, every SOL_SOCKET opt
-- 3. getsockname/getpeername on unnamed socketpair — unzeroed sockaddr_un
-- 4. kevent EVFILT_PROC/TIMER/USER event data — data field upper bits
--
-- Section A: fstat full struct dump on multiple fd types (LOW risk)
-- Section B: getsockopt comprehensive sweep (LOW risk)
-- Section C: sockaddr_un padding scan (LOW risk)
-- Section D: kevent event data deep scan (LOW risk)

print("=== PROBE 109a: KERNEL INFO LEAK SWEEP ===")
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

local SYS_close       = 6
local SYS_getpid      = 20
local SYS_getpeername  = 31
local SYS_getsockname  = 32
local SYS_socket      = 97
local SYS_getsockopt  = 118
local SYS_setsockopt  = 105
local SYS_socketpair  = 135
local SYS_fstat       = 189
local SYS_fstat12     = 551
local SYS_kqueue      = 362
local SYS_kevent      = 363

local AF_LOCAL     = 1
local AF_INET      = 2
local SOCK_STREAM  = 1
local SOCK_DGRAM   = 2
local SOL_SOCKET   = 0xFFFF
local SOL_LOCAL    = 0
local IPPROTO_TCP  = 6

local pid = to_num(make_syscall(SYS_getpid)())
print("pid: " .. pid)
print("")

local function close_fd(fd)
    if fd == nil then return end
    pcall(function() make_syscall(SYS_close)(uint64(fd)) end)
end

local function create_socketpair()
    local sv = memory.alloc(8)
    safe_wd(sv, 0); safe_wd(sv + 4, 0)
    local ok, ret = pcall(function()
        return make_syscall(SYS_socketpair)(uint64(AF_LOCAL), uint64(SOCK_STREAM),
            uint64(0), uint64(sv))
    end)
    if not ok or to_num(ret) ~= 0 then return nil, nil end
    return safe_rd(sv), safe_rd(sv + 4)
end

local function scan_buf_for_kptrs(tag, buf, size)
    local kptr_count = 0
    local interesting = 0
    for i = 0, size - 8, 8 do
        local qv = safe_rq(buf + i)
        if qv ~= nil then
            local h, l = get_hi_lo(qv)
            if is_kptr(qv) then
                print(tag .. " +" .. string.format("%02X", i) .. ": " ..
                      fmt_addr(qv) .. " *** KERNEL POINTER ***")
                kptr_count = kptr_count + 1
            elseif h ~= 0 and h ~= 0xFFFFFFFF and l ~= 0 then
                interesting = interesting + 1
            end
        end
    end
    return kptr_count, interesting
end

-- ============================================================
-- SECTION A: fstat on pseudo-fds
-- ============================================================
print("--- SECTION A: FSTAT ON PSEUDO-FDs ---")
print("")

local function try_fstat(fd, label)
    local buf = memory.alloc(0x100)
    -- Fill with sentinel
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

    -- Try fstat (189)
    local ok1, rv1 = pcall(function()
        return to_num(make_syscall(SYS_fstat)(uint64(fd), uint64(buf)))
    end)
    local used_syscall = 189
    local rv = rv1

    if not ok1 or to_num(rv1) ~= 0 then
        -- Try freebsd12 fstat (551)
        for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end
        local ok2, rv2 = pcall(function()
            return to_num(make_syscall(SYS_fstat12)(uint64(fd), uint64(buf)))
        end)
        if ok2 then
            used_syscall = 551
            rv = rv2
        else
            print("[A] " .. label .. ": fstat FAILED (both 189 and 551)")
            return
        end
    end

    print("[A] " .. label .. " (sys " .. used_syscall .. "): ret=" .. tostring(rv))

    -- Dump first 0x90 bytes (typical struct stat size)
    local dump_size = 0x90
    print("[A] " .. label .. " stat dump:")
    local kptrs = 0
    for i = 0, dump_size - 1, 8 do
        local qv = safe_rq(buf + i)
        if qv ~= nil then
            local h, l = get_hi_lo(qv)
            local m = ""
            if is_kptr(qv) then
                m = " *** KERNEL POINTER ***"
                kptrs = kptrs + 1
            elseif h == 0xDEADBEEF then
                m = " [sentinel - not written]"
            end
            print("[A]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
        end
    end

    -- Check for non-sentinel data past expected struct end
    print("[A] " .. label .. " past-struct scan:")
    for i = dump_size, 0xFF, 8 do
        local qv = safe_rq(buf + i)
        if qv ~= nil then
            local h, l = get_hi_lo(qv)
            if h ~= 0xDEADBEEF then
                local m = ""
                if is_kptr(qv) then m = " *** KERNEL POINTER ***"; kptrs = kptrs + 1 end
                print("[A]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
            end
        end
    end
    print("[A] " .. label .. " kernel ptrs: " .. kptrs)
    print("")
end

repeat
    -- kqueue fd
    local ok_kq, kq = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
    if ok_kq and kq >= 0 then
        try_fstat(kq, "kqueue fd=" .. kq)
        close_fd(kq)
    else
        print("[A] kqueue create FAILED")
    end

    -- AF_LOCAL socketpair
    local spa, spb = create_socketpair()
    if spa ~= nil then
        try_fstat(spa, "socketpair-a fd=" .. spa)
        try_fstat(spb, "socketpair-b fd=" .. spb)
        close_fd(spa); close_fd(spb)
    end

    -- AF_INET socket
    local ok_inet, inet_fd = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0)))
    end)
    if ok_inet and inet_fd >= 0 then
        try_fstat(inet_fd, "inet-tcp fd=" .. inet_fd)
        close_fd(inet_fd)
    end

    -- AF_INET SOCK_DGRAM
    local ok_udp, udp_fd = pcall(function()
        return to_num(make_syscall(SYS_socket)(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0)))
    end)
    if ok_udp and udp_fd >= 0 then
        try_fstat(udp_fd, "inet-udp fd=" .. udp_fd)
        close_fd(udp_fd)
    end
until true

-- ============================================================
-- SECTION B: getsockopt sweep
-- ============================================================
print("--- SECTION B: GETSOCKOPT SWEEP ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[B] socketpair FAILED"); break end
    print("[B] socketpair: fd_a=" .. fd_a .. " fd_b=" .. fd_b)

    local opts = {
        -- SOL_SOCKET options
        {SOL_SOCKET, 0x0001, "SO_DEBUG"},
        {SOL_SOCKET, 0x0002, "SO_ACCEPTCONN"},
        {SOL_SOCKET, 0x0004, "SO_REUSEADDR"},
        {SOL_SOCKET, 0x0008, "SO_KEEPALIVE"},
        {SOL_SOCKET, 0x0010, "SO_DONTROUTE"},
        {SOL_SOCKET, 0x0020, "SO_BROADCAST"},
        {SOL_SOCKET, 0x0080, "SO_LINGER"},
        {SOL_SOCKET, 0x0100, "SO_OOBINLINE"},
        {SOL_SOCKET, 0x0200, "SO_REUSEPORT"},
        {SOL_SOCKET, 0x0400, "SO_TIMESTAMP"},
        {SOL_SOCKET, 0x0800, "SO_NOSIGPIPE"},
        {SOL_SOCKET, 0x1001, "SO_SNDBUF"},
        {SOL_SOCKET, 0x1002, "SO_RCVBUF"},
        {SOL_SOCKET, 0x1003, "SO_SNDLOWAT"},
        {SOL_SOCKET, 0x1004, "SO_RCVLOWAT"},
        {SOL_SOCKET, 0x1005, "SO_SNDTIMEO"},
        {SOL_SOCKET, 0x1006, "SO_RCVTIMEO"},
        {SOL_SOCKET, 0x1007, "SO_ERROR"},
        {SOL_SOCKET, 0x1008, "SO_TYPE"},
        {SOL_SOCKET, 0x1009, "SO_LABEL"},
        {SOL_SOCKET, 0x100a, "SO_PEERLABEL"},
        {SOL_SOCKET, 0x100b, "SO_LISTENQLIMIT"},
        {SOL_SOCKET, 0x100c, "SO_LISTENQLEN"},
        {SOL_SOCKET, 0x100d, "SO_LISTENINCQLEN"},
        {SOL_SOCKET, 0x1010, "SO_PROTOCOL"},
        {SOL_SOCKET, 0x1011, "SO_PROTOTYPE"},
        {SOL_SOCKET, 0x1014, "SO_DOMAIN"},
        -- SOL_LOCAL options
        {SOL_LOCAL, 0x0001, "LOCAL_PEERCRED"},
        {SOL_LOCAL, 0x0002, "LOCAL_CREDS"},
        {SOL_LOCAL, 0x0003, "LOCAL_CONNWAIT"},
    }

    local total_kptrs = 0
    for _, opt in ipairs(opts) do
        local level, name, label = opt[1], opt[2], opt[3]
        local buf = memory.alloc(0x100)
        for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end
        local lenp = memory.alloc(8)
        safe_wd(lenp, 0x100)

        local ok, rv = pcall(function()
            return to_num(make_syscall(SYS_getsockopt)(uint64(fd_a), uint64(level),
                uint64(name), uint64(buf), uint64(lenp)))
        end)

        local actual_len = safe_rd(lenp)
        if ok and to_num(rv) == 0 and actual_len ~= nil and actual_len > 0 then
            -- Scan returned data for kernel pointers
            local kptrs = 0
            local data_summary = ""
            for i = 0, math.min(actual_len, 0xFF) - 1, 8 do
                local qv = safe_rq(buf + i)
                if is_kptr(qv) then
                    kptrs = kptrs + 1
                    data_summary = data_summary .. " KPTR@+" .. string.format("%02X", i)
                end
            end

            local first_dword = safe_rd(buf) or 0
            print("[B] " .. label .. ": ret=0 len=" .. actual_len ..
                  " val[0]=0x" .. string.format("%X", first_dword) .. data_summary)

            if kptrs > 0 or actual_len > 32 then
                -- Full dump for interesting options
                print("[B]   full dump:")
                for i = 0, math.min(actual_len + 8, 0x7F), 8 do
                    local qv = safe_rq(buf + i)
                    local h, l = get_hi_lo(qv)
                    local m = ""
                    if is_kptr(qv) then m = " *** KPTR ***" end
                    if h == 0xDEADBEEF then m = " [sentinel]" end
                    print("[B]     +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
                end
            end
            total_kptrs = total_kptrs + kptrs
        elseif ok then
            -- Only print failures for potentially interesting options
            if label == "SO_LABEL" or label == "SO_PEERLABEL" or label == "LOCAL_PEERCRED" then
                print("[B] " .. label .. ": ret=" .. tostring(rv) .. " (blocked)")
            end
        end
    end
    print("[B] total kernel ptrs across all opts: " .. total_kptrs)
    print("")

    close_fd(fd_a); close_fd(fd_b)
until true

-- ============================================================
-- SECTION C: sockaddr_un padding scan
-- ============================================================
print("--- SECTION C: SOCKADDR_UN PADDING ---")
print("")

repeat
    local fd_a, fd_b = create_socketpair()
    if fd_a == nil then print("[C] socketpair FAILED"); break end

    -- getsockname on unnamed AF_LOCAL socketpair
    -- sockaddr_un is 106 bytes; kernel should write sun_len + sun_family + sun_path
    -- For unnamed socket, sun_path should be empty — but is padding zeroed?
    local name_buf = memory.alloc(0x80)
    for i = 0, 0x7F, 4 do safe_wd(name_buf + i, 0xDEADBEEF) end
    local namelen = memory.alloc(4)
    safe_wd(namelen, 0x80)

    local ok1, rv1 = pcall(function()
        return to_num(make_syscall(SYS_getsockname)(uint64(fd_a), uint64(name_buf), uint64(namelen)))
    end)
    local actual_len = safe_rd(namelen)
    print("[C] getsockname fd_a: ret=" .. tostring(rv1) .. " namelen=" .. tostring(actual_len))

    if ok1 and to_num(rv1) == 0 and actual_len ~= nil and actual_len > 0 then
        print("[C] sockaddr dump (" .. actual_len .. " bytes):")
        local kptrs = 0
        for i = 0, math.min(actual_len + 16, 0x7F), 8 do
            local qv = safe_rq(name_buf + i)
            local h, l = get_hi_lo(qv)
            local m = ""
            if is_kptr(qv) then m = " *** KPTR ***"; kptrs = kptrs + 1 end
            if h == 0xDEADBEEF then m = " [sentinel]" end
            print("[C]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
        end
        print("[C] kernel ptrs: " .. kptrs)
    end
    print("")

    -- getpeername
    for i = 0, 0x7F, 4 do safe_wd(name_buf + i, 0xDEADBEEF) end
    safe_wd(namelen, 0x80)

    local ok2, rv2 = pcall(function()
        return to_num(make_syscall(SYS_getpeername)(uint64(fd_a), uint64(name_buf), uint64(namelen)))
    end)
    actual_len = safe_rd(namelen)
    print("[C] getpeername fd_a: ret=" .. tostring(rv2) .. " namelen=" .. tostring(actual_len))

    if ok2 and to_num(rv2) == 0 and actual_len ~= nil and actual_len > 0 then
        print("[C] peer sockaddr dump (" .. actual_len .. " bytes):")
        local kptrs = 0
        for i = 0, math.min(actual_len + 16, 0x7F), 8 do
            local qv = safe_rq(name_buf + i)
            local h, l = get_hi_lo(qv)
            local m = ""
            if is_kptr(qv) then m = " *** KPTR ***"; kptrs = kptrs + 1 end
            if h == 0xDEADBEEF then m = " [sentinel]" end
            print("[C]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
        end
        print("[C] kernel ptrs: " .. kptrs)
    end
    print("")

    -- Also try getsockname on SOCK_DGRAM pair
    close_fd(fd_a); close_fd(fd_b)

    local sv = memory.alloc(8)
    safe_wd(sv, 0); safe_wd(sv + 4, 0)
    local ok_dg, rv_dg = pcall(function()
        return make_syscall(SYS_socketpair)(uint64(AF_LOCAL), uint64(SOCK_DGRAM),
            uint64(0), uint64(sv))
    end)
    if ok_dg and to_num(rv_dg) == 0 then
        local dg_a = safe_rd(sv)
        local dg_b = safe_rd(sv + 4)
        print("[C] SOCK_DGRAM pair: fd_a=" .. tostring(dg_a) .. " fd_b=" .. tostring(dg_b))

        for i = 0, 0x7F, 4 do safe_wd(name_buf + i, 0xDEADBEEF) end
        safe_wd(namelen, 0x80)
        local ok_dgn, rv_dgn = pcall(function()
            return to_num(make_syscall(SYS_getsockname)(uint64(dg_a), uint64(name_buf), uint64(namelen)))
        end)
        actual_len = safe_rd(namelen)
        print("[C] dgram getsockname: ret=" .. tostring(rv_dgn) .. " len=" .. tostring(actual_len))
        if ok_dgn and to_num(rv_dgn) == 0 and actual_len ~= nil and actual_len > 2 then
            for i = 0, math.min(actual_len + 8, 0x3F), 8 do
                local qv = safe_rq(name_buf + i)
                local m = ""
                if is_kptr(qv) then m = " *** KPTR ***" end
                if get_hi_lo(qv) == 0xDEADBEEF then m = " [sentinel]" end
                print("[C]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
            end
        end
        close_fd(dg_a); close_fd(dg_b)
    else
        print("[C] SOCK_DGRAM socketpair: ret=" .. tostring(rv_dg))
    end
until true
print("")

-- ============================================================
-- SECTION D: kevent event data deep scan
-- ============================================================
print("--- SECTION D: KEVENT EVENT DATA ---")
print("")

repeat
    local ok_kq, kq = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
    if not ok_kq or kq < 0 then print("[D] kqueue FAILED"); break end
    print("[D] kqueue fd=" .. kq)

    -- struct kevent = 32 bytes (0x20)
    -- +0x00: ident (8)   +0x08: filter (2) +0x0A: flags (2)
    -- +0x0C: fflags (4)  +0x10: data (8)   +0x18: udata (8)

    local EVFILT_READ  = -1
    local EVFILT_WRITE = -2
    local EVFILT_PROC  = -5
    local EVFILT_TIMER = -7
    local EVFILT_USER  = -11

    local EV_ADD      = 0x0001
    local EV_ENABLE   = 0x0004
    local EV_ONESHOT  = 0x0010
    local EV_CLEAR    = 0x0020

    local NOTE_EXIT   = 0x80000000
    local NOTE_FORK   = 0x40000000
    local NOTE_EXEC   = 0x20000000
    local NOTE_TRACK  = 0x00000001
    local NOTE_TRIGGER = 0x01000000
    local NOTE_MSECONDS = 0x00000000

    local function write_kevent(buf, ident, filter, flags, fflags, data, udata)
        safe_wq(buf, uint64(ident))
        -- filter is signed short at +8, flags is unsigned short at +10
        local filter_flags = 0
        if filter < 0 then
            filter_flags = (0x10000 + filter) + flags * 0x10000
        else
            filter_flags = filter + flags * 0x10000
        end
        safe_wd(buf + 8, filter_flags)
        safe_wd(buf + 0x0C, fflags)
        safe_wq(buf + 0x10, uint64(data))
        safe_wq(buf + 0x18, uint64(udata))
    end

    local function dump_kevent(tag, buf, count)
        local kptrs = 0
        for ev = 0, count - 1 do
            local base = buf + ev * 0x20
            local ident_q = safe_rq(base)
            local filter_flags = safe_rd(base + 8)
            local fflags = safe_rd(base + 0x0C)
            local data_q = safe_rq(base + 0x10)
            local udata_q = safe_rq(base + 0x18)

            local filter = 0
            local flags = 0
            if filter_flags ~= nil then
                filter = filter_flags % 0x10000
                if filter >= 0x8000 then filter = filter - 0x10000 end
                flags = math.floor(filter_flags / 0x10000)
            end

            print(tag .. " ev" .. ev .. ": ident=" .. fmt_addr(ident_q) ..
                  " filter=" .. tostring(filter) .. " flags=0x" .. string.format("%X", flags) ..
                  " fflags=0x" .. string.format("%X", fflags or 0))
            print(tag .. "   data=" .. fmt_addr(data_q) .. " udata=" .. fmt_addr(udata_q))

            if is_kptr(data_q) then
                print(tag .. "   *** DATA IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
            if is_kptr(udata_q) then
                print(tag .. "   *** UDATA IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
            if is_kptr(ident_q) then
                print(tag .. "   *** IDENT IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
        end
        return kptrs
    end

    local total_kptrs = 0

    -- D1: EVFILT_USER — register, trigger, poll
    print("[D] D1: EVFILT_USER register + trigger + poll")
    local change = memory.alloc(0x40)
    write_kevent(change, 42, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0xAAAA)
    local events = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    local ts = memory.alloc(16)
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_r, rv_r = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(0), uint64(ts)))
    end)
    print("[D] register EVFILT_USER: ret=" .. tostring(rv_r))

    -- Trigger it
    write_kevent(change, 42, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0)
    pcall(function()
        make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)

    -- Poll
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end
    local ok_p, rv_p = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(0), uint64(0),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] poll EVFILT_USER: ret=" .. tostring(rv_p) .. " (events returned)")
    if ok_p and to_num(rv_p) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_p))
    end
    print("")

    -- D2: EVFILT_TIMER — short timer poll
    print("[D] D2: EVFILT_TIMER register + poll")
    write_kevent(change, 99, EVFILT_TIMER, EV_ADD + EV_ONESHOT, NOTE_MSECONDS, 1, 0xBBBB)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    -- Register + immediate poll with 10ms timeout
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(10000000)) -- 10ms in nanoseconds
    local ok_t, rv_t = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_TIMER register+poll: ret=" .. tostring(rv_t))
    if ok_t and to_num(rv_t) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_t))
    end
    print("")

    -- D3: EVFILT_PROC on self
    print("[D] D3: EVFILT_PROC on self (pid=" .. pid .. ")")
    write_kevent(change, pid, EVFILT_PROC, EV_ADD + EV_CLEAR,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0xCCCC)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_proc, rv_proc = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_PROC register+poll: ret=" .. tostring(rv_proc))
    if ok_proc and to_num(rv_proc) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_proc))
    elseif ok_proc then
        print("[D] no events (expected — no fork/exec happened)")
    end
    print("")

    -- D4: EVFILT_PROC on pid=1 (init)
    print("[D] D4: EVFILT_PROC on pid=1 (init)")
    write_kevent(change, 1, EVFILT_PROC, EV_ADD + EV_CLEAR,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK, 0, 0xDDDD)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_init, rv_init = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_PROC pid=1 register+poll: ret=" .. tostring(rv_init))
    if ok_init and to_num(rv_init) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_init))
    end
    print("")

    -- D5: EVFILT_READ on socketpair (data available)
    print("[D] D5: EVFILT_READ on socketpair with data")
    local sp_a, sp_b = create_socketpair()
    if sp_a ~= nil then
        -- Write data to sp_b so sp_a has bytes to read
        local wbuf = memory.alloc(8)
        safe_wd(wbuf, 0x41424344)
        pcall(function()
            make_syscall(4)(uint64(sp_b), uint64(wbuf), uint64(4)) -- write(4)
        end)

        write_kevent(change, sp_a, EVFILT_READ, EV_ADD, 0, 0, 0xEEEE)
        for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

        safe_wq(ts, uint64(0))
        safe_wq(ts + 8, uint64(0))

        local ok_rd, rv_rd = pcall(function()
            return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
                uint64(events), uint64(4), uint64(ts)))
        end)
        print("[D] EVFILT_READ register+poll: ret=" .. tostring(rv_rd))
        if ok_rd and to_num(rv_rd) > 0 then
            total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_rd))
        end

        close_fd(sp_a); close_fd(sp_b)
    end

    print("")
    print("[D] total kernel pointers across all events: " .. total_kptrs)

    close_fd(kq)
until true

print("")
print("=== PROBE 109a COMPLETE ===")
