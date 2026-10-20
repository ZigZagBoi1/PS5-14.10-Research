-- CRASH_CLASS: LOW
-- Isolated getsockopt option copyout survey on AF_LOCAL socketpair.
print("=== PROBE 109g: GETSOCKOPT SURVEY ===")
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

print("=== PROBE 109g COMPLETE ===")
