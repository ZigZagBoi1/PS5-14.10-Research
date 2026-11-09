-- CRASH_CLASS: LOW
-- Isolated fstat comparison across pseudo descriptor classes.
print("=== PROBE 109i: FSTAT FD CLASSES ===")
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

print("=== PROBE 109i COMPLETE ===")
