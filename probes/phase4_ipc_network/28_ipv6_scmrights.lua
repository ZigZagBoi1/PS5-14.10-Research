-- 14.10 Recon Probe 28: IPv6 raw sockets + SCM_RIGHTS deep probe
-- From probe 27:
--   - AF_INET6 RAW works (ip6_input_hbh UAF surface)
--   - SCM_RIGHTS fd passing works
--   - No threading (fork/rfork/thr_new all blocked)
--   - dup/dup2 blocked, fstat blocked
--
-- Part 1: IPv6 raw socket options (setsockopt surface)
-- Part 2: IPv6 ancillary data (sendmsg with IPv6 options)
-- Part 3: SCM_RIGHTS stress — pass many fds, close racing
-- Part 4: SCM_RIGHTS with invalid/closed fds

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: IPV6 + SCM_RIGHTS ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_socketpair = 135,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_bind = 104,
    sc_connect = 98,
    sc_sendto = 133,
    sc_recvfrom = 29,
})

local pid = syscall.sc_getpid():tonumber()

-- ============================================================
-- PART 1: IPv6 raw socket setsockopt surface
-- ============================================================
log("")
log("--- PART 1: IPv6 raw socket options ---")

-- Create IPv6 raw socket (proto=0 or specific)
local s6_ok, s6_ret = pcall(function()
    return syscall.sc_socket(28, 3, 0) -- AF_INET6, SOCK_RAW, proto 0
end)
local raw6_fd = -1
if s6_ok then
    raw6_fd = s6_ret:tonumber()
    log("  raw6 socket: fd=" .. raw6_fd)
end

if raw6_fd >= 0 then
    local optval = memory.alloc(256)
    local optlen = memory.alloc(8)

    -- IPPROTO_IPV6 = 41
    local IPV6 = 41

    -- Test key IPv6 socket options
    local ipv6_opts = {
        {1, "IPV6_UNICAST_HOPS"},
        {2, "IPV6_MULTICAST_IF"}, -- was IPV6_MULTICAST_IF on older
        {8, "IPV6_V6ONLY"},
        {18, "IPV6_RECVTCLASS"},
        {25, "IPV6_RECVPKTINFO"},
        {26, "IPV6_RECVHOPLIMIT"},
        {27, "IPV6_RECVRTHDR"},      -- receive routing header
        {28, "IPV6_RECVHOPOPTS"},    -- receive hop-by-hop opts ← THE TARGET
        {29, "IPV6_RECVDSTOPTS"},    -- receive destination opts
        {36, "IPV6_RTHDR"},          -- set routing header
        {39, "IPV6_HOPOPTS"},        -- set hop-by-hop options ← KEY
        {40, "IPV6_DSTOPTS"},        -- set destination options
        {41, "IPV6_RTHDRDSTOPTS"},   -- dest opts before routing hdr
        {50, "IPV6_PKTINFO"},
        {51, "IPV6_HOPLIMIT"},
        {52, "IPV6_NEXTHOP"},
        {54, "IPV6_TCLASS"},
        {61, "IPV6_ORIGDSTADDR"},
    }

    for _, opt in ipairs(ipv6_opts) do
        -- Try getsockopt first
        memory.write_qword(optlen, 256)
        for i = 0, 31, 8 do memory.write_qword(optval + i, 0) end

        local g_ok, g_ret = pcall(function()
            return syscall.sc_getsockopt(raw6_fd, IPV6, opt[1], optval, optlen)
        end)

        local info = ""
        if g_ok then
            local len = memory.read_qword(optlen):tonumber()
            local val = memory.read_dword(optval):tonumber()
            info = string.format("get:rv=%d len=%d val=%d", g_ret:tonumber(), len, val)
        else
            info = "get:ERR"
        end

        -- Try setsockopt (enable it)
        memory.write_dword(optval, 1) -- enable
        local s_ok, s_ret = pcall(function()
            return syscall.sc_setsockopt(raw6_fd, IPV6, opt[1], optval, 4)
        end)
        info = info .. " set:" .. (s_ok and "rv=" .. s_ret:tonumber() or "ERR")

        log(string.format("  %-22s %s", opt[2], info))
    end

    -- ============================================================
    -- PART 2: IPv6 HBH options via sendmsg ancillary data
    -- This is the ip6_input_hbh attack surface
    -- ============================================================
    log("")
    log("--- PART 2: IPv6 HBH ancillary data ---")

    -- First enable IPV6_HOPOPTS
    memory.write_dword(optval, 1)
    pcall(function() syscall.sc_setsockopt(raw6_fd, IPV6, 39, optval, 4) end)

    -- Build a hop-by-hop options header
    -- Format: next_header(1) + hdr_ext_len(1) + options...
    -- Option TLV: type(1) + length(1) + data(length)
    -- PadN option: type=1, length=N-2, data=zeros
    local hbh = memory.alloc(64)
    -- 8-byte HBH header with PadN
    memory.write_byte(hbh, 59)   -- next header = no next
    memory.write_byte(hbh + 1, 0) -- hdr_ext_len = 0 (8 bytes total)
    memory.write_byte(hbh + 2, 1) -- PadN option type
    memory.write_byte(hbh + 3, 4) -- PadN length = 4 (6 bytes total with TL)
    memory.write_dword(hbh + 4, 0) -- padding

    -- Build cmsg with IPV6_HOPOPTS
    local cmsg = memory.alloc(64)
    -- CMSG header: cmsg_len(4) + cmsg_level(4) + cmsg_type(4) then data at +16
    local CMSG_DATA_OFF = 16
    local hbh_len = 8
    memory.write_dword(cmsg, CMSG_DATA_OFF + hbh_len) -- cmsg_len = 24
    memory.write_dword(cmsg + 4, IPV6)     -- cmsg_level = IPPROTO_IPV6
    memory.write_dword(cmsg + 8, 39)       -- cmsg_type = IPV6_HOPOPTS
    -- Copy HBH data
    for i = 0, hbh_len - 1 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(hbh + i):tonumber())
    end

    -- Build target address (::1 = localhost IPv6)
    local dst = memory.alloc(32) -- sockaddr_in6
    memory.write_byte(dst, 28)   -- sin6_len
    memory.write_byte(dst + 1, 28) -- sin6_family = AF_INET6
    -- sin6_port at +2 = 0
    -- sin6_flowinfo at +4 = 0
    -- sin6_addr at +8 = ::1
    for i = 0, 15 do memory.write_byte(dst + 8 + i, 0) end
    memory.write_byte(dst + 23, 1) -- ::1

    -- Build iovec
    local payload = memory.alloc(8)
    memory.write_qword(payload, 0x4141414142424242)
    local iov = memory.alloc(16)
    memory.write_qword(iov, payload)
    memory.write_qword(iov + 8, 8)

    -- Build msghdr
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh, dst)         -- msg_name
    memory.write_dword(mh + 8, 28)      -- msg_namelen
    memory.write_qword(mh + 16, iov)    -- msg_iov
    memory.write_qword(mh + 24, 1)      -- msg_iovlen
    memory.write_qword(mh + 32, cmsg)   -- msg_control
    memory.write_qword(mh + 40, 32)     -- msg_controllen (CMSG_SPACE(8))

    local sm_ok, sm_ret = pcall(function()
        return syscall.sc_sendmsg(raw6_fd, mh, 0)
    end)
    log("  sendmsg with HBH: " .. (sm_ok and "rv=" .. sm_ret:tonumber() or "ERR"))

    -- Try with malformed HBH (oversized length)
    memory.write_byte(hbh + 1, 255) -- hdr_ext_len = 255 (2048 bytes claimed)
    for i = 0, hbh_len - 1 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(hbh + i):tonumber())
    end
    local sm2_ok, sm2_ret = pcall(function()
        return syscall.sc_sendmsg(raw6_fd, mh, 0)
    end)
    log("  sendmsg malformed HBH: " .. (sm2_ok and "rv=" .. sm2_ret:tonumber() or "ERR"))

    -- Try with large HBH option value
    memory.write_byte(hbh + 1, 1) -- hdr_ext_len=1 (16 bytes)
    memory.write_byte(hbh + 2, 0xC2) -- option type with "change" flag
    memory.write_byte(hbh + 3, 10)   -- option data length = 10
    memory.write_dword(cmsg, CMSG_DATA_OFF + 16) -- cmsg_len = 32
    memory.write_qword(mh + 40, 40) -- controllen
    for i = 0, 15 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(hbh + i):tonumber())
    end
    local sm3_ok, sm3_ret = pcall(function()
        return syscall.sc_sendmsg(raw6_fd, mh, 0)
    end)
    log("  sendmsg change-flag HBH: " .. (sm3_ok and "rv=" .. sm3_ret:tonumber() or "ERR"))

    pcall(function() syscall.sc_close(raw6_fd) end)
end

-- ============================================================
-- PART 3: SCM_RIGHTS stress — pass many fds
-- ============================================================
log("")
log("--- PART 3: SCM_RIGHTS stress ---")

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local ssa = memory.read_dword(sp):tonumber()
local ssb = memory.read_dword(sp + 4):tonumber()
log(string.format("  control pair: %d,%d", ssa, ssb))

-- Create a bunch of sockets to pass
local pass_fds = {}
for i = 1, 10 do
    local tmp = memory.alloc(8)
    pcall(function() syscall.sc_socketpair(1, 1, 0, tmp) end)
    local fa = memory.read_dword(tmp):tonumber()
    local fb = memory.read_dword(tmp + 4):tonumber()
    pass_fds[#pass_fds+1] = fa
    pass_fds[#pass_fds+1] = fb
end
log("  created " .. #pass_fds .. " fds to pass")

-- Pass multiple fds at once (up to 20 fds in one SCM_RIGHTS msg)
local n_pass = math.min(#pass_fds, 16)
local cmsg_multi = memory.alloc(256)
local cmsg_data_off = 16
local cmsg_total = cmsg_data_off + n_pass * 4
memory.write_dword(cmsg_multi, cmsg_total) -- cmsg_len
memory.write_dword(cmsg_multi + 4, 0xFFFF) -- SOL_SOCKET
memory.write_dword(cmsg_multi + 8, 1)       -- SCM_RIGHTS
for i = 0, n_pass - 1 do
    memory.write_dword(cmsg_multi + cmsg_data_off + i * 4, pass_fds[i + 1])
end

-- Align CMSG_SPACE
local cmsg_space = cmsg_total
if cmsg_space % 8 ~= 0 then cmsg_space = cmsg_space + (8 - cmsg_space % 8) end

local payload = memory.alloc(4)
memory.write_dword(payload, 0xBEEF)
local iov = memory.alloc(16)
memory.write_qword(iov, payload)
memory.write_qword(iov + 8, 4)

local mh_send = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh_send + i, 0) end
memory.write_qword(mh_send + 16, iov)
memory.write_qword(mh_send + 24, 1)
memory.write_qword(mh_send + 32, cmsg_multi)
memory.write_qword(mh_send + 40, cmsg_space)

local ms_ok, ms_ret = pcall(function() return syscall.sc_sendmsg(ssa, mh_send, 0) end)
log("  sendmsg " .. n_pass .. " fds: " ..
    (ms_ok and "rv=" .. ms_ret:tonumber() or "ERR"))

-- Receive them
local recv_cmsg = memory.alloc(256)
local recv_buf = memory.alloc(16)
local recv_iov = memory.alloc(16)
memory.write_qword(recv_iov, recv_buf)
memory.write_qword(recv_iov + 8, 16)

local mh_recv = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh_recv + i, 0) end
for i = 0, 255, 8 do memory.write_qword(recv_cmsg + i, 0) end
memory.write_qword(mh_recv + 16, recv_iov)
memory.write_qword(mh_recv + 24, 1)
memory.write_qword(mh_recv + 32, recv_cmsg)
memory.write_qword(mh_recv + 40, 256)

local mr_ok, mr_ret = pcall(function() return syscall.sc_recvmsg(ssb, mh_recv, 0) end)
if mr_ok then
    local rcv_len = memory.read_dword(recv_cmsg):tonumber()
    local rcv_n = (rcv_len - cmsg_data_off) / 4
    local fds_str = {}
    for i = 0, rcv_n - 1 do
        fds_str[#fds_str+1] = tostring(memory.read_dword(recv_cmsg + cmsg_data_off + i * 4):tonumber())
    end
    log(string.format("  recvmsg: %d fds received: %s", rcv_n, table.concat(fds_str, ",")))
end

-- ============================================================
-- PART 4: SCM_RIGHTS with already-closed fds
-- If kernel doesn't validate: refcount underflow
-- ============================================================
log("")
log("--- PART 4: SCM_RIGHTS closed fd ---")

-- Close some of the fds we're about to pass
local closed_fd = pass_fds[1]
pcall(function() syscall.sc_close(closed_fd) end)

-- Try to pass the closed fd
memory.write_dword(cmsg_multi, cmsg_data_off + 4) -- 1 fd
memory.write_dword(cmsg_multi + cmsg_data_off, closed_fd)
memory.write_qword(mh_send + 40, 24)

local mc_ok, mc_ret = pcall(function() return syscall.sc_sendmsg(ssa, mh_send, 0) end)
log("  sendmsg closed fd " .. closed_fd .. ": " ..
    (mc_ok and "rv=" .. mc_ret:tonumber() or "ERR"))

-- Try to pass fd -1 (invalid)
memory.write_dword(cmsg_multi + cmsg_data_off, 0xFFFFFFFF) -- -1
local mi_ok, mi_ret = pcall(function() return syscall.sc_sendmsg(ssa, mh_send, 0) end)
log("  sendmsg fd=-1: " .. (mi_ok and "rv=" .. mi_ret:tonumber() or "ERR"))

-- Try to pass fd 9999 (likely invalid)
memory.write_dword(cmsg_multi + cmsg_data_off, 9999)
local m9_ok, m9_ret = pcall(function() return syscall.sc_sendmsg(ssa, mh_send, 0) end)
log("  sendmsg fd=9999: " .. (m9_ok and "rv=" .. m9_ret:tonumber() or "ERR"))

-- Cleanup
pcall(function() syscall.sc_close(ssa) end)
pcall(function() syscall.sc_close(ssb) end)
for _, fd in ipairs(pass_fds) do
    pcall(function() syscall.sc_close(fd) end)
end

log("")
log("=== IPV6+SCM DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
