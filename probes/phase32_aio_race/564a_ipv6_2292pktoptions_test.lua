-- CRASH_CLASS: MODERATE
-- PROBE 564a: IPv6 IPV6_2292PKTOPTIONS capability test
--
-- Context: RE of Prolapse kexp_2026_05_25.bin reveals the kernel exploit uses
-- IPv6 setsockopt(IPV6_2292PKTOPTIONS) + routing header spray to UAF a ucred.
-- We have ZERO IPv6 probes. This tests basic AF_INET6 socket creation and
-- the critical socket options the exploit needs.
--
-- Tests:
--   [A] AF_INET6 SOCK_DGRAM creation
--   [B] AF_INET6 SOCK_STREAM creation
--   [C] AF_INET6 SOCK_RAW creation
--   [D] IPV6_2292PKTOPTIONS setsockopt (the exploit's core option)
--   [E] IPV6_PKTINFO setsockopt
--   [F] IPV6_RTHDR setsockopt (used for spray)
--   [G] IPV6_2292RTHDR setsockopt
--   [H] IPV6_DSTOPTS / IPV6_HOPOPTS
--   [I] Bulk socket creation (can we make many?)

print("=== PROBE 564a: IPv6 IPV6_2292PKTOPTIONS TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- Constants
local AF_INET6    = 28
local SOCK_DGRAM  = 2
local SOCK_STREAM = 1
local SOCK_RAW    = 3
local IPPROTO_IPV6 = 41
local IPPROTO_UDP  = 17

-- IPv6 socket option numbers (FreeBSD)
local IPV6_2292PKTOPTIONS = 6
local IPV6_PKTINFO        = 46  -- RFC 3542
local IPV6_RTHDR          = 51  -- RFC 3542
local IPV6_2292RTHDR      = 5   -- old API
local IPV6_DSTOPTS        = 59
local IPV6_HOPOPTS        = 49
local IPV6_2292HOPOPTS    = 3
local IPV6_2292DSTOPTS    = 4
local IPV6_TCLASS         = 61
local IPV6_RECVPKTINFO    = 36
local IPV6_RECVRTHDR      = 38

-- Helper: create socket
local function try_socket(family, stype, proto)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 97, uint64(family), uint64(stype), uint64(proto))
    end)
    if not ok then return -999 end
    local fd = N(rv)
    if fd < 0 then fd = -1 end
    return fd
end

-- Helper: close fd
local function close_fd(fd)
    if fd >= 0 then
        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
    end
end

-- Helper: setsockopt with buffer
local function try_setsockopt(fd, level, optname, optbuf, optlen)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 105,
            uint64(fd), uint64(level), uint64(optname),
            uint64(optbuf), uint64(optlen))
    end)
    if not ok then return -999 end
    return N(rv)
end

-- Helper: getsockopt
local function try_getsockopt(fd, level, optname, optbuf, optlenp)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 118,
            uint64(fd), uint64(level), uint64(optname),
            uint64(optbuf), uint64(optlenp))
    end)
    if not ok then return -999 end
    return N(rv)
end

-- ================================================================
-- [A] AF_INET6 SOCK_DGRAM
-- ================================================================
print("[A] AF_INET6 SOCK_DGRAM...")
io.flush()
local fd_dgram = try_socket(AF_INET6, SOCK_DGRAM, 0)
print("  fd=" .. fd_dgram)
if fd_dgram >= 0 then
    print("  AF_INET6 DGRAM: OK")
else
    print("  AF_INET6 DGRAM: BLOCKED")
end
io.flush()

-- ================================================================
-- [B] AF_INET6 SOCK_STREAM
-- ================================================================
print("[B] AF_INET6 SOCK_STREAM...")
io.flush()
local fd_stream = try_socket(AF_INET6, SOCK_STREAM, 0)
print("  fd=" .. fd_stream)
if fd_stream >= 0 then
    print("  AF_INET6 STREAM: OK")
else
    print("  AF_INET6 STREAM: BLOCKED")
end
io.flush()

-- ================================================================
-- [C] AF_INET6 SOCK_RAW
-- ================================================================
print("[C] AF_INET6 SOCK_RAW...")
io.flush()
local fd_raw6 = try_socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)
print("  fd=" .. fd_raw6)
if fd_raw6 >= 0 then
    print("  AF_INET6 RAW: OK")
else
    print("  AF_INET6 RAW: BLOCKED")
end
io.flush()

-- Use whichever socket we got for option tests
local test_fd = -1
if fd_dgram >= 0 then test_fd = fd_dgram
elseif fd_stream >= 0 then test_fd = fd_stream
elseif fd_raw6 >= 0 then test_fd = fd_raw6
end

if test_fd < 0 then
    print("")
    print("*** NO AF_INET6 SOCKETS AVAILABLE — IPv6 IS BLOCKED ***")
    print("=== 564a DONE (early) ===")
    return
end

print("")
print("Using fd=" .. test_fd .. " for option tests")
print("")

-- Allocate option buffers
local optbuf = memory.alloc(0x1000)
local optlenp = memory.alloc(8)

-- ================================================================
-- [D] IPV6_2292PKTOPTIONS — THE exploit option
-- ================================================================
print("[D] IPV6_2292PKTOPTIONS (opt 6) — THE exploit's core option...")
io.flush()

-- Try setsockopt with empty/small data
wd(N(optbuf), 0)
local rv_set = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, N(optbuf), 0)
print("  setsockopt(len=0): rv=" .. rv_set)

-- Try with some data
for i = 0, 63 do wd(N(optbuf) + i*4, 0) end
local rv_set4 = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, N(optbuf), 4)
print("  setsockopt(len=4): rv=" .. rv_set4)

local rv_set64 = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, N(optbuf), 64)
print("  setsockopt(len=64): rv=" .. rv_set64)

-- Try getsockopt
wd(N(optlenp), 0x400)
local rv_get = try_getsockopt(test_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, N(optbuf), N(optlenp))
local gotten_len = rb(N(optlenp)) or 0
print("  getsockopt: rv=" .. rv_get .. " len=" .. gotten_len)

if rv_set == 0 or rv_set4 == 0 or rv_set64 == 0 then
    print("  *** IPV6_2292PKTOPTIONS ACCEPTED! ***")
else
    print("  IPV6_2292PKTOPTIONS REFUSED (all calls returned error)")
end
io.flush()

-- ================================================================
-- [E] IPV6_PKTINFO
-- ================================================================
print("[E] IPV6_PKTINFO (opt 46)...")
io.flush()

-- struct in6_pktinfo { struct in6_addr addr; unsigned int ifindex; }
for i = 0, 19 do wb(N(optbuf) + i, 0) end
-- Set ifindex = 1
wd(N(optbuf) + 16, 1)
local rv_pktinfo = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_PKTINFO, N(optbuf), 20)
print("  setsockopt: rv=" .. rv_pktinfo)

-- Also try RECVPKTINFO (enable receiving)
wd(N(optbuf), 1)
local rv_recvpkt = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, N(optbuf), 4)
print("  RECVPKTINFO: rv=" .. rv_recvpkt)
io.flush()

-- ================================================================
-- [F] IPV6_RTHDR (opt 51) — used for spray
-- ================================================================
print("[F] IPV6_RTHDR (opt 51) — used for heap spray...")
io.flush()

-- Build a minimal routing header: type 2, segleft 1, 24 bytes
for i = 0, 23 do wb(N(optbuf) + i, 0) end
wb(N(optbuf) + 2, 2)  -- type = 2
wb(N(optbuf) + 3, 1)  -- segments_left = 1

local rv_rthdr = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_RTHDR, N(optbuf), 24)
print("  setsockopt(len=24): rv=" .. rv_rthdr)

-- Try empty
local rv_rthdr0 = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_RTHDR, N(optbuf), 0)
print("  setsockopt(len=0): rv=" .. rv_rthdr0)

-- Try RECVRTHDR
wd(N(optbuf), 1)
local rv_recvrthdr = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_RECVRTHDR, N(optbuf), 4)
print("  RECVRTHDR: rv=" .. rv_recvrthdr)
io.flush()

-- ================================================================
-- [G] IPV6_2292RTHDR (opt 5) — old API
-- ================================================================
print("[G] IPV6_2292RTHDR (opt 5) — old API routing header...")
io.flush()

for i = 0, 23 do wb(N(optbuf) + i, 0) end
wb(N(optbuf) + 2, 2)
wb(N(optbuf) + 3, 1)
local rv_2292rthdr = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_2292RTHDR, N(optbuf), 24)
print("  setsockopt(len=24): rv=" .. rv_2292rthdr)

local rv_2292rthdr0 = try_setsockopt(test_fd, IPPROTO_IPV6, IPV6_2292RTHDR, N(optbuf), 0)
print("  setsockopt(len=0): rv=" .. rv_2292rthdr0)
io.flush()

-- ================================================================
-- [H] IPV6_DSTOPTS / HOPOPTS
-- ================================================================
print("[H] IPV6_DSTOPTS/HOPOPTS/2292 variants...")
io.flush()

for i = 0, 7 do wb(N(optbuf) + i, 0) end
wb(N(optbuf) + 1, 0)  -- hdrlen = 0 (8 bytes total)

local opts_to_test = {
    {IPV6_HOPOPTS, "HOPOPTS(49)", 8},
    {IPV6_DSTOPTS, "DSTOPTS(59)", 8},
    {IPV6_2292HOPOPTS, "2292HOPOPTS(3)", 8},
    {IPV6_2292DSTOPTS, "2292DSTOPTS(4)", 8},
    {IPV6_TCLASS, "TCLASS(61)", 4},
}

for _, opt in ipairs(opts_to_test) do
    if opt[1] == IPV6_TCLASS then
        wd(N(optbuf), 0)
    end
    local rv = try_setsockopt(test_fd, IPPROTO_IPV6, opt[1], N(optbuf), opt[3])
    print(string.format("  %s: rv=%d", opt[2], rv))
end
io.flush()

-- ================================================================
-- [I] Bulk IPv6 socket creation
-- ================================================================
print("[I] Bulk AF_INET6 DGRAM creation (for spray)...")
io.flush()

local count = 0
local fds = {}
for i = 1, 100 do
    local fd = try_socket(AF_INET6, SOCK_DGRAM, 0)
    if fd >= 0 then
        count = count + 1
        fds[#fds + 1] = fd
    else
        break
    end
end
print("  created " .. count .. " sockets")

-- Close them all
for _, fd in ipairs(fds) do close_fd(fd) end

-- Close our test sockets
close_fd(fd_dgram)
close_fd(fd_stream)
close_fd(fd_raw6)

print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 564a DONE ===")
