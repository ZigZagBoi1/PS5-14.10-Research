-- CRASH_CLASS: LOW
-- PROBE 50e3: Discriminate MSFILTER rejection
--
-- 50e2 showed ALL MSFILTER calls return -1. But we don't know if it's
-- ENOPROTOOPT (option missing) or EINVAL (handler exists, rejects args).
-- This probe tests known-working options to confirm setsockopt works,
-- then compares against a nonsense option number.

print("=== PROBE 50e3: MSFILTER DISCRIMINATE ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPV6_JOIN_GROUP = 12
local IPV6_UNICAST_HOPS = 4
local IPV6_MULTICAST_HOPS = 10
local IPV6_MULTICAST_LOOP = 11
local IPV6_MSFILTER = 74
local IPV6_V6ONLY = 27
local MCAST_INCLUDE = 1

local sc_socket = mk(97)
local sc_close = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Create UDPv6 socket
local ok_s, fd = pcall(function()
    return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
end)
fd = ok_s and N(fd) or -999
print("socket fd=" .. fd)
if fd < 0 then print("ABORT") return end

-- Join ff02::1 on if 1
local mreq = memory.alloc(32)
wd(N(mreq), 255 + 2 * 256)     -- addr[0-3]: ff02
wd(N(mreq) + 12, 16777216)     -- addr[12-15]: ::1
wd(N(mreq) + 16, 1)            -- ifindex=1
local ok_j, rv_j = pcall(function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_JOIN_GROUP), mreq, uint64(20))
end)
print("JOIN ret=" .. (ok_j and tostring(N(rv_j)) or "PFAIL"))

-- [A] Test known-working socket options
print("")
print("[A] Known-working setsockopt options")
local val4 = memory.alloc(16)
local vallen = memory.alloc(16)

local tests = {
    {IPV6_UNICAST_HOPS, 64, "UNICAST_HOPS=64"},
    {IPV6_MULTICAST_HOPS, 1, "MCAST_HOPS=1"},
    {IPV6_MULTICAST_LOOP, 0, "MCAST_LOOP=0"},
    {IPV6_V6ONLY, 1, "V6ONLY=1"},
}

for _, t in ipairs(tests) do
    local opt, val, label = t[1], t[2], t[3]
    wd(N(val4), val)
    local ok, rv = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(opt), val4, uint64(4))
    end)
    print(string.format("  setsockopt(%d) %s -> %s",
        opt, label, ok and tostring(N(rv)) or "PFAIL"))
end
if not alive() then print("DIED!") return end

-- [B] Test bogus option numbers
print("")
print("[B] Bogus option numbers (expect ENOPROTOOPT)")
for _, opt in ipairs({999, 200, 75, 73, 0}) do
    wd(N(val4), 0)
    local ok, rv = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(opt), val4, uint64(4))
    end)
    print(string.format("  setsockopt(opt=%d, len=4) -> %s",
        opt, ok and tostring(N(rv)) or "PFAIL"))
end
if not alive() then print("DIED!") return end

-- [C] MSFILTER with different sizes
print("")
print("[C] MSFILTER different sizes")
local big = memory.alloc(0x400)
local BIG = N(big)
for i = 0, 0x3FF, 4 do wd(BIG + i, 0) end
-- Fill with valid-looking msfr: ifindex=1, fmode=INCLUDE, nsrcs=0, group=ff02::1
wd(BIG, 1)
wd(BIG + 4, MCAST_INCLUDE)
wd(BIG + 8, 0)
-- group at +12
wd(BIG + 12, 28 + 28 * 256) -- sin6_len + sin6_family
wd(BIG + 20, 255 + 2 * 256) -- ff02
wd(BIG + 32, 16777216)       -- ::1

for _, sz in ipairs({4, 12, 16, 28, 140, 148, 256, 512}) do
    local ok, rv = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), big, uint64(sz))
    end)
    print(string.format("  MSFILTER size=%d -> %s",
        sz, ok and tostring(N(rv)) or "PFAIL"))
end
if not alive() then print("DIED!") return end

-- [D] getsockopt readback with various option numbers
print("")
print("[D] getsockopt readback")
for _, opt in ipairs({IPV6_UNICAST_HOPS, IPV6_MULTICAST_HOPS, IPV6_V6ONLY, IPV6_MSFILTER}) do
    local out = memory.alloc(256)
    local olen = memory.alloc(16)
    for i = 0, 252, 4 do wd(N(out) + i, 0) end
    wd(N(olen), 256)
    local ok, rv = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(opt), out, olen)
    end)
    local rval = rd(N(out)) or 0
    local rlen = rd(N(olen)) or 0
    print(string.format("  getsockopt(opt=%d) -> %s val=%d len=%d",
        opt, ok and tostring(N(rv)) or "PFAIL", rval, rlen))
end
if not alive() then print("DIED!") return end

-- [E] Also test MCAST_JOIN_GROUP (42) and MCAST_MSFILTER (72)
-- These are the newer RFC 3678 APIs
print("")
print("[E] RFC 3678 alternatives")
local MCAST_JOIN_GROUP = 42
local MCAST_BLOCK_SOURCE = 43
local MCAST_UNBLOCK_SOURCE = 44
local MCAST_LEAVE_GROUP = 45
local MCAST_JOIN_SOURCE_GROUP = 46
local MCAST_LEAVE_SOURCE_GROUP = 47
local MCAST_MSFILTER = 72

for _, item in ipairs({
    {MCAST_MSFILTER, 148, "MCAST_MSFILTER(72)"},
    {MCAST_JOIN_GROUP, 132, "MCAST_JOIN_GROUP(42)"},
    {MCAST_BLOCK_SOURCE, 260, "MCAST_BLOCK_SOURCE(43)"},
}) do
    local opt, sz, label = item[1], item[2], item[3]
    -- Reuse big buffer with valid-ish data
    local ok, rv = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(opt), big, uint64(sz))
    end)
    print(string.format("  setsockopt(%s, size=%d) -> %s",
        label, sz, ok and tostring(N(rv)) or "PFAIL"))
end
if not alive() then print("DIED!") return end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 50e3 COMPLETE ===")
