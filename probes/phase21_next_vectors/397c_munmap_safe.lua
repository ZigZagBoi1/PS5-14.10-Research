-- CRASH_CLASS: LOW
-- PROBE 397c: munmap + madvise + fd survey (safe version)
--
-- 397b confirmed munmap=0 but crashed reading the freed page.
-- This version: SIGSEGV/SIGBUS ignore, fd survey, madvise tests,
-- MAP_FIXED after munmap to verify re-mapping works.

print("=== PROBE 397c: safe munmap ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Signal ignore: SIGSYS(12) + SIGSEGV(11) + SIGBUS(10)
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

-- ============================================
-- PART A: fd survey — fstat on fds 0-30
-- ============================================
print("")
print("-- fd survey --")
local found_fds = {}
for fd = 0, 30 do
    local sb = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(sb) + i, 0xCC) end
    local ok_f, rv_f = pcall(function()
        return mk(189)(uint64(fd), uint64(N(sb)))
    end)
    local f_ret = ok_f and N(rv_f) or -999
    if f_ret == 0 then
        local st_mode = rd(N(sb) + 8) or 0
        local ftype = st_mode % 0x10000 - st_mode % 0x1000
        local tname = ftype == 0xC000 and "SOCK" or
                      ftype == 0x1000 and "PIPE" or
                      ftype == 0x8000 and "REG" or
                      ftype == 0x2000 and "CHR" or
                      ftype == 0x4000 and "DIR" or
                      ftype == 0x6000 and "BLK" or string.format("%04X", ftype)
        print(string.format("  fd %2d: mode=%04X type=%s", fd, st_mode, tname))
        found_fds[#found_fds + 1] = fd
    end
end
print(string.format("total_fds=%d", #found_fds))

-- ============================================
-- PART B: Socket + setsockopt on THIS instance
-- ============================================
print("")
print("-- socket test --")
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(6))
end)
local tcp_fd = ok_s and N(rv_s) or -1
print(string.format("tcp_socket=%d", tcp_fd))

if tcp_fd >= 0 then
    -- fstat the new socket
    local sb2 = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(sb2) + i, 0xCC) end
    local ok_f2, rv_f2 = pcall(function()
        return mk(189)(uint64(tcp_fd), uint64(N(sb2)))
    end)
    local f2_ret = ok_f2 and N(rv_f2) or -999
    local st_mode2 = rd(N(sb2) + 8) or 0
    print(string.format("fstat(%d)=%d mode=%04X", tcp_fd, f2_ret, st_mode2))

    -- getsockopt(SO_TYPE)
    local gbuf = memory.alloc(16)
    wd(N(gbuf), 0xCC)
    local glenp = memory.alloc(8)
    wq(glenp, uint64(4))
    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(tcp_fd), uint64(0xFFFF), uint64(0x1008),
            uint64(N(gbuf)), uint64(N(glenp)))
    end)
    local g_ret = ok_g and N(rv_g) or -999
    local g_val = rd(N(gbuf)) or 0xCC
    print(string.format("getsockopt(SO_TYPE)=%d val=%X", g_ret, g_val))

    -- setsockopt(TCP_NODELAY)
    local optbuf = memory.alloc(16)
    wd(N(optbuf), 1)
    local ok_so, rv_so = pcall(function()
        return mk(105)(uint64(tcp_fd), uint64(6), uint64(1),
            uint64(N(optbuf)), uint64(4))
    end)
    print(string.format("setsockopt(TCP_NODELAY)=%d", ok_so and N(rv_so) or -999))

    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

-- ============================================
-- PART C: munmap + MAP_FIXED remap
-- ============================================
print("")
print("-- munmap + remap --")

-- Map page 1
local ok_m1, page1 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h1, l1 = 0, 0
if ok_m1 and page1 then h1, l1 = get_hi_lo(page1) end
print(string.format("page1=%X_%08X", h1, l1))

if h1 > 0 or l1 > 0 then
    local base1 = l1 + h1 * 0x100000000
    wd(base1, 0xAAAA)
    print(string.format("wrote=%08X", rd(base1) or 0))

    -- Unmap
    local ok_u, rv_u = pcall(function()
        return mk(73)(page1, uint64(0x4000))
    end)
    print(string.format("munmap=%d", ok_u and N(rv_u) or -999))

    -- Read after unmap (with SIGSEGV ignore)
    local ok_r = pcall(function() return memory.read_dword(base1) end)
    print(string.format("read_after_unmap=%s", tostring(ok_r)))

    -- Remap at same address with MAP_FIXED
    -- MAP_FIXED=0x10, MAP_ANON=0x1000, MAP_PRIVATE=0x2
    -- flags = 0x1012
    local ok_m2, page2 = pcall(function()
        return mk(477)(page1, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local h2, l2 = 0, 0
    if ok_m2 and page2 then h2, l2 = get_hi_lo(page2) end
    print(string.format("remap=%X_%08X (expect %X_%08X)", h2, l2, h1, l1))

    if h2 == h1 and l2 == l1 then
        -- New mapping at same address, should be zeroed
        local val = rd(base1)
        print(string.format("remap_data=%08X (expect 0, was AAAA)", val or 0xDEAD))
    elseif h2 > 0 or l2 > 0 then
        local base2 = l2 + h2 * 0x100000000
        wd(base2, 0xBBBB)
        print(string.format("remap_at_different=%X_%08X", h2, l2))
        pcall(function() mk(73)(page2, uint64(0x4000)) end)
    end
end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: madvise on live page
-- ============================================
print("")
print("-- madvise --")

local ok_m3, page3 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h3, l3 = 0, 0
if ok_m3 and page3 then h3, l3 = get_hi_lo(page3) end
print(string.format("page3=%X_%08X", h3, l3))

if h3 > 0 or l3 > 0 then
    local base3 = l3 + h3 * 0x100000000
    wd(base3, 0xCCCC)

    local advices = {
        {0, "NORMAL"}, {1, "RANDOM"}, {2, "SEQ"},
        {3, "WILLNEED"}, {4, "DONTNEED"}, {5, "FREE"},
        {6, "NOSYNC"}, {7, "AUTOSYNC"}, {8, "NOCORE"}, {9, "CORE"}
    }
    for _, pair in ipairs(advices) do
        local ok_a, rv_a = pcall(function()
            return mk(75)(page3, uint64(0x4000), uint64(pair[1]))
        end)
        print(string.format("  %s(%d)=%d", pair[2], pair[1], ok_a and N(rv_a) or -999))
    end

    -- Check data after DONTNEED
    local after = rd(base3)
    print(string.format("data_after=%08X (was CCCC)", after or 0xDEAD))

    pcall(function() mk(73)(page3, uint64(0x4000)) end)
end
if not alive() then print("CANARY FAIL D"); return end

-- ============================================
-- PART E: Double munmap (UAF test)
-- ============================================
print("")
print("-- double munmap --")

local ok_m4, page4 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h4, l4 = 0, 0
if ok_m4 and page4 then h4, l4 = get_hi_lo(page4) end
if h4 > 0 or l4 > 0 then
    -- First munmap
    local ok_u1, rv_u1 = pcall(function()
        return mk(73)(page4, uint64(0x4000))
    end)
    print(string.format("munmap1=%d", ok_u1 and N(rv_u1) or -999))

    -- Second munmap on same address (should fail: EINVAL)
    local ok_u2, rv_u2 = pcall(function()
        return mk(73)(page4, uint64(0x4000))
    end)
    print(string.format("munmap2=%d (expect -1)", ok_u2 and N(rv_u2) or -999))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 397c COMPLETE ===")
