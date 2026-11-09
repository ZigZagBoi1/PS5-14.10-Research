-- CRASH_CLASS: LOW
-- PROBE 397b: test munmap(73) and madvise(75) on GPU mmap pages
--
-- If munmap works, we can do MAP/UNMAP races with concurrent child threads.
-- If madvise(MADV_DONTNEED=4) works, we can release physical pages without
-- unmapping the VA range — creating a window for double-map or stale TLB.
-- Also test mprotect to verify the fd allocation issue doesn't affect these.

print("=== PROBE 397b: munmap + madvise ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end return nil
end
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

-- ============================================
-- PART A: Map a GPU page, write to it, munmap
-- ============================================
print("")
print("-- GPU mmap + munmap test --")

local sc_mmap = mk(477)
local ok_m, gpu_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local gpu_addr = ok_m and gpu_page or nil
local h, l = 0, 0
if gpu_addr then h, l = get_hi_lo(gpu_addr) end
print(string.format("mmap=%X_%08X", h, l))

if h > 0 or l > 0 then
    -- Write a marker
    wd(l + h * 0x100000000, 0xDEAD)
    local check = rd(l + h * 0x100000000)
    print(string.format("write_check=%08X (expect DEAD)", check or 0))

    -- Try munmap(73) on this page
    local ok_u, rv_u = pcall(function()
        return mk(73)(gpu_addr, uint64(0x4000))
    end)
    local u_ret = ok_u and N(rv_u) or -999
    print(string.format("munmap=%d", u_ret))

    if u_ret == 0 then
        -- Page unmapped. Try reading — should crash or return different data
        local ok_r, rv_r = pcall(function()
            return memory.read_dword(l + h * 0x100000000)
        end)
        print(string.format("read_after_unmap: ok=%s val=%s", tostring(ok_r),
            ok_r and string.format("%08X", N(rv_r)) or "CRASH"))
    end
    if not alive() then print("CANARY FAIL"); return end
end

-- ============================================
-- PART B: Map another page, test madvise
-- ============================================
print("")
print("-- madvise test --")

local ok_m2, gpu_page2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local addr2 = ok_m2 and gpu_page2 or nil
local h2, l2 = 0, 0
if addr2 then h2, l2 = get_hi_lo(addr2) end
print(string.format("mmap2=%X_%08X", h2, l2))

if h2 > 0 or l2 > 0 then
    local base2 = l2 + h2 * 0x100000000
    wd(base2, 0xBEEF)
    local check2 = rd(base2)
    print(string.format("write_check2=%08X", check2 or 0))

    -- MADV_NORMAL=0, MADV_RANDOM=1, MADV_SEQUENTIAL=2, MADV_WILLNEED=3,
    -- MADV_DONTNEED=4, MADV_FREE=5, MADV_NOSYNC=6, MADV_AUTOSYNC=7,
    -- MADV_NOCORE=8, MADV_CORE=9, MADV_PROTECT=10
    local advices = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    for _, adv in ipairs(advices) do
        local ok_a, rv_a = pcall(function()
            return mk(75)(addr2, uint64(0x4000), uint64(adv))
        end)
        local a_ret = ok_a and N(rv_a) or -999
        local names = {"NORMAL","RANDOM","SEQUENTIAL","WILLNEED","DONTNEED",
                       "FREE","NOSYNC","AUTOSYNC","NOCORE","CORE","PROTECT"}
        print(string.format("  madvise(%s=%d)=%d", names[adv+1] or "?", adv, a_ret))
        if not alive() then print("CANARY FAIL after madvise " .. adv); return end
    end

    -- Check if MADV_DONTNEED zeroed the data
    local after = rd(base2)
    print(string.format("data_after_dontneed=%08X (was BEEF)", after or 0))
end

-- ============================================
-- PART C: Map anonymous via mk(477), verify
-- Then test MAP_ANON via mk(9) [mmap syscall]
-- ============================================
print("")
print("-- anon mmap via sys 9 --")

-- FreeBSD mmap is syscall 477 on PS5, not 9
-- But standard FreeBSD mmap is 477 (or 197 for old ABI)
-- Let's try sys 477 with MAP_ANON | MAP_PRIVATE = 0x1000 | 0x2 = 0x1002
-- which is what we already use

-- Also try the fd=-1 anonymous pattern explicitly
local ok_m3, anon_page = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h3, l3 = 0, 0
if ok_m3 and anon_page then h3, l3 = get_hi_lo(anon_page) end
print(string.format("anon_mmap=%X_%08X ret=%s", h3, l3,
    ok_m3 and tostring(N(anon_page)) or "FAIL"))

-- ============================================
-- PART D: Test if existing fds work
-- fd 0,1,2 = stdin/stdout/stderr (if they exist)
-- The loader's TCP socket should be some fd < 23
-- ============================================
print("")
print("-- existing fd test --")

-- fstat on fds 0-5 to find which are alive
for fd = 0, 10 do
    local sb = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(sb) + i, 0xCC) end
    local ok_f, rv_f = pcall(function()
        return mk(189)(uint64(fd), uint64(N(sb)))
    end)
    local f_ret = ok_f and N(rv_f) or -999
    if f_ret == 0 then
        local st_dev = rd(N(sb)) or 0
        local st_mode = rd(N(sb) + 8) or 0
        local st_nlink = rd(N(sb) + 12) or 0
        local ftype = st_mode % 0x10000 - st_mode % 0x1000
        local tname = ftype == 0xC000 and "SOCK" or
                      ftype == 0x1000 and "PIPE" or
                      ftype == 0x8000 and "REG" or
                      ftype == 0x2000 and "CHR" or string.format("%04X", ftype)
        print(string.format("  fd %d: mode=%04X type=%s", fd, st_mode, tname))
    elseif f_ret == -1 then
        -- fd doesn't exist or fstat blocked
    else
        print(string.format("  fd %d: fstat=%d", fd, f_ret))
    end
end

-- Also check fd 22-25 (around the problematic fd 23)
for fd = 20, 25 do
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
                      ftype == 0x2000 and "CHR" or string.format("%04X", ftype)
        print(string.format("  fd %d: mode=%04X type=%s", fd, st_mode, tname))
    end
end

-- ============================================
-- PART E: mprotect on GPU page (should work)
-- Verify non-fd kernel calls still function
-- ============================================
print("")
print("-- mprotect verify --")

if h3 > 0 or l3 > 0 then
    -- mprotect to RW (0x3) — same as current, should be noop
    local ok_p, rv_p = pcall(function()
        return mk(74)(anon_page, uint64(0x4000), uint64(0x3))
    end)
    print(string.format("mprotect(RW)=%d", ok_p and N(rv_p) or -999))

    -- mprotect to R only (0x1)
    local ok_p2, rv_p2 = pcall(function()
        return mk(74)(anon_page, uint64(0x4000), uint64(0x1))
    end)
    print(string.format("mprotect(R)=%d", ok_p2 and N(rv_p2) or -999))

    -- Try to write (should fail after mprotect to R)
    local ok_w = pcall(function() memory.write_dword(l3 + h3 * 0x100000000, 0xDEAD) end)
    print(string.format("write_after_R=%s", tostring(ok_w)))

    -- Restore to RW
    local ok_p3, rv_p3 = pcall(function()
        return mk(74)(anon_page, uint64(0x4000), uint64(0x3))
    end)
    print(string.format("mprotect(RW_restore)=%d", ok_p3 and N(rv_p3) or -999))
end

-- ============================================
-- PART F: sys 547 query memory protection
-- Verify VM operations still work
-- ============================================
print("")
print("-- sys 547 query --")

if h3 > 0 or l3 > 0 then
    local qbuf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(qbuf) + i, 0) end
    local ok_q, rv_q = pcall(function()
        return mk(547)(anon_page, uint64(N(qbuf)))
    end)
    local q_ret = ok_q and N(rv_q) or -999
    local q0 = rd(N(qbuf)) or 0
    local q1 = rd(N(qbuf) + 4) or 0
    local q2 = rd(N(qbuf) + 8) or 0
    print(string.format("547(query)=%d prot=%X %X %X", q_ret, q0, q1, q2))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 397b COMPLETE ===")
