-- CRASH_CLASS: LOW
-- PROBE 397d: munmap remap + madvise + double munmap
--
-- 397c: setsockopt WORKS on fresh instance, munmap=0 works, but read after
-- unmap kills past pcall. This version skips the dangerous read.
-- Tests: MAP_FIXED remap, madvise behaviors, double munmap.

print("=== PROBE 397d: remap + madvise ===")

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

-- Signal ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

-- ============================================
-- PART A: munmap + MAP_FIXED remap
-- ============================================
print("-- A: munmap + remap --")

local ok_m1, page1 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h1, l1 = 0, 0
if ok_m1 and page1 then h1, l1 = get_hi_lo(page1) end
print(string.format("page1=%X_%08X", h1, l1))

if h1 > 0 or l1 > 0 then
    local base1 = l1 + h1 * 0x100000000
    wd(base1, 0xAAAA1111)
    wd(base1 + 4, 0xBBBB2222)

    -- Unmap
    local ok_u1, rv_u1 = pcall(function()
        return mk(73)(page1, uint64(0x4000))
    end)
    print(string.format("munmap=%d", ok_u1 and N(rv_u1) or -999))

    -- DO NOT read the page. Remap with MAP_FIXED at same address.
    -- MAP_FIXED=0x10, MAP_ANON=0x1000, MAP_PRIVATE=0x2
    local ok_rm, page_rm = pcall(function()
        return mk(477)(page1, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local h_rm, l_rm = 0, 0
    if ok_rm and page_rm then h_rm, l_rm = get_hi_lo(page_rm) end
    print(string.format("remap=%X_%08X (want %X_%08X)", h_rm, l_rm, h1, l1))

    if h_rm == h1 and l_rm == l1 then
        -- Same address! Is it zeroed or does it have old data?
        local d0 = rd(base1) or 0xDEAD
        local d1 = rd(base1 + 4) or 0xDEAD
        print(string.format("remap_data=%08X %08X (was AAAA1111 BBBB2222)", d0, d1))
        -- Write to confirm it's writable
        wd(base1, 0xDEAD)
        print(string.format("write_check=%08X", rd(base1) or 0))
        pcall(function() mk(73)(page_rm, uint64(0x4000)) end)
    elseif h_rm > 0 or l_rm > 0 then
        print("remap at different address")
        pcall(function() mk(73)(page_rm, uint64(0x4000)) end)
    else
        print("remap FAILED")
    end
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: madvise behaviors
-- ============================================
print("")
print("-- B: madvise --")

local ok_m2, page2 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h2, l2 = 0, 0
if ok_m2 and page2 then h2, l2 = get_hi_lo(page2) end
print(string.format("page2=%X_%08X", h2, l2))

if h2 > 0 or l2 > 0 then
    local base2 = l2 + h2 * 0x100000000
    wd(base2, 0xCCCC)
    wd(base2 + 4, 0xDDDD)

    local advices = {
        {0, "NORMAL"}, {1, "RANDOM"}, {2, "SEQ"},
        {3, "WILLNEED"}, {4, "DONTNEED"}, {5, "FREE"},
        {6, "NOSYNC"}, {7, "AUTOSYNC"}, {8, "NOCORE"}, {9, "CORE"},
        {10, "PROTECT"}
    }
    for _, pair in ipairs(advices) do
        -- Re-write markers before each test
        wd(base2, 0xCCCC)
        wd(base2 + 4, 0xDDDD)
        local ok_a, rv_a = pcall(function()
            return mk(75)(page2, uint64(0x4000), uint64(pair[1]))
        end)
        local a_ret = ok_a and N(rv_a) or -999
        -- Check if data survived
        local d0 = rd(base2)
        local survived = (d0 == 0xCCCC) and "kept" or
                         (d0 == 0) and "ZEROED" or string.format("changed=%08X", d0 or 0)
        print(string.format("  %s(%d)=%d data=%s", pair[2], pair[1], a_ret, survived))
        if not alive() then print("CANARY FAIL madvise " .. pair[1]); return end
    end

    -- Final state after all madvise calls
    local final = rd(base2)
    print(string.format("final=%08X", final or 0xDEAD))
    pcall(function() mk(73)(page2, uint64(0x4000)) end)
end

-- ============================================
-- PART C: Double munmap
-- ============================================
print("")
print("-- C: double munmap --")

local ok_m3, page3 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_m3 and page3 then
    local ok_u1, rv_u1 = pcall(function()
        return mk(73)(page3, uint64(0x4000))
    end)
    print(string.format("munmap1=%d", ok_u1 and N(rv_u1) or -999))

    local ok_u2, rv_u2 = pcall(function()
        return mk(73)(page3, uint64(0x4000))
    end)
    print(string.format("munmap2=%d (expect -1)", ok_u2 and N(rv_u2) or -999))
end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: munmap subset of a larger mapping
-- ============================================
print("")
print("-- D: partial munmap --")

-- Map 4 pages (0x10000 = 64KB)
local ok_m4, page4 = pcall(function()
    return mk(477)(uint64(0), uint64(0x10000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local h4, l4 = 0, 0
if ok_m4 and page4 then h4, l4 = get_hi_lo(page4) end

if h4 > 0 or l4 > 0 then
    local base4 = l4 + h4 * 0x100000000
    -- Write markers in all 4 pages
    wd(base4, 0x1111)
    wd(base4 + 0x4000, 0x2222)
    wd(base4 + 0x8000, 0x3333)
    wd(base4 + 0xC000, 0x4444)
    print(string.format("4pages=%X_%08X marks=%X %X %X %X",
        h4, l4, rd(base4), rd(base4+0x4000), rd(base4+0x8000), rd(base4+0xC000)))

    -- Unmap just page 2 (offset +0x4000)
    local page2_addr = uint64(string.format("0x%X%08X", h4, l4 + 0x4000))
    local ok_up, rv_up = pcall(function()
        return mk(73)(page2_addr, uint64(0x4000))
    end)
    print(string.format("partial_munmap=%d", ok_up and N(rv_up) or -999))

    -- Pages 1,3,4 should still be readable
    local p1 = rd(base4)
    local p3 = rd(base4 + 0x8000)
    local p4 = rd(base4 + 0xC000)
    print(string.format("remaining: p1=%X p3=%X p4=%X (expect 1111 3333 4444)",
        p1 or 0xDEAD, p3 or 0xDEAD, p4 or 0xDEAD))

    -- Cleanup
    pcall(function() mk(73)(page4, uint64(0x4000)) end)  -- page 1
    local p3_addr = uint64(string.format("0x%X%08X", h4, l4 + 0x8000))
    pcall(function() mk(73)(p3_addr, uint64(0x8000)) end) -- pages 3+4
end

-- ============================================
-- PART E: sys 547 after munmap (check VM state)
-- ============================================
print("")
print("-- E: VM state after ops --")

local ok_m5, page5 = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_m5 and page5 then
    -- Query before munmap
    local qbuf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(qbuf) + i, 0) end
    local ok_q1, rv_q1 = pcall(function()
        return mk(547)(page5, uint64(N(qbuf)))
    end)
    local q1_prot = rd(N(qbuf)) or 0
    print(string.format("before: 547=%d prot=%X", ok_q1 and N(rv_q1) or -999, q1_prot))

    -- Munmap
    pcall(function() mk(73)(page5, uint64(0x4000)) end)

    -- Query after munmap
    for i = 0, 60, 4 do wd(N(qbuf) + i, 0) end
    local ok_q2, rv_q2 = pcall(function()
        return mk(547)(page5, uint64(N(qbuf)))
    end)
    local q2_prot = rd(N(qbuf)) or 0
    print(string.format("after:  547=%d prot=%X", ok_q2 and N(rv_q2) or -999, q2_prot))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 397d COMPLETE ===")
