-- CRASH_CLASS: LOW
-- PROBE 56k: Investigate mprotect ret=0 on kernel addresses
--
-- 56f found: mprotect(74) returns ret=0 for kernel addresses (0xFFFF8xxx+)
-- with sys 624 delta=1. This is anomalous — FreeBSD should reject addresses
-- outside the process's VM map.
--
-- Questions:
-- 1. Does ret=0 actually change any protection? (sys 547 before/after)
-- 2. Does the return value vary by kernel address? (KASLR oracle?)
-- 3. Does the protection argument matter? (RW, RX, RWX, NONE)
-- 4. Does the size argument matter?
-- 5. What about addresses just below kernel space?
-- 6. Does it work on user-unmapped addresses too?

print("=== PROBE 56k: MPROTECT KERNEL ANOMALY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc74 = mk(74)   -- mprotect
local sc547 = mk(547)  -- query_memory_protection
local sc624 = mk(624)  -- VM op counter

local function get_624()
    local ok2, v = pcall(function() return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok2 then return N(v) end return -1
end

local function query_prot(addr)
    local pbuf = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(pbuf) + i, 0) end
    local ok2, rv = pcall(function()
        return sc547(addr, uint64(N(pbuf)))
    end)
    local ret = ok2 and N(rv) or -999
    local prot = rd(N(pbuf))
    local flags = rd(N(pbuf) + 4)
    return ret, prot, flags
end

-- ============ SECTION A: Baseline — mprotect on known mappings ============
print("--- A: Baseline on known mappings ---")

-- Get a GPU mmap page
local sc477 = mk(477)
local gpu = sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_a = N(gpu)
print(string.format("  gpu_page=0x%X", gpu_a))

-- Check its current protection
local qr, qp, qf = query_prot(uint64(gpu_a))
print(string.format("  547(gpu): ret=%d prot=0x%X flags=0x%X", qr, qp or 0, qf or 0))

-- mprotect gpu page to PROT_READ (1)
local ok, ret = pcall(function() return sc74(uint64(gpu_a), uint64(0x4000), uint64(1)) end)
print(string.format("  mprotect(gpu, READ): ret=%d", ok and N(ret) or -999))

-- Check protection changed
qr, qp, qf = query_prot(uint64(gpu_a))
print(string.format("  547(gpu) after: ret=%d prot=0x%X flags=0x%X", qr, qp or 0, qf or 0))

-- Restore to RW
pcall(function() sc74(uint64(gpu_a), uint64(0x4000), uint64(3)) end)

if not alive() then print("DEAD"); return end

-- ============ SECTION B: mprotect on kernel addresses — ret value sweep ============
print("")
print("--- B: mprotect on kernel addresses ---")

local kern_addrs = {
    {name = "kern_8000_0",   hi = 0xFFFF8000, lo = 0x00000000},
    {name = "kern_9000_0",   hi = 0xFFFF9000, lo = 0x00000000},
    {name = "kern_A000_0",   hi = 0xFFFFA000, lo = 0x00000000},
    {name = "kern_C000_0",   hi = 0xFFFFC000, lo = 0x00000000},
    {name = "kern_F800_0",   hi = 0xFFFFF800, lo = 0x00000000},
    {name = "kern_F800_1M",  hi = 0xFFFFF800, lo = 0x00100000},
    {name = "kern_F800_10M", hi = 0xFFFFF800, lo = 0x01000000},
    {name = "kern_FFFF_0",   hi = 0xFFFFFFFF, lo = 0x00000000},
    {name = "user_high",     hi = 0x0000000F, lo = 0x00000000},
    {name = "user_unmapped",  hi = 0x00000100, lo = 0x00000000},
}

-- PROT_NONE=0, PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
local prots = {
    {name="NONE", val=0},
    {name="READ", val=1},
    {name="RW",   val=3},
    {name="RX",   val=5},
    {name="RWX",  val=7},
}

for _, ka in ipairs(kern_addrs) do
    local addr = uint64(string.format("0x%08X%08X", ka.hi, ka.lo))

    -- 547 query first
    local qr547, qp547, qf547 = query_prot(addr)

    local results = {}
    for _, p in ipairs(prots) do
        local b624 = get_624()
        ok, ret = pcall(function() return sc74(addr, uint64(0x4000), uint64(p.val)) end)
        local rv = ok and N(ret) or -999
        local d624 = get_624() - b624
        results[#results + 1] = string.format("%s=%d(d%d)", p.name, rv, d624)
    end

    print(string.format("  %-16s 547:ret=%d p=0x%X | %s",
        ka.name, qr547, qp547 or 0, table.concat(results, " ")))

    if not alive() then print("DEAD"); return end
end

-- ============ SECTION C: Size sensitivity ============
print("")
print("--- C: Size sensitivity on kernel address ---")

local kaddr = uint64(string.format("0x%08X%08X", 0xFFFFF800, 0))
local sizes = {0, 0x1000, 0x4000, 0x10000, 0x100000, 0x1000000, 0x10000000}

for _, sz in ipairs(sizes) do
    ok, ret = pcall(function() return sc74(kaddr, uint64(sz), uint64(1)) end)
    local rv = ok and N(ret) or -999
    print(string.format("  mprotect(kern_F800, 0x%X, READ): ret=%d", sz, rv))
    if not alive() then print("DEAD"); return end
end

-- ============ SECTION D: Does mprotect ret=0 change 547? ============
-- If mprotect actually changes protection on a kernel page, that's exploitable.
-- Call 547 before, mprotect, 547 after on the SAME kernel address.
print("")
print("--- D: 547 before/after mprotect on kernel ---")

local test_kaddrs = {
    {hi = 0xFFFFF800, lo = 0x00000000},
    {hi = 0xFFFF8000, lo = 0x00000000},
    {hi = 0xFFFFFF00, lo = 0x00000000},
}

for _, ka in ipairs(test_kaddrs) do
    local addr = uint64(string.format("0x%08X%08X", ka.hi, ka.lo))
    local name = string.format("0x%08X%08X", ka.hi, ka.lo)

    -- Before
    local br, bp, bf = query_prot(addr)

    -- mprotect to RW
    pcall(function() sc74(addr, uint64(0x4000), uint64(3)) end)

    -- After
    local ar, ap, af = query_prot(addr)

    print(string.format("  %s: before=ret%d/p0x%X → after=ret%d/p0x%X %s",
        name, br, bp or 0, ar, ap or 0,
        (bp ~= ap) and "*** CHANGED ***" or "(same)"))

    if not alive() then print("DEAD"); return end
end

-- ============ SECTION E: Boundary scan — where does ret=0 start? ============
-- Find the exact address boundary where mprotect switches from -1 to 0
print("")
print("--- E: Address boundary (where does ret=0 start?) ---")

local boundary_tests = {
    {hi = 0x00000010, lo = 0x00000000},  -- userland high
    {hi = 0x00000100, lo = 0x00000000},
    {hi = 0x00001000, lo = 0x00000000},
    {hi = 0x00010000, lo = 0x00000000},
    {hi = 0x00100000, lo = 0x00000000},
    {hi = 0x00800000, lo = 0x00000000},
    {hi = 0x7FFF0000, lo = 0x00000000},
    {hi = 0x7FFFFFFF, lo = 0x00000000},
    {hi = 0x80000000, lo = 0x00000000},
    {hi = 0xFFFF0000, lo = 0x00000000},
    {hi = 0xFFFF7FFF, lo = 0x00000000},
    {hi = 0xFFFF8000, lo = 0x00000000},
    {hi = 0xFFFF8001, lo = 0x00000000},
}

for _, bt in ipairs(boundary_tests) do
    local addr = uint64(string.format("0x%08X%08X", bt.hi, bt.lo))
    ok, ret = pcall(function() return sc74(addr, uint64(0x4000), uint64(1)) end)
    local rv = ok and N(ret) or -999
    print(string.format("  0x%08X%08X: ret=%d", bt.hi, bt.lo, rv))
    if not alive() then print("DEAD"); return end
end

-- ============ SECTION F: mprotect on unmapped userland addresses ============
print("")
print("--- F: mprotect on unmapped userland ---")

-- These are unmapped but in userland VA space
local unmapped = {
    {name = "0x1_00000000",   hi = 0x00000001, lo = 0x00000000},
    {name = "0x42_00000000",  hi = 0x00000042, lo = 0x00000000},
    {name = "0x200_00000000", hi = 0x00000200, lo = 0x00000000},
    {name = "0x7FF_00000000", hi = 0x000007FF, lo = 0x00000000},
}

for _, u in ipairs(unmapped) do
    local addr = uint64(string.format("0x%08X%08X", u.hi, u.lo))
    ok, ret = pcall(function() return sc74(addr, uint64(0x4000), uint64(1)) end)
    local rv = ok and N(ret) or -999
    local b = get_624()
    print(string.format("  %-20s ret=%d", u.name, rv))
    if not alive() then print("DEAD"); return end
end

-- ============ DONE ============
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56k COMPLETE ===")
