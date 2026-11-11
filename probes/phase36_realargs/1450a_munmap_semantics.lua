-- CRASH_CLASS: LOW
-- PROBE 1450a: what munmap(73) actually removes
--
-- Context: probe 1446d (results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt)
--   mapped 0x4000, wrote canaries at every page, called munmap(base+0x3000, 0x1000) which returned 0,
--   and then faulted on a read at base -- i.e. the pages BELOW the requested range had gone too.
--   That is not POSIX behaviour and it invalidated the guard-page instrument used by 1446b/1446c.
--
--   Three explanations fit and they have very different consequences:
--     (i)   the handler ignores the address and removes the whole vm_map_entry that contains it;
--     (ii)  the handler removes [addr, end-of-entry) -- everything from addr upward;
--     (iii) the entry is removed but the page tables are not, or the reverse, leaving the map and the
--           PTEs inconsistent.  (iii) would be a page-level use-after-free: a page freed here while
--           still reachable through a stale mapping.
--
--   sys 547 (query_memory_protection) answers "is this VA inside a mapped region" WITHOUT touching
--   memory -- it writes {start, end, ..., prot} into a caller buffer and returns 0, or returns -1 when
--   the VA is not mapped.  So the map entry can be interrogated safely, and only the pages 547 still
--   claims are dereferenced afterwards.
--
-- -- prior art: 1446d (the anomaly), 1446b/1446c (void -- both built guard holes with munmap),
--   doc "sys 547 userland-only VM lookup" in CLAUDE.md and probes/phase34_kread_survey/1300a (the
--   547 call shape: 547(addr, region) with start at +0x00, end at +0x08, prot at +0x18).
--
-- Discriminator: [A] munmaps the FIRST page of a 4-page region.
--     (i)   all four pages answer -1,
--     (ii)  pages 0..0 answer -1 and 1..3 answer 0,
--     (iii) pages answer whatever the handler chose, and the canary read afterwards decides whether
--           the mapping that 547 still reports is backed by anything.
--   [C] munmaps a MIDDLE page, which separates (i) from (ii) no matter which way the handler rounds.

print("=== PROBE 1450a: MUNMAP SEMANTICS ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local MAP    = make_syscall(477)
local UNMAP  = make_syscall(73)
local QPROT  = make_syscall(547)
local GETPID = make_syscall(20)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sgn(rv) local n = to_num(rv) if n < 0 then return -1 end return n end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return (pcall(function() memory.write_dword(a, uint64(v)) end)) end
local function hex(n) if n == nil then return "----" end return string.format("0x%08X", n) end

local function mmap(len)
    local ok, va = pcall(function()
        return MAP(uint64(0), uint64(len), uint64(3), uint64(0x1002),
                   uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return -1 end
    local n = to_num(va)
    if n < 0x10000 or n > 0x8000000000 then return -1 end
    return n
end

local pid = sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("canary getpid=%d", pid))
print("")

local REG = nil
do
    local ok, a = pcall(function() return memory.alloc(0x100) end)
    if ok then REG = a end
end
if REG == nil then print("alloc failed"); return end

-- 547 probe: returns nil when unmapped, else {start, end, prot}
local function qprot(addr)
    local i = 0
    while i < 0x100 do wd(REG + i, 0) i = i + 4 end
    local ok, rv = pcall(function() return QPROT(uint64(addr), uint64(REG)) end)
    if not ok then return nil end
    if sgn(rv) ~= 0 then return nil end
    return { rd(REG), rd(REG + 4), rd(REG + 8), rd(REG + 0x18) }
end

local function desc(t)
    if t == nil then return "unmapped" end
    return string.format("mapped %s..%s", hex(t[1]), hex(t[3]))
end

-- safe read: only call when 547 says the page is mapped
local function peek(addr)
    local q = qprot(addr)
    if q == nil then return "unmapped(547)" end
    local v = rd(addr)
    if v == nil then return "read-failed" end
    return hex(v)
end

local function canaries(base)
    local i = 0
    while i < 4 do
        wd(base + i * 0x1000, 0xA0000000 + i)
        wd(base + i * 0x1000 + 0xFFC, 0xB0000000 + i)
        i = i + 1
    end
end

local function report(tag, base, pages)
    local i = 0
    while i < pages do
        local a = base + i * 0x1000
        print(string.format("   %s page %d @%s : %s", tag, i, hex(a), desc(qprot(a))))
        i = i + 1
    end
end

local function check(tag, base, pages)
    local i = 0
    while i < pages do
        local a = base + i * 0x1000
        print(string.format("   %s page %d @%s : %s  head=%s tail=%s",
            tag, i, hex(a), desc(qprot(a)), peek(a), peek(a + 0xFFC)))
        i = i + 1
    end
end

--------------------------------------------------------------------------
-- [A] munmap the FIRST page of a 4-page region
--------------------------------------------------------------------------
print("[A] map 0x4000, munmap(base, 0x1000)")
local A = mmap(0x4000)
print(string.format("   base=%s", hex(A)))
if A > 0 then
    canaries(A)
    print(string.format("   munmap rv=%s", tostring(sgn(UNMAP(uint64(A), uint64(0x1000),
        uint64(0), uint64(0), uint64(0), uint64(0))))))
    report("A", A, 4)
    check("A", A, 4)
end
print("")

--------------------------------------------------------------------------
-- [B] munmap the LAST page
--------------------------------------------------------------------------
print("[B] map 0x4000, munmap(base+0x3000, 0x1000)")
local B = mmap(0x4000)
print(string.format("   base=%s", hex(B)))
if B > 0 then
    canaries(B)
    print(string.format("   munmap rv=%s", tostring(sgn(UNMAP(uint64(B + 0x3000), uint64(0x1000),
        uint64(0), uint64(0), uint64(0), uint64(0))))))
    report("B", B, 4)
    check("B", B, 4)
end
print("")

--------------------------------------------------------------------------
-- [C] munmap a MIDDLE page
--------------------------------------------------------------------------
print("[C] map 0x4000, munmap(base+0x1000, 0x1000)")
local C = mmap(0x4000)
print(string.format("   base=%s", hex(C)))
if C > 0 then
    canaries(C)
    print(string.format("   munmap rv=%s", tostring(sgn(UNMAP(uint64(C + 0x1000), uint64(0x1000),
        uint64(0), uint64(0), uint64(0), uint64(0))))))
    report("C", C, 4)
    check("C", C, 4)
end
print("")

--------------------------------------------------------------------------
-- [D] two independent regions: does munmapping inside the first touch the second?
--------------------------------------------------------------------------
print("[D] two separate 0x4000 regions, munmap a sub-range of the first")
local D1 = mmap(0x4000)
local D2 = mmap(0x4000)
print(string.format("   D1=%s D2=%s", hex(D1), hex(D2)))
if D1 > 0 and D2 > 0 then
    canaries(D1)
    canaries(D2)
    print(string.format("   D2 before: %s", desc(qprot(D2))))
    print(string.format("   munmap(D1+0x2000) rv=%s", tostring(sgn(UNMAP(uint64(D1 + 0x2000), uint64(0x1000),
        uint64(0), uint64(0), uint64(0), uint64(0))))))
    report("D1", D1, 4)
    report("D2", D2, 4)
end
print("")

print(string.format("[E] survivor pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1450a COMPLETE ===")
