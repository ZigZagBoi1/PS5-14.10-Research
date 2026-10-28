-- CRASH_CLASS: LOW
-- PROBE 532q: mmap_dmem(628) with errno — v2 minimal
--
-- 532n: errno=16 (EBUSY) for sys 628 with all-zeros args.
-- BUT: previous probe tests (330a/331a) with proper args got -1.
-- Question: what errno do we get with PROPER args?
--
-- From 13.60: mmap_dmem(addr, len, descriptor, prot, flags, offset)
--   desc=-1 bypasses device lookup
--   16KB alignment on addr, len, offset
--   prot mask 0x3f3
--   flags excluding 0x009fdf2f
--
-- We use AllocateDirectMemory first to get a real phys address.
-- Then test sys 628 with various descriptor/flag combos.

print("=== PROBE 532q: MMAP_DMEM V2 ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local error_fn = lk + uint64(0x02E10)
local alloc_fn = lk + uint64(0x17EF0)
print("lk=" .. q(lk))

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

-- Allocate physical memory
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("phys=" .. q(phys))

local sc_628 = make_syscall(628)
print("")

local function test(label, a1, a2, a3, a4, a5, a6)
    local ok_c, rv = pcall(function()
        return sc_628(a1, a2, a3, a4, a5, a6)
    end)
    local rvn = -999
    if ok_c then rvn = to_num(rv) end
    local errno = get_errno()
    local extra = ""
    if ok_c and rv and rvn >= 0 then
        extra = " VA=" .. q(rv)
    end
    print(string.format("  %-30s rv=%d e=%d%s", label, rvn, errno, extra))
end

-- desc=-1 (bypass device), phys offset, aligned
test("d=-1 phys prot=3 f=0",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), phys)

test("d=-1 phys f=0x40",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x40), phys)

test("d=-1 off=0 f=0",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64(0))

test("d=-1 off=0 f=0x40",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x40), uint64(0))

-- desc=22 (typical dmem0 fd from 330a)
test("d=22 phys f=0",
    uint64(0), uint64(0x4000), uint64(22),
    uint64(3), uint64(0), phys)

test("d=22 phys f=0x40",
    uint64(0), uint64(0x4000), uint64(22),
    uint64(3), uint64(0x40), phys)

-- desc=0 (stdin-ish)
test("d=0 phys f=0",
    uint64(0), uint64(0x4000), uint64(0),
    uint64(3), uint64(0), phys)

-- Try different prot values
test("d=-1 prot=1 f=0",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(1), uint64(0), phys)

test("d=-1 prot=0x33 f=0",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(0x33), uint64(0), phys)

-- flags: try all combos of low bits
test("d=-1 f=1",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(1), phys)

test("d=-1 f=2",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(2), phys)

test("d=-1 f=0x10",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x10), phys)

test("d=-1 f=0x20",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x20), phys)

-- All zeros with 0x4000 len
test("all_zero len=0x4000",
    uint64(0), uint64(0x4000), uint64(0),
    uint64(0), uint64(0), uint64(0))

-- Physical addr in system RAM range (below GPU pool)
test("d=-1 off=0x1000(sysRAM)",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64(0x1000))

test("d=-1 off=0x80000000",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64("0x80000000"))

print("")
print("=== 532q DONE ===")
