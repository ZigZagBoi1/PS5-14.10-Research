-- CRASH_CLASS: HIGH
-- PROBE 531b: MapDirectMemory read test
--
-- 531a: AllocateDirectMemory rv=0, phys=0x110010000
--        MapDirectMemory rv=0 (SUCCESS!) but output truncated before mapped_va
--
-- This probe:
-- 1. Allocate physical memory
-- 2. Map it with MapDirectMemory (6 args via fcall - 7th arg is garbage but rv=0!)
-- 3. Read the mapped VA carefully
-- 4. Write a pattern, read it back (confirm R/W)
-- 5. If works: try mapping at a different physical address (kernel region)

print("=== PROBE 531b: MAPDM READ ===")
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
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get libkernel base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk_base + uint64(0x17EF0)
local map_fn = lk_base + uint64(0x15020)

-- ============================================================
-- [A] Allocate physical memory
-- ============================================================
print("")
print("[A] AllocateDirectMemory")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  rv=%s phys=%s", ok_a and hexq(rv_a) or "FAIL", hexq(phys)))

if not phys or N(phys) == 0 then
    print("ALLOC FAILED")
    print("=== 531b DONE ===")
    return
end

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
print(string.format("  phys=0x%X%08X", ph, pl))

-- ============================================================
-- [B] MapDirectMemory
-- ============================================================
print("")
print("[B] MapDirectMemory")
local out_ptr = memory.alloc(8)
wq(N(out_ptr), uint64(0))
print("  calling map...")

local ok_m, rv_m = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(N(out_ptr)), uint64(0x4000), uint64(3),
        uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
end)
print(string.format("  map ok=%s rv=%s", tostring(ok_m), ok_m and hexq(rv_m) or "FAIL"))

local mapped = rq(N(out_ptr))
print(string.format("  out_ptr=%s", hexq(mapped)))

if not mapped or N(mapped) == 0 then
    print("MAP RETURNED ZERO VA")
    -- The rv was 0 (success) but VA is 0? Check if rv is actually an error code
    if rv_m then
        local rvn = N(rv_m)
        if rvn ~= 0 then
            print(string.format("  rv nonzero: %d (0x%X)", rvn, rvn))
        end
    end
    print("=== 531b DONE ===")
    return
end

local mh, ml = get_hi_lo(mapped)
if mh < 0 then mh = mh + 0x100000000 end
if ml < 0 then ml = ml + 0x100000000 end
print(string.format("  VA=0x%X%08X", mh, ml))

-- ============================================================
-- [C] Read from mapped physical memory
-- ============================================================
print("")
print("[C] Read mapped memory")
local mn = N(mapped)
for off = 0, 0x3C, 4 do
    local d = rd(mn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        print(string.format("  [+0x%02X] 0x%08X", off, d))
    else
        print(string.format("  [+0x%02X] FAULT", off))
        break
    end
end

-- ============================================================
-- [D] Write + Read back (confirm R/W)
-- ============================================================
print("")
print("[D] Write/Read test")
local test_val = 0xCAFEBABE
wd(mn, test_val)
local rb = rd(mn)
if rb then
    if rb < 0 then rb = rb + 0x100000000 end
    print(string.format("  wrote=0x%08X read=0x%08X match=%s",
        test_val, rb, rb == test_val and "YES" or "NO"))
else
    print("  read back FAULT")
end

-- ============================================================
-- [E] Try mapping a SECOND page at different phys addr
-- This tests if we can map arbitrary physical memory
-- ============================================================
print("")
print("[E] Second page allocation")
local phys2_out = memory.alloc(8)
wq(N(phys2_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys2_out)))
end)
local phys2 = rq(N(phys2_out))
print(string.format("  phys2=%s", hexq(phys2)))

if phys2 and N(phys2) ~= 0 then
    local p2h, p2l = get_hi_lo(phys2)
    if p2h < 0 then p2h = p2h + 0x100000000 end
    if p2l < 0 then p2l = p2l + 0x100000000 end

    local out2 = memory.alloc(8)
    wq(N(out2), uint64(0))
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(N(out2)), uint64(0x4000), uint64(3),
            uint64(0), uint64(string.format("0x%X%08X", p2h, p2l)), uint64(0x4000))
    end)
    print(string.format("  map2 rv=%s", ok2 and hexq(rv2) or "FAIL"))
    local m2 = rq(N(out2))
    print(string.format("  VA2=%s", hexq(m2)))

    if m2 and N(m2) ~= 0 then
        local d2 = rd(N(m2))
        if d2 then
            if d2 < 0 then d2 = d2 + 0x100000000 end
            print(string.format("  VA2[0]=0x%08X", d2))
        end
        -- Write different pattern
        wd(N(m2), 0xDEADBEEF)
        local rb2 = rd(N(m2))
        if rb2 then
            if rb2 < 0 then rb2 = rb2 + 0x100000000 end
            print(string.format("  VA2 write test: 0x%08X", rb2))
        end
    end
end

-- ============================================================
-- [F] Get DirectMemorySize for physical memory range
-- ============================================================
print("")
print("[F] GetDirectMemorySize")
local getsize_fn = lk_base + uint64(0x17810)
local ok_s, rv_s = pcall(function()
    return native.fcall_with_rax(getsize_fn, 0)
end)
print(string.format("  total=%s", ok_s and hexq(rv_s) or "FAIL"))

print("")
print("=== 531b DONE ===")
