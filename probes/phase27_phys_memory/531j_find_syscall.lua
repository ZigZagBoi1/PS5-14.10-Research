-- CRASH_CLASS: LOW
-- PROBE 531j: Find MapDirectMemory syscall number
--
-- Strategy:
-- 1. libkernel .text is XO (can't read)
-- 2. But we can probe syscall numbers around 547-548 with correct args
-- 3. The raw syscall for MapDirectMemory should accept 6 args
-- 4. AllocateDirectMemory uses syscall 546 (confirmed in DEM9N101)
-- 5. MapDirectMemory likely uses 547 or 548
-- 6. Previous test (531e) got -1 from both, but maybe wrong arg format
--
-- FreeBSD/PS5 sceKernelMapDirectMemory:
--   arg1 = addr (void**, INOUT — kernel reads hint, writes result)
--   arg2 = len
--   arg3 = prot
--   arg4 = flags
--   arg5 = directMemoryStart (physical offset)
--   arg6 = alignment
--
-- For raw syscall: rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
-- (rcx is clobbered by syscall, so arg4 goes in r10)
-- BUT make_syscall might not set r10! It sets rcx.
-- This could be why 547/548 fail: arg4 (flags) goes to rcx not r10.
--
-- On FreeBSD, the syscall calling convention uses:
-- rdi, rsi, rdx, r10, r8, r9 for args 1-6
-- rcx is saved for return address by syscall instruction
--
-- So make_syscall(547)(arg1,arg2,arg3,arg4,arg5,arg6) puts:
-- arg4 → rcx (WRONG! Should be r10)
-- This means 4+ arg syscalls via make_syscall MIGHT NOT WORK for arg4!
--
-- Actually wait — the Lua loader's syscall mechanism might handle this.
-- Let's check: pipe(42) is a 1-arg syscall.
-- sysctl(202) is 6 args and works fine.
-- The loader probably does the rcx→r10 translation internally.
--
-- Let's try again with correct args. The issue might be alignment.

print("=== PROBE 531j: FIND SYSCALL ===")
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_base + uint64(0x17EF0)

-- ============================================================
-- [A] Allocate physical memory first
-- ============================================================
print("[A] Alloc")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  phys=%s", hexq(phys)))
if not phys or N(phys) == 0 then print("FAIL") return end

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
local phys_str = string.format("0x%X%08X", ph, pl)

-- ============================================================
-- [B] Try syscalls 547,548 with various arg layouts
-- Maybe the issue is that addr should be an INOUT pointer
-- (kernel reads a hint address, writes back the actual VA)
-- ============================================================
print("")
print("[B] Syscall 547/548 variations")

-- GPU mmap for buffer
local sc_477 = mk(477)
local gpu = sc_477(uint64(0), uint64(0x4000*4), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_n = N(gpu)
print(string.format("  gpu=0x%X", gpu_n))

for _, sc_num in ipairs({547, 548}) do
    local sc = mk(sc_num)

    -- Layout A: (va_out_ptr, len, prot, flags, phys, align) — like library
    local va_out = memory.alloc(8)
    wq(N(va_out), uint64(0))
    local ok_a, rv_a = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(0), uint64(phys_str), uint64(0x4000))
    end)
    local va_a = rq(N(va_out))
    print(string.format("  %d-A: rv=%s out=%s", sc_num,
        ok_a and hexq(rv_a) or "FAIL", hexq(va_a)))

    -- Layout B: with flags=0x10 (MAP_FIXED analog?)
    wq(N(va_out), uint64(gpu_n + 0x4000))
    local ok_b, rv_b = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(0x10), uint64(phys_str), uint64(0x4000))
    end)
    local va_b = rq(N(va_out))
    print(string.format("  %d-B(fixed): rv=%s out=%s", sc_num,
        ok_b and hexq(rv_b) or "FAIL", hexq(va_b)))

    -- Layout C: with flags=0x440000 (MAP_PREFAULT_READ|some Sony flag?)
    wq(N(va_out), uint64(0))
    local ok_c, rv_c = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(0x440000), uint64(phys_str), uint64(0x4000))
    end)
    print(string.format("  %d-C(440000): rv=%s", sc_num, ok_c and hexq(rv_c) or "FAIL"))

    -- Layout D: alignment = len (some implementations want this)
    wq(N(va_out), uint64(0))
    local ok_d, rv_d = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(0), uint64(phys_str), uint64(0))
    end)
    print(string.format("  %d-D(align=0): rv=%s", sc_num, ok_d and hexq(rv_d) or "FAIL"))
end

-- ============================================================
-- [C] Try the EXACT syscall number the library uses
-- From 13.60 CSV: look at syscall range 540-560
-- ============================================================
print("")
print("[C] Syscall range 540-560")

for sc_num = 540, 560 do
    local sc = mk(sc_num)
    local va_out = memory.alloc(8)
    wq(N(va_out), uint64(0))
    local ok_sc, rv_sc = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(0), uint64(phys_str), uint64(0x4000))
    end)
    local rv_str = "KILL"
    if ok_sc and rv_sc then
        local rvn = N(rv_sc)
        if rvn < 0 then rvn = rvn + 0x100000000 end
        rv_str = string.format("0x%X", rvn)
    end
    local va_v = rq(N(va_out))
    local va_changed = (va_v and N(va_v) ~= 0) and "VA!" or ""
    print(string.format("  %d: rv=%s %s", sc_num, rv_str, va_changed))
end

-- ============================================================
-- [D] Check errno after failures
-- Sony error 0x80020023 = EINVAL-like
-- ============================================================
print("")
print("[D] Detailed errors for 547/548")
for _, sc_num in ipairs({547, 548}) do
    local sc = mk(sc_num)
    -- With prot=1 (RO), flags=0, good phys, align=0x4000
    local va_out = memory.alloc(8)
    wq(N(va_out), uint64(0))
    local ok_e, rv_e = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(1),
            uint64(0), uint64(phys_str), uint64(0x4000))
    end)
    print(string.format("  %d(ro): rv=%s", sc_num, ok_e and hexq(rv_e) or "FAIL"))

    -- With prot=3, flags=1, phys, align=0x4000
    wq(N(va_out), uint64(0))
    ok_e, rv_e = pcall(function()
        return sc(uint64(N(va_out)), uint64(0x4000), uint64(3),
            uint64(1), uint64(phys_str), uint64(0x4000))
    end)
    print(string.format("  %d(f=1): rv=%s", sc_num, ok_e and hexq(rv_e) or "FAIL"))
end

print("")
print("=== 531j DONE ===")
