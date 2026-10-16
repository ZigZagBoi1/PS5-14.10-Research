-- 14.10 Recon Probe 16: dmem0 mmap physical memory scan
-- Probe 15 showed mmap(dmem0, offset=0) succeeds with real data
-- Strategy: mmap at various offsets to map different physical pages
-- Look for kernel structures, page tables, process lists, cred structs

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: DMEM MMAP SCAN ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_open = 5, sc_close = 6,
    sc_mmap = 477, sc_munmap = 73,
    sc_getpid = 20,
})

local dmem_fd = -1
local ok, ret = pcall(function() return syscall.sc_open("/dev/dmem0", 2):tonumber() end)
if ok and ret >= 0 then dmem_fd = ret end
if dmem_fd < 0 then
    ok, ret = pcall(function() return syscall.sc_open("/dev/dmem0", 0):tonumber() end)
    if ok and ret >= 0 then dmem_fd = ret end
end
log("dmem0 fd: " .. dmem_fd)
if dmem_fd < 0 then
    log("FATAL: cannot open dmem0")
    return table.concat(out, "\n")
end

local PAGE = 0x4000 -- 16KB (PS5 uses 16KB pages)
local PROT_READ = 1
local PROT_RW = 3
local MAP_SHARED = 1

-- ============================================================
-- PART 1: Confirm base mapping and dump first page
-- ============================================================
log("")
log("--- PART 1: base mapping dump ---")

local base_ok, base_ret = pcall(function()
    return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, 0)
end)
local base_addr = 0
if base_ok then base_addr = base_ret:tonumber() end

if base_addr == 0 or base_addr == 0xFFFFFFFFFFFFFFFF then
    log("base mmap failed")
    -- Try with PROT_RW
    base_ok, base_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, PROT_RW, MAP_SHARED, dmem_fd, 0)
    end)
    if base_ok then base_addr = base_ret:tonumber() end
end

if base_addr ~= 0 and base_addr ~= 0xFFFFFFFFFFFFFFFF then
    log("mapped at " .. string.format("0x%x", base_addr))

    -- Dump first 256 bytes as qwords
    log("  first 256 bytes:")
    for i = 0, 248, 8 do
        local lo = memory.read_dword(base_addr + i):tonumber()
        local hi = memory.read_dword(base_addr + i + 4):tonumber()
        if lo ~= 0 or hi ~= 0 then
            log(string.format("    +%04x: %08x%08x", i, hi, lo))
        end
    end

    -- Scan full page for pointer-like values
    local ptrs = {}
    for i = 0, PAGE - 8, 8 do
        local lo = memory.read_dword(base_addr + i):tonumber()
        local hi = memory.read_dword(base_addr + i + 4):tonumber()
        if hi >= 0xFFFF0000 then
            ptrs[#ptrs + 1] = {off = i, hi = hi, lo = lo}
        end
    end
    if #ptrs > 0 then
        log("  kernel pointers found: " .. #ptrs)
        for j = 1, math.min(20, #ptrs) do
            local p = ptrs[j]
            log(string.format("    +%04x: 0x%08x%08x", p.off, p.hi, p.lo))
        end
    else
        log("  no kernel pointers in first page")
    end

    pcall(function() syscall.sc_munmap(base_addr, PAGE) end)
else
    log("base mmap failed completely")
end

-- ============================================================
-- PART 2: Scan offsets — map at various physical offsets
-- PS5 has 16GB RAM, so offsets up to 0x400000000
-- Try powers of 2 and interesting physical ranges
-- ============================================================
log("")
log("--- PART 2: offset scan ---")

local offsets = {
    0x0, 0x4000, 0x8000, 0x10000, 0x40000, 0x100000,
    0x200000, 0x400000, 0x800000, 0x1000000,
    0x2000000, 0x4000000, 0x8000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000,
    0x100000000, 0x200000000, 0x300000000,
}

local mapped_offsets = {}

for _, offset in ipairs(offsets) do
    local m_ok, m_ret = pcall(function()
        return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, offset)
    end)
    local addr = 0
    if m_ok then addr = m_ret:tonumber() end

    if addr ~= 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
        -- Read first 4 qwords
        local q0_lo = memory.read_dword(addr):tonumber()
        local q0_hi = memory.read_dword(addr + 4):tonumber()
        local q1_lo = memory.read_dword(addr + 8):tonumber()
        local q1_hi = memory.read_dword(addr + 12):tonumber()
        local q2_lo = memory.read_dword(addr + 16):tonumber()
        local q2_hi = memory.read_dword(addr + 20):tonumber()
        local q3_lo = memory.read_dword(addr + 24):tonumber()
        local q3_hi = memory.read_dword(addr + 28):tonumber()

        -- Count non-zero qwords in the page
        local nonzero = 0
        local kptrs = 0
        for i = 0, PAGE - 8, 8 do
            local lo = memory.read_dword(addr + i):tonumber()
            local hi = memory.read_dword(addr + i + 4):tonumber()
            if lo ~= 0 or hi ~= 0 then nonzero = nonzero + 1 end
            if hi >= 0xFFFF0000 then kptrs = kptrs + 1 end
        end

        local tag = ""
        if kptrs > 0 then tag = " *** KPTRS:" .. kptrs .. " ***" end

        log(string.format("  off=0x%09x: mapped nz=%d%s", offset, nonzero, tag))
        log(string.format("    %08x%08x %08x%08x %08x%08x %08x%08x",
            q0_hi, q0_lo, q1_hi, q1_lo, q2_hi, q2_lo, q3_hi, q3_lo))

        mapped_offsets[#mapped_offsets + 1] = {
            offset = offset, addr = addr, nonzero = nonzero, kptrs = kptrs
        }

        pcall(function() syscall.sc_munmap(addr, PAGE) end)
    else
        log(string.format("  off=0x%09x: FAILED", offset))
    end
end

-- ============================================================
-- PART 3: Deep dive on offsets that had kernel pointers
-- Dump more data from interesting pages
-- ============================================================
log("")
log("--- PART 3: deep dump of interesting pages ---")

for _, entry in ipairs(mapped_offsets) do
    if entry.kptrs > 0 or entry.nonzero > 100 then
        local m_ok, m_ret = pcall(function()
            return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dmem_fd, entry.offset)
        end)
        if m_ok then
            local addr = m_ret:tonumber()
            if addr ~= 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
                log(string.format("  === offset 0x%09x (kptrs=%d nz=%d) ===",
                    entry.offset, entry.kptrs, entry.nonzero))

                -- Dump all kernel pointers
                for i = 0, PAGE - 8, 8 do
                    local lo = memory.read_dword(addr + i):tonumber()
                    local hi = memory.read_dword(addr + i + 4):tonumber()
                    if hi >= 0xFFFF0000 then
                        local tag = "KHIGH"
                        if hi >= 0xFFFFFFFF and lo >= 0x80000000 then
                            tag = "KTEXT"
                        elseif hi >= 0xFFFFF800 and hi < 0xFFFFFF00 then
                            tag = "DMAP"
                        end
                        log(string.format("    +%04x: 0x%08x%08x [%s]", i, hi, lo, tag))
                    end
                end

                -- Look for ASCII strings (process names, struct signatures)
                local strings = {}
                local cur = {}
                for i = 0, math.min(PAGE - 1, 4095) do
                    local b = memory.read_byte(addr + i):tonumber()
                    if b >= 32 and b < 127 then
                        cur[#cur + 1] = string.char(b)
                    else
                        if #cur >= 6 then
                            strings[#strings + 1] = {off = i - #cur, str = table.concat(cur)}
                        end
                        cur = {}
                    end
                end
                if #cur >= 6 then
                    strings[#strings + 1] = {off = PAGE - #cur, str = table.concat(cur)}
                end

                if #strings > 0 then
                    log("    strings found: " .. #strings)
                    for _, s in ipairs(strings) do
                        log(string.format("      +%04x: \"%s\"", s.off, s.str:sub(1, 60)))
                    end
                end

                pcall(function() syscall.sc_munmap(addr, PAGE) end)
            end
        end
    end
end

-- ============================================================
-- PART 4: Try larger mappings
-- ============================================================
log("")
log("--- PART 4: large mapping test ---")

local large_sizes = {0x10000, 0x40000, 0x100000, 0x400000, 0x1000000}
for _, sz in ipairs(large_sizes) do
    local m_ok, m_ret = pcall(function()
        return syscall.sc_mmap(0, sz, PROT_READ, MAP_SHARED, dmem_fd, 0)
    end)
    local addr = 0
    if m_ok then addr = m_ret:tonumber() end

    if addr ~= 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
        -- Scan for kernel pointers across the whole mapping
        local kptr_count = 0
        local sample_ptrs = {}
        for i = 0, sz - 8, 4096 do -- sample every 4KB
            local lo = memory.read_dword(addr + i):tonumber()
            local hi = memory.read_dword(addr + i + 4):tonumber()
            if hi >= 0xFFFF0000 then
                kptr_count = kptr_count + 1
                if #sample_ptrs < 5 then
                    sample_ptrs[#sample_ptrs + 1] = string.format(
                        "+%06x:0x%08x%08x", i, hi, lo)
                end
            end
        end
        local ptrs_str = ""
        if #sample_ptrs > 0 then ptrs_str = " " .. table.concat(sample_ptrs, " ") end
        log(string.format("  size=0x%x: OK kptrs=%d%s", sz, kptr_count, ptrs_str))
        pcall(function() syscall.sc_munmap(addr, sz) end)
    else
        log(string.format("  size=0x%x: FAILED", sz))
    end
end

-- ============================================================
-- PART 5: Try dmem1 and dmem2 as well
-- ============================================================
log("")
log("--- PART 5: dmem1/dmem2 comparison ---")

for _, devpath in ipairs({"/dev/dmem1", "/dev/dmem2"}) do
    local dfd = -1
    local dok, dret = pcall(function() return syscall.sc_open(devpath, 0):tonumber() end)
    if dok and dret >= 0 then dfd = dret end
    if dfd < 0 then
        log("  " .. devpath .. ": cannot open")
    else
        local m_ok2, m_ret2 = pcall(function()
            return syscall.sc_mmap(0, PAGE, PROT_READ, MAP_SHARED, dfd, 0)
        end)
        local a2 = 0
        if m_ok2 then a2 = m_ret2:tonumber() end
        if a2 ~= 0 and a2 ~= 0xFFFFFFFFFFFFFFFF then
            local q0lo = memory.read_dword(a2):tonumber()
            local q0hi = memory.read_dword(a2 + 4):tonumber()
            local q1lo = memory.read_dword(a2 + 8):tonumber()
            local q1hi = memory.read_dword(a2 + 12):tonumber()

            -- Count kptrs
            local kp = 0
            for i = 0, PAGE - 8, 8 do
                local hi2 = memory.read_dword(a2 + i + 4):tonumber()
                if hi2 >= 0xFFFF0000 then kp = kp + 1 end
            end

            log(string.format("  %s: mapped kptrs=%d first=%08x%08x %08x%08x",
                devpath, kp, q0hi, q0lo, q1hi, q1lo))
            pcall(function() syscall.sc_munmap(a2, PAGE) end)
        else
            log("  " .. devpath .. ": mmap failed")
        end
        pcall(function() syscall.sc_close(dfd) end)
    end
end

-- ============================================================
-- PART 6: Write test — can we write to dmem0 mapping?
-- ============================================================
log("")
log("--- PART 6: write test ---")

local w_ok, w_ret = pcall(function()
    return syscall.sc_mmap(0, PAGE, PROT_RW, MAP_SHARED, dmem_fd, 0)
end)
local w_addr = 0
if w_ok then w_addr = w_ret:tonumber() end

if w_addr ~= 0 and w_addr ~= 0xFFFFFFFFFFFFFFFF then
    log("  RW map at " .. string.format("0x%x", w_addr))
    -- Read original value
    local orig_lo = memory.read_dword(w_addr + 256):tonumber()
    local orig_hi = memory.read_dword(w_addr + 260):tonumber()
    log(string.format("  original @+256: %08x%08x", orig_hi, orig_lo))

    -- Write test value
    local write_ok = pcall(function()
        memory.write_dword(w_addr + 256, 0x41424344)
    end)
    log("  write attempt: " .. (write_ok and "OK" or "FAILED"))

    if write_ok then
        -- Read back
        local new_lo = memory.read_dword(w_addr + 256):tonumber()
        log(string.format("  readback: %08x", new_lo))
        if new_lo == 0x41424344 then
            log("  *** WRITE CONFIRMED — we have R/W to physical memory! ***")
            -- Restore original
            memory.write_dword(w_addr + 256, orig_lo)
        end
    end

    pcall(function() syscall.sc_munmap(w_addr, PAGE) end)
else
    log("  RW mmap failed")
end

pcall(function() syscall.sc_close(dmem_fd) end)

log("")
log("=== DMEM MMAP SCAN DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
