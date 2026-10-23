-- CRASH_CLASS: LOW
-- PROBE 399f: Scan eboot .text for kernel address references
--
-- Eboot is RX (readable). If Sony's linker hardcoded kernel addresses
-- in eboot stubs (call/jmp to kernel VA), we can read them to find the
-- kernel base without KASLR defeat.
--
-- Also scan eboot .rodata and writable sections for kernel-range values.
-- On FreeBSD 11 (no KARL), kernel could be at a fixed address.

print("=== PROBE 399f: eboot kernel refs ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Get eboot base and text info
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local txt_sz_lo = rd(N(info) + 0x110) or 0
local txt_sz_hi = rd(N(info) + 0x114) or 0
local txt_size = txt_sz_lo + txt_sz_hi * 0x100000000
print(string.format("eboot=%X_%08X text_size=%X", eb_hi, eb_lo, txt_size))

-- Get full VM map to find eboot data segments
local sc_674 = mk(674)
local map_buf = memory.alloc(0x100)
local kptr_found = {}

-- ============================================
-- PART A: Scan eboot .text for qword-aligned kernel addresses
-- Kernel VA range: 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF
-- (hi dword >= 0xFFFF8000, excluding 0xFFFFFFFF sentinels)
-- ============================================
print("")
print("-- A: eboot .text kernel addr scan --")

local eb_base = eb_lo + eb_hi * 0x100000000
local scan_limit = math.min(txt_size, 0x480000)  -- cap at ~4.5MB
local kptr_text = 0
local total_scanned = 0

-- Scan in chunks to avoid timeout
for chunk_start = 0, scan_limit - 8, 0x10000 do
    local chunk_end = math.min(chunk_start + 0x10000, scan_limit)
    for off = chunk_start, chunk_end - 8, 8 do
        local lo = rd(eb_base + off)
        local hi = rd(eb_base + off + 4)
        total_scanned = total_scanned + 1
        if hi and lo then
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then
                kptr_text = kptr_text + 1
                if kptr_text <= 20 then
                    table.insert(kptr_found, {off, lo, hi})
                    print(string.format("  +%06X: %08X_%08X ★", off, hi, lo))
                end
            end
        else
            break
        end
    end

    if not alive() then print("CANARY FAIL scan"); return end
end

print(string.format("  scanned %d qwords, kernel refs=%d", total_scanned, kptr_text))

-- ============================================
-- PART B: Check writable segments for kernel addresses
-- Use VM map (674) to find data segments
-- ============================================
print("")
print("-- B: eboot data segment scan --")

-- Get VM regions near eboot
local regions = {}
local addr_scan = uint64(0)
for i = 1, 20 do
    for j = 0, 0xFC, 4 do wd(N(map_buf) + j, 0) end

    local ok_q, rv_q = pcall(function()
        return sc_674(addr_scan, map_buf, uint64(0x100))
    end)
    if not ok_q or N(rv_q) == 0xFFFFFFFF then break end

    local start_lo = rd(N(map_buf)) or 0
    local start_hi = rd(N(map_buf) + 4) or 0
    local end_lo = rd(N(map_buf) + 8) or 0
    local end_hi = rd(N(map_buf) + 12) or 0
    local prot = rd(N(map_buf) + 0x18) or 0

    local start_addr = start_lo + start_hi * 0x100000000
    local end_addr = end_lo + end_hi * 0x100000000

    -- Check if near eboot (within ±16MB)
    if start_addr > eb_base - 0x1000000 and start_addr < eb_base + 0x1000000 then
        local name = ""
        for c = 0x20, 0x40 do
            local byte = rd(N(map_buf) + c)
            if byte and byte > 0 and byte < 128 then
                name = name .. string.char(byte % 256)
            end
        end

        table.insert(regions, {
            start = start_addr,
            size = end_addr - start_addr,
            prot = prot,
            name = name
        })
        print(string.format("  %X_%08X sz=%X p=%X %s",
            start_hi, start_lo, end_addr - start_addr, prot, name))
    end

    addr_scan = uint64(string.format("0x%X%08X", end_hi, end_lo))
    if end_addr == 0 then break end
end

-- Scan writable eboot regions for kernel addresses
local data_kptr = 0
for _, reg in ipairs(regions) do
    -- Only scan writable (prot has bit 1) and non-text regions
    if reg.prot % 4 >= 2 and reg.size > 0 and reg.size < 0x200000 then
        local scan_sz = math.min(reg.size, 0x100000)
        for off = 0, scan_sz - 8, 8 do
            local lo = rd(reg.start + off)
            local hi = rd(reg.start + off + 4)
            if hi and lo then
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then
                    data_kptr = data_kptr + 1
                    if data_kptr <= 10 then
                        print(string.format("  DATA +%06X: %08X_%08X (reg %X p=%X) ★",
                            off, hi, lo, reg.start % 0x100000000, reg.prot))
                    end
                end
            end
        end
    end
    if not alive() then print("CANARY FAIL data scan"); return end
end

print(string.format("  data_kptr=%d", data_kptr))

-- ============================================
-- PART C: Check if kernel base is constant across connections
-- We can't directly read it, but: the 13.60 sysent CSV has thunk
-- addresses. If kernel base is fixed, we can compute it.
-- Print 13.60 info for reference.
-- ============================================
print("")
print("-- C: cross-reference --")
print("  13.60 sysent thunk example: syscall 202 @ 0x265950")
print("  13.60 sysent base estimate: check CSV for lowest thunk addr")
print(string.format("  eboot_base=%X_%08X (this connection)", eb_hi, eb_lo))
print(string.format("  pid=%d (this connection)", pid_val))

-- Print a few eboot addresses for cross-connection comparison
print(string.format("  text_kptr_count=%d data_kptr_count=%d", kptr_text, data_kptr))

if #kptr_found > 0 then
    print("  KERNEL REFS IN EBOOT TEXT:")
    for _, k in ipairs(kptr_found) do
        print(string.format("    +%06X = %08X_%08X", k[1], k[3], k[2]))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399f COMPLETE ===")
