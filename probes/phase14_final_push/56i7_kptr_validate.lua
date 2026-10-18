-- CRASH_CLASS: LOW
-- PROBE 56i7: Validate kernel pointers — are they real KASLR-shifted addresses?
--
-- Context: 56i6 found 2828 "kernel pointers" in module .data segments.
-- Key question: are the 0xFFFF8xxx high words real kernel VA or NID hash fragments?
--
-- Validation strategy:
--   [B] Read libkernel data+0x3E38..+0x3F00 — dump full qwords with structure analysis
--   [C] Read the SURROUNDING context (before/after the kptr block) for structure clues
--   [D] Check if values are page-aligned (real kernel ptrs often are)
--   [E] Compute deltas between adjacent pointers (random = real, structured = hash)
--   [F] Read handle 0x2 kptr block for cross-module comparison
--   [G] Also scan eboot .data (was skipped in 56i6 — size cap was too low at 1MB)

print("=== PROBE 56i7: KPTR VALIDATION ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

local sc_info = make_syscall(593)

-- ============================================================
-- [B] Dump libkernel kptr block with full structure analysis
-- ============================================================
print("")
print("[B] libkernel (0x2001) kptr block detail")

local lk_info = memory.alloc(0x200)
safe_wd(lk_info, 0x160)
pcall(function() sc_info(uint64(0x2001), lk_info) end)

local lk_data_lo = safe_rd(lk_info + 0x118) or 0
local lk_data_hi = safe_rd(lk_info + 0x11C) or 0
local lk_data_sz = safe_rd(lk_info + 0x120) or 0
local lk_text_lo = safe_rd(lk_info + 0x108) or 0
local lk_text_hi = safe_rd(lk_info + 0x10C) or 0

print(string.format("  text: 0x%X_%08X", lk_text_hi, lk_text_lo))
print(string.format("  data: 0x%X_%08X size=0x%X", lk_data_hi, lk_data_lo, lk_data_sz))

-- Dump 256 bytes before the kptr block (context)
print("")
print("  Context before kptr block (data+0x3D38..+0x3E38):")
for off = 0x3D38, 0x3E30, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then
            print(string.format("    +0x%04X: %s", off, hexval(val)))
        end
    end
end

-- Dump the kptr block itself — first 40 entries with analysis
print("")
print("  Kptr block (data+0x3E38..+0x3F78):")
local prev_h = 0
local deltas = {}
for i = 0, 39 do
    local off = 0x3E38 + i * 8
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        local delta_h = vh - prev_h
        if i > 0 and prev_h > 0 then
            deltas[#deltas + 1] = delta_h
        end
        print(string.format("    +0x%04X: hi=0x%04X lo=0x%08X  delta_hi=%d",
            off, vh, vl, i > 0 and delta_h or 0))
        prev_h = vh
    end
end

-- Analyze deltas
if #deltas > 0 then
    print("")
    print("  Delta analysis (hi word differences):")
    local min_d, max_d, sum = 99999, 0, 0
    for _, d in ipairs(deltas) do
        if d < min_d then min_d = d end
        if d > max_d then max_d = d end
        sum = sum + d
    end
    print(string.format("    min=%d max=%d avg=%.1f", min_d, max_d, sum / #deltas))
    print("    Structured (constant delta) = NID hash table")
    print("    Random/variable deltas = REAL kernel function addresses")
end

-- Context after kptr block
print("")
print("  Context after kptr block (last 8 kptrs + 128 bytes after):")
-- Find where kptrs end
local kptr_end_off = 0x3E38
for off = 0x3E38, lk_data_sz - 1, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh < 0xFFFF8000 or vh >= 0xFFFFFFFF then
            kptr_end_off = off
            break
        end
    end
    if off > 0x5000 then kptr_end_off = off; break end
end
print(string.format("  Kptr block ends at +0x%04X (%d entries)",
    kptr_end_off, (kptr_end_off - 0x3E38) / 8))

-- Dump 128 bytes after end
for off = kptr_end_off, kptr_end_off + 120, 8 do
    if off < lk_data_sz then
        local a_l = lk_data_lo + off
        local a_h = lk_data_hi
        if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
        local addr = uint64(string.format("0x%X%08X", a_h, a_l))
        local val = safe_rq(addr)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                print(string.format("    +0x%04X: %s", off, hexval(val)))
            end
        end
    end
end

-- ============================================================
-- [C] Page alignment check
-- Real kernel pointers are often page-aligned (or at known offsets)
-- FreeBSD kernel uses 16KB pages on PS5
-- ============================================================
print("")
print("[C] Page alignment check (16KB = 0x4000)")

-- Re-read first 20 kptrs and check alignment
local aligned_count = 0
local total_checked = 0
for i = 0, 19 do
    local off = 0x3E38 + i * 8
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        total_checked = total_checked + 1
        -- Full 48-bit address = (vh << 32) | vl, check low 14 bits (16KB align)
        local low14 = vl % 0x4000
        local low12 = vl % 0x1000  -- 4KB align
        if low14 == 0 then
            aligned_count = aligned_count + 1
            print(string.format("    [%d] 0x%04X_%08X — 16KB aligned", i, vh, vl))
        elseif low12 == 0 then
            print(string.format("    [%d] 0x%04X_%08X — 4KB aligned", i, vh, vl))
        end
    end
end
print(string.format("  16KB aligned: %d/%d", aligned_count, total_checked))

-- ============================================================
-- [D] Read low dwords as potential NID strings
-- If low dword is a small number, it might be a table index
-- If it's in the range of text offsets, it's a function offset
-- ============================================================
print("")
print("[D] Low dword analysis")

-- Collect all low dwords from first 40 kptrs
print("  First 40 low dwords:")
local lo_vals = {}
for i = 0, 39 do
    local off = 0x3E38 + i * 8
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        lo_vals[#lo_vals + 1] = vl
    end
end

-- Are they monotonically increasing?
local monotonic = true
for i = 2, #lo_vals do
    if lo_vals[i] <= lo_vals[i-1] then monotonic = false; break end
end
print(string.format("  Monotonic increasing: %s", monotonic and "YES" or "NO"))

-- What's the range?
if #lo_vals > 0 then
    local lo_min = lo_vals[1]
    local lo_max = lo_vals[#lo_vals]
    print(string.format("  Range: 0x%08X - 0x%08X (span=0x%X)", lo_min, lo_max, lo_max - lo_min))

    -- Check if these match libkernel text offsets
    print(string.format("  libkernel text base: 0x%X_%08X", lk_text_hi, lk_text_lo))
    print(string.format("  Low dwords as text offsets: +0x%X to +0x%X", lo_min, lo_max))
end

-- ============================================================
-- [E] Handle 0x2 comparison — same structure?
-- ============================================================
print("")
print("[E] Handle 0x2 kptr block")

local h2_info = memory.alloc(0x200)
safe_wd(h2_info, 0x160)
pcall(function() sc_info(uint64(0x2), h2_info) end)

local h2_data_lo = safe_rd(h2_info + 0x118) or 0
local h2_data_hi = safe_rd(h2_info + 0x11C) or 0
local h2_text_lo = safe_rd(h2_info + 0x108) or 0
local h2_text_hi = safe_rd(h2_info + 0x10C) or 0

print(string.format("  text: 0x%X_%08X", h2_text_hi, h2_text_lo))
print(string.format("  data: 0x%X_%08X", h2_data_hi, h2_data_lo))

-- Read first 20 kptrs from handle 0x2
print("  First 20 kptrs:")
for i = 0, 19 do
    local off = 0xA428 + i * 8
    local a_l = h2_data_lo + off
    local a_h = h2_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        print(string.format("    +0x%04X: hi=0x%04X lo=0x%08X", off, vh, vl))
    end
end

-- ============================================================
-- [F] THE KEY TEST: Read each qword as TWO separate dwords
-- If this is a packed struct (e.g., {uint32 nid_hash; uint32 func_offset})
-- then what we see as a "qword" is actually two independent 32-bit values
-- ============================================================
print("")
print("[F] Split dword test — are these packed structs?")

print("  libkernel block as separate dwords:")
for i = 0, 14 do
    local off = 0x3E38 + i * 8
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local dw0 = safe_rd(addr)      -- low dword (at lower address)
    local dw1 = safe_rd(addr + 4)  -- high dword (at higher address)
    print(string.format("    +0x%04X: dw[0]=0x%08X dw[1]=0x%08X",
        off, dw0 or 0, dw1 or 0))
end

print("")
print("  If dw[0] are small incrementing offsets and dw[1] are NID hashes,")
print("  these are NOT kernel pointers but {offset, nid_hash} structs.")
print("  If dw[0]+dw[1] form a coherent 48-bit address, they ARE kernel ptrs.")

-- ============================================================
-- [G] Eboot .data scan (full — 1.5MB)
-- Scan in chunks to avoid timeout
-- ============================================================
print("")
print("[G] Eboot .data scan (full 0x180000)")

local eb_data_lo = safe_rd(lk_info + 0x118)  -- reuse lk_info? No, need eboot
local eb_info = memory.alloc(0x200)
safe_wd(eb_info, 0x160)
pcall(function() sc_info(uint64(0), eb_info) end)

local ebd_lo = safe_rd(eb_info + 0x118) or 0
local ebd_hi = safe_rd(eb_info + 0x11C) or 0
local ebd_sz = safe_rd(eb_info + 0x120) or 0

print(string.format("  eboot data: 0x%X_%08X size=0x%X", ebd_hi, ebd_lo, ebd_sz))

local eb_kptrs = 0
-- Scan full 1.5MB but only print first 20
for off = 0, ebd_sz - 1, 8 do
    local a_l = ebd_lo + off
    local a_h = ebd_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            eb_kptrs = eb_kptrs + 1
            if eb_kptrs <= 20 then
                print(string.format("  data+0x%06X: hi=0x%04X lo=0x%08X", off, vh, vl))
            end
        end
    end
end
print("  Eboot .data kernel pointers: " .. eb_kptrs)

collectgarbage("restart")

print("")
print("=== PROBE 56i7 COMPLETE ===")
