-- CRASH_CLASS: LOW
-- PROBE 74e: Verify module data "kernel pointers" — NID table vs real
--
-- 74b found 103 kernel-pointer-shaped values (h >= 0xFFFF8000) in modules
-- 2, 17, 34, 49, 50 data segments. Pattern: varying high 32 bits with
-- small low 32 bits suggests NID hash resolution tables, NOT real kernel
-- pointers. This probe verifies by:
-- (1) Reading module text_base/text_size to check if low_dword falls within
--     the module's own text range (= resolved NID, not kernel ptr)
-- (2) Checking if any two values share a common base (= real kernel KASLR)
-- (3) Dumping surrounding context for structure analysis

print("=== PROBE 74e: VERIFY MODULE KPTRS ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local info_buf = memory.alloc(0x200)

-- Get module info: text_base, text_size, data_base, data_size
local function get_module_info(handle)
    wd(N(info_buf), 0x160)
    for i = 4, 0x15F, 4 do wd(N(info_buf) + i, 0) end
    local ret = -1
    pcall(function() ret = N(mk(593)(uint64(handle), info_buf)) end)
    if ret ~= 0 then return nil end

    local text_lo = rd(N(info_buf) + 0x108) or 0
    local text_hi = rd(N(info_buf) + 0x10C) or 0
    local text_sz_lo = rd(N(info_buf) + 0x110) or 0
    local text_sz_hi = rd(N(info_buf) + 0x114) or 0
    local data_lo = rd(N(info_buf) + 0x118) or 0
    local data_hi = rd(N(info_buf) + 0x11C) or 0
    local data_sz_lo = rd(N(info_buf) + 0x120) or 0
    local data_sz_hi = rd(N(info_buf) + 0x124) or 0

    return {
        text_base = uint64(string.format("0x%X%08X", text_hi, text_lo)),
        text_size = text_sz_lo,
        data_base = uint64(string.format("0x%X%08X", data_hi, data_lo)),
        data_size = data_sz_lo,
        text_hi = text_hi, text_lo = text_lo,
        data_hi = data_hi, data_lo = data_lo
    }
end

-- ============================================================
-- [A] Module info for kptr-bearing modules
-- ============================================================
print("[A] Module info")
local targets = {2, 17, 20, 34, 49, 50}
local mod_info = {}

for _, h in ipairs(targets) do
    local mi = get_module_info(h)
    if mi then
        mod_info[h] = mi
        print(string.format("  module %d: text=0x%X%08X sz=0x%X data=0x%X%08X dsz=0x%X",
            h, mi.text_hi, mi.text_lo, mi.text_size,
            mi.data_hi, mi.data_lo, mi.data_size))
    else
        print(string.format("  module %d: NOT FOUND", h))
    end
end

-- ============================================================
-- [B] Detailed analysis of module 2 kptrs (offset 0xA428-0xA4C0)
-- ============================================================
print("")
print("[B] Module 2 kptr analysis (data+0xA428..0xA4C0)")

local m2 = mod_info[2]
if m2 then
    local data_addr = N(m2.data_base)
    local text_addr_lo = m2.text_lo
    local text_size = m2.text_size

    local nid_match = 0
    local real_kptr = 0

    for off = 0xA428, 0xA4C0, 8 do
        local val = rq(uint64(data_addr + off))
        if val == nil then break end
        local h, l = get_hi_lo(val)

        -- Check if low dword could be an offset within this module's text
        local in_text = (l >= text_addr_lo and l < text_addr_lo + text_size)
        -- Check if low dword is a small offset (< 1MB, typical function offset)
        local small_offset = (l < 0x100000)

        -- For NID tables: entry format might be {nid_hi:u32, resolved_addr_lo:u32}
        -- The resolved_addr_lo would be an offset within the module
        local verdict = ""
        if small_offset then
            verdict = "NID_TABLE(small_offset)"
            nid_match = nid_match + 1
        elseif in_text then
            verdict = "NID_TABLE(in_text)"
            nid_match = nid_match + 1
        else
            verdict = "POSSIBLE_KPTR"
            real_kptr = real_kptr + 1
        end

        print(string.format("  +0x%04X: %s  h=0x%08X l=0x%08X  %s",
            off, fmt(val), h, l, verdict))
    end
    print(string.format("  VERDICT: %d NID-like, %d possible kernel ptrs", nid_match, real_kptr))
end

-- ============================================================
-- [C] Module 2: read broader context around kptr block
-- ============================================================
print("")
print("[C] Module 2 context dump (data+0xA400..0xA510)")

if m2 then
    local data_addr = N(m2.data_base)
    for off = 0xA400, 0xA508, 8 do
        local val = rq(uint64(data_addr + off))
        if val == nil then break end
        local h, l = get_hi_lo(val)
        local tag = ""
        if is_kptr(val) then tag = " <-- KPTR" end
        if l == 0 and h == 0 then tag = " (zero)" end
        print(string.format("  +0x%04X: 0x%08X_%08X%s", off, h, l, tag))
    end
end

-- ============================================================
-- [D] Module 17 kptrs (data+0x2E8..0x380)
-- ============================================================
print("")
print("[D] Module 17 kptr analysis (data+0x2E8..0x380)")

local m17 = mod_info[17]
if m17 then
    local data_addr = N(m17.data_base)
    local text_lo = m17.text_lo

    for off = 0x2D0, 0x398, 8 do
        local val = rq(uint64(data_addr + off))
        if val == nil then break end
        local h, l = get_hi_lo(val)
        local tag = ""
        if is_kptr(val) then tag = " <-- KPTR" end
        if l == 0 and h == 0 then tag = " (zero)" end
        print(string.format("  +0x%04X: 0x%08X_%08X%s", off, h, l, tag))
    end
end

-- ============================================================
-- [E] Module 49 kptrs (data+0x08..0xA0)
-- ============================================================
print("")
print("[E] Module 49 kptr analysis (data+0x00..0xB0)")

local m49 = mod_info[49]
if m49 then
    local data_addr = N(m49.data_base)
    for off = 0x00, 0xB0, 8 do
        local val = rq(uint64(data_addr + off))
        if val == nil then break end
        local h, l = get_hi_lo(val)
        local tag = ""
        if is_kptr(val) then tag = " <-- KPTR" end
        if l == 0 and h == 0 then tag = " (zero)" end
        print(string.format("  +0x%04X: 0x%08X_%08X%s", off, h, l, tag))
    end
end

-- ============================================================
-- [F] Cross-module base analysis
-- ============================================================
print("")
print("[F] Cross-module base analysis")
print("  If these are kernel pointers, they should share a KASLR base.")
print("  If NID hashes, the high 32 bits should appear random.")

-- Collect all high-dwords
local all_highs = {}
for _, h_mod in ipairs(targets) do
    local mi = mod_info[h_mod]
    if mi then
        local data_addr = N(mi.data_base)
        local scan_size = mi.data_size
        if scan_size > 0x20000 then scan_size = 0x20000 end
        if scan_size < 0x100 then scan_size = 0x10000 end

        for off = 0, scan_size - 8, 8 do
            local val = rq(uint64(data_addr + off))
            if val ~= nil and is_kptr(val) then
                local h, l = get_hi_lo(val)
                all_highs[#all_highs + 1] = h
            end
        end
    end
end

-- Check if high dwords cluster around a common base
local base_counts = {}
for _, h in ipairs(all_highs) do
    -- Round to 4K page: kernel base would have the same top 20 bits
    local page = math.floor(h / 0x1000) * 0x1000
    base_counts[page] = (base_counts[page] or 0) + 1
end

-- Report top base candidates
local sorted_bases = {}
for base, count in pairs(base_counts) do
    sorted_bases[#sorted_bases + 1] = {base = base, count = count}
end
table.sort(sorted_bases, function(a, b) return a.count > b.count end)

print("  Unique high-dword 4K-page clusters (top 10):")
for i = 1, math.min(10, #sorted_bases) do
    local b = sorted_bases[i]
    print(string.format("    0x%08Xxxx: %d occurrences", b.base / 0x1000, b.count))
end
print("  Total unique high-dword pages: " .. #sorted_bases)
print("  Total kptr-shaped values: " .. #all_highs)

if #sorted_bases > 0 then
    local top = sorted_bases[1]
    if top.count > #all_highs * 0.5 then
        print("  VERDICT: Majority cluster at one base => likely REAL kernel KASLR base")
    else
        print("  VERDICT: Scattered high-dwords => likely NID hash table (FALSE POSITIVES)")
    end
end

-- ============================================================
-- [G] Final cross-check: do low dwords match any module text ranges?
-- ============================================================
print("")
print("[G] Low dword vs module text range cross-check")

-- For each kptr-shaped value, check if its low 32 bits falls in any module's text range
local match_count = 0
local total_checked = 0
for _, h_mod in ipairs({2, 17, 34, 49, 50}) do
    local mi = mod_info[h_mod]
    if mi then
        local data_addr = N(mi.data_base)
        local scan_size = mi.data_size
        if scan_size > 0x20000 then scan_size = 0x20000 end
        if scan_size < 0x100 then scan_size = 0x10000 end

        for off = 0, scan_size - 8, 8 do
            local val = rq(uint64(data_addr + off))
            if val ~= nil and is_kptr(val) then
                total_checked = total_checked + 1
                local h, l = get_hi_lo(val)
                -- Check if l is within THIS module's text segment
                if l < mi.text_size then
                    match_count = match_count + 1
                end
            end
        end
    end
end

print(string.format("  %d/%d kptr-shaped values have low dword < own module text_size",
    match_count, total_checked))
if match_count > total_checked * 0.8 then
    print("  STRONG EVIDENCE: These are NID hash resolution tables, NOT kernel pointers")
elseif match_count > total_checked * 0.3 then
    print("  MIXED: Some may be NID tables, some may be real")
else
    print("  LOW MATCH: These may be real kernel pointers")
end

print("")
print("=== PROBE 74e COMPLETE ===")
