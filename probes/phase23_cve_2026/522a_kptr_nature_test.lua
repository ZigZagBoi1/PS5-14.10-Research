-- CRASH_CLASS: MODERATE
-- PROBE 522a: determine nature of 0xFFFF8xxx table values
--
-- 521a confirmed: stride-8 pointer table, hi words increment
-- by multiples of 0x10000 (16KB pages), low in 0x35000-0x44000.
-- Also revealed 0xFFFF7xxx values below our filter threshold.
--
-- This probe answers 3 critical questions:
-- [A] Full range: what is the COMPLETE value range (including 0xFFFF7xxx)?
-- [B] Are they stable within one connection? (read twice, compare)
-- [C] What happens if we modify ONE value? (write different, call module func, restore)
-- [D] Byte-level analysis: are these IEEE 754 doubles/NaN?
-- [E] Relationship to 674 VM map entries (do they fall inside any mapped region?)

print("=== PROBE 522a: kptr nature test ===")
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function read_str(addr, maxlen)
    maxlen = maxlen or 64
    local s = ""
    for i = 0, maxlen - 1 do
        local b = safe_rd(addr + i)
        if not b then break end
        local c = b % 256
        if c == 0 then break end
        if c >= 32 and c < 127 then
            s = s .. string.char(c)
        else
            s = s .. "."
        end
    end
    return s
end

local sc20  = make_syscall(20)
local sc593 = make_syscall(593)
local sc674 = make_syscall(674)

local pid = to_num(sc20())
print("pid: " .. pid)

-- get module h=2
local mod_info = memory.alloc(0x200)
local function get_mod(h)
    for j = 0, 0x15C, 4 do safe_wd(mod_info + j, 0) end
    safe_wd(mod_info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), mod_info) end)
    if ok and to_num(ret) == 0 then
        local mt = safe_rq(mod_info + 0x108)
        local md = safe_rq(mod_info + 0x118)
        local dsz_raw = safe_rq(mod_info + 0x120)
        local dsz = 0
        if dsz_raw then
            local _, dl = get_hi_lo(dsz_raw)
            dsz = dl
        end
        local name = read_str(mod_info + 8, 48)
        return {handle = h, text = mt, data = md, name = name, dsz = dsz}
    end
    return nil
end

local m2 = get_mod(2)
if not m2 or not m2.data then
    print("ERROR: module h=2 not found")
    print("=== PROBE 522a FAILED ===")
    return
end
print("mod2: \"" .. m2.name .. "\" data=" .. fmt_hex(m2.data) .. " dsz=0x" .. string.format("%X", m2.dsz))
print("")

-- ============================================================
-- [A] Full range scan: include ALL high canonical values
-- Count values with hi >= 0xFFFF0000 (not just 0xFFFF8000)
-- ============================================================
print("[A] Full range scan (hi >= 0xFFFF0000, excluding 0xFFFFFFFF)")

local range_counts = {}
local full_min_h, full_min_l = 0xFFFFFFFF, 0xFFFFFFFF
local full_max_h, full_max_l = 0, 0
local full_total = 0
local table_start = nil
local table_end = nil

local scan_sz = math.min(m2.dsz > 0 and m2.dsz or 0x10000, 0x40000)
for off = 0, scan_sz - 8, 8 do
    local q = safe_rq(m2.data + off)
    if not q then break end
    local qh, ql = get_hi_lo(q)

    if qh >= 0xFFFF0000 and qh < 0xFFFFFFFF then
        full_total = full_total + 1
        if not table_start then table_start = off end
        table_end = off

        -- bucket by top nibble after 0xFFFF
        local bucket = math.floor((qh - 0xFFFF0000) / 0x1000)
        range_counts[bucket] = (range_counts[bucket] or 0) + 1

        if qh < full_min_h or (qh == full_min_h and ql < full_min_l) then
            full_min_h, full_min_l = qh, ql
        end
        if qh > full_max_h or (qh == full_max_h and ql > full_max_l) then
            full_max_h, full_max_l = qh, ql
        end
    end
end

print("  total entries (hi >= 0xFFFF0000): " .. full_total)
print("  table region: +0x" .. string.format("%X", table_start or 0) .. " to +0x" .. string.format("%X", table_end or 0))
print("  min: 0x" .. string.format("%08X_%08X", full_min_h, full_min_l))
print("  max: 0x" .. string.format("%08X_%08X", full_max_h, full_max_l))
print("")

print("  distribution by hi nibble range:")
local sorted_buckets = {}
for b, c in pairs(range_counts) do
    table.insert(sorted_buckets, {bucket = b, count = c})
end
table.sort(sorted_buckets, function(a, b) return a.bucket < b.bucket end)
for _, sb in ipairs(sorted_buckets) do
    local lo_range = 0xFFFF0000 + sb.bucket * 0x1000
    local hi_range = lo_range + 0xFFF
    print(string.format("    0x%08X-0x%08X: %d entries", lo_range, hi_range, sb.count))
end
print("")

-- ============================================================
-- [B] Stability test: read 20 values, wait, read again
-- ============================================================
print("[B] Stability test")

-- find first 20 table entries (hi >= 0xFFFF0000)
local test_offsets = {}
for off = 0, scan_sz - 8, 8 do
    if #test_offsets >= 20 then break end
    local q = safe_rq(m2.data + off)
    if not q then break end
    local qh, ql = get_hi_lo(q)
    if qh >= 0xFFFF0000 and qh < 0xFFFFFFFF then
        table.insert(test_offsets, off)
    end
end

-- first read
local first_read = {}
for _, off in ipairs(test_offsets) do
    local q = safe_rq(m2.data + off)
    local qh, ql = get_hi_lo(q)
    table.insert(first_read, {h = qh, l = ql})
end

-- do some work to let time pass (read 1000 qwords elsewhere)
local dummy = 0
for i = 0, 999 do
    local q = safe_rq(m2.data + (i * 8) % 0x4000)
    if q then dummy = dummy + 1 end
end

-- second read
local changed = 0
for i, off in ipairs(test_offsets) do
    local q = safe_rq(m2.data + off)
    local qh, ql = get_hi_lo(q)
    local same = (qh == first_read[i].h and ql == first_read[i].l)
    if not same then
        changed = changed + 1
        print(string.format("  CHANGED +0x%04X: was 0x%08X_%08X now 0x%08X_%08X",
            off, first_read[i].h, first_read[i].l, qh, ql))
    end
end
print("  " .. #test_offsets .. " values checked, " .. changed .. " changed")
if changed == 0 then
    print("  *** ALL STABLE within connection ***")
end
print("")

-- ============================================================
-- [C] BYTE-LEVEL analysis: are these IEEE 754 doubles?
-- NaN has exponent bits 0x7FF (bits 62:52)
-- 0xFFFF8xxx as a double: exponent = bits 62:52 = 0xFFF (NaN),
-- sign bit = 1 (negative). These ARE NaN values in IEEE 754!
-- ============================================================
print("[C] IEEE 754 double analysis")

-- check first 5 table entries
for i = 1, math.min(5, #test_offsets) do
    local off = test_offsets[i]
    local q = safe_rq(m2.data + off)
    local qh, ql = get_hi_lo(q)

    -- IEEE 754 double: bit 63 = sign, bits 62:52 = exponent, bits 51:0 = mantissa
    local sign = math.floor(qh / 0x80000000)
    local exponent = math.floor((qh % 0x80000000) / 0x100000) -- bits 62:52 (11 bits)
    local mantissa_hi = qh % 0x100000 -- bits 51:32
    -- ql = bits 31:0

    local classification = "normal"
    if exponent == 0x7FF then
        if mantissa_hi == 0 and ql == 0 then
            classification = sign == 1 and "-Infinity" or "+Infinity"
        else
            classification = "NaN (quiet=" .. tostring(math.floor(mantissa_hi / 0x80000) == 1) .. ")"
        end
    elseif exponent == 0 then
        classification = "subnormal/zero"
    end

    print(string.format("  [%d] +0x%04X: 0x%08X_%08X", i, off, qh, ql))
    print(string.format("       sign=%d exp=0x%03X mantissa_hi=0x%05X mantissa_lo=0x%08X -> %s",
        sign, exponent, mantissa_hi, ql, classification))
end
print("")

-- count how many of the table entries are NaN
local nan_count = 0
for off = (table_start or 0), (table_end or 0), 8 do
    local q = safe_rq(m2.data + off)
    if not q then break end
    local qh, ql = get_hi_lo(q)
    if qh >= 0xFFFF0000 and qh < 0xFFFFFFFF then
        local exponent = math.floor((qh % 0x80000000) / 0x100000)
        if exponent == 0x7FF then
            nan_count = nan_count + 1
        end
    end
end
print("  NaN entries in table: " .. nan_count .. " / " .. full_total)
if nan_count == full_total then
    print("  *** ALL TABLE VALUES ARE IEEE 754 NaN ***")
    print("  These are NOT kernel pointers - they are NaN-boxed values!")
elseif nan_count > full_total * 0.9 then
    print("  *** >90% are NaN - likely NaN-boxed values ***")
else
    print("  *** Mixed - some NaN, some real pointers ***")
end
print("")

-- ============================================================
-- [D] NaN-boxing analysis: Lua 5.1 / LuaJIT use NaN-boxing
-- In NaN-boxing, non-double values are stored as NaN with
-- type info in the quiet NaN payload bits
-- LuaJIT format: 0xFFF8xxxx_xxxxxxxx = pointer
--                0xFFFFxxxx_xxxxxxxx = tagged value
-- ============================================================
print("[D] NaN-boxing type analysis")

-- Check if these look like LuaJIT NaN-boxed pointers
-- LuaJIT: pointer = 0xFFFE0000_00000000 | addr (48-bit)
-- But PS5 Lua might use different scheme

-- Let's extract the "payload" from each NaN
-- For NaN-boxed pointer: lower 47-48 bits are the address
print("  Extracting NaN payloads (first 10):")
for i = 1, math.min(10, #test_offsets) do
    local off = test_offsets[i]
    local q = safe_rq(m2.data + off)
    local qh, ql = get_hi_lo(q)

    -- Extract potential pointer from NaN payload
    -- bits 47:0 = potential address
    local payload_hi = qh % 0x10000  -- bottom 16 bits of hi word
    local payload_lo = ql

    -- Also check: could this be a kernel VA with NaN tag?
    -- Canonical kernel VA: 0xFFFF800000000000 to 0xFFFFFFFFFFFFFFFF
    -- As NaN-boxed: the 0xFFFF prefix IS the NaN exponent+sign
    -- So 0xFFFF8xxx_xxxxxxxx could be EITHER:
    --   - A real kernel pointer
    --   - A NaN-boxed value where payload happens to start with 0x8xxx

    print(string.format("  [%2d] full=0x%08X_%08X payload(lo48)=0x%04X_%08X",
        i, qh, ql, payload_hi, payload_lo))
end
print("")

-- ============================================================
-- [E] Context: what's BEFORE the table?
-- Read 128 bytes before table_start to see what leads into it
-- ============================================================
print("[E] Pre-table context (128B before table start)")
if table_start and table_start >= 0x80 then
    local pre_start = table_start - 0x80
    for off = pre_start, table_start - 8, 8 do
        local q = safe_rq(m2.data + off)
        if q then
            local qh, ql = get_hi_lo(q)
            local tag = ""
            if qh >= 0xFFFF0000 and qh < 0xFFFFFFFF then tag = " [TABLE]" end
            if qh == 0 and ql == 0 then tag = " [zero]" end
            -- check if it looks like a small integer or userland pointer
            if qh == 0 and ql > 0 and ql < 0x10000 then tag = " [smallint]" end
            if qh >= 0x1 and qh <= 0xF then tag = " [userptr]" end
            print(string.format("  +0x%04X: 0x%08X_%08X%s", off, qh, ql, tag))
        end
    end
    print("  --- TABLE STARTS ---")
    -- first 4 table entries
    for off = table_start, table_start + 0x18, 8 do
        local q = safe_rq(m2.data + off)
        if q then
            local qh, ql = get_hi_lo(q)
            print(string.format("  +0x%04X: 0x%08X_%08X [TABLE]", off, qh, ql))
        end
    end
end
print("")

-- ============================================================
-- [F] Table END: what comes after the last table entry?
-- ============================================================
print("[F] Post-table context (64B after table end)")
if table_end then
    -- last 4 table entries
    local pre_end = math.max(table_start or 0, table_end - 0x18)
    for off = pre_end, table_end, 8 do
        local q = safe_rq(m2.data + off)
        if q then
            local qh, ql = get_hi_lo(q)
            print(string.format("  +0x%04X: 0x%08X_%08X [TABLE]", off, qh, ql))
        end
    end
    print("  --- TABLE ENDS ---")
    for off = table_end + 8, math.min(table_end + 0x40, scan_sz - 8), 8 do
        local q = safe_rq(m2.data + off)
        if q then
            local qh, ql = get_hi_lo(q)
            local tag = ""
            if qh >= 0xFFFF0000 and qh < 0xFFFFFFFF then tag = " [TABLE continues?]" end
            if qh == 0 and ql == 0 then tag = " [zero]" end
            print(string.format("  +0x%04X: 0x%08X_%08X%s", off, qh, ql, tag))
        end
    end
end
print("")

-- ============================================================
-- [G] Definitive test: table size vs data region size
-- What fraction of the data region is this table?
-- ============================================================
print("[G] Table metrics")
if table_start and table_end then
    local table_bytes = table_end - table_start + 8
    local table_entries = table_bytes / 8
    print("  table offset: +0x" .. string.format("%X", table_start) .. " to +0x" .. string.format("%X", table_end))
    print("  table size: " .. table_bytes .. " bytes (" .. table_entries .. " entries)")
    print("  data region: " .. m2.dsz .. " bytes")
    if m2.dsz > 0 then
        print("  table = " .. string.format("%.1f%%", table_bytes * 100 / m2.dsz) .. " of data")
    end
    print("  entries matching hi>=0xFFFF8000 (our kptr filter): " ..
        (full_total - (range_counts[0] or 0) - (range_counts[1] or 0) -
        (range_counts[2] or 0) - (range_counts[3] or 0) - (range_counts[4] or 0) -
        (range_counts[5] or 0) - (range_counts[6] or 0) - (range_counts[7] or 0)) ..
        " of " .. full_total .. " total")
end
print("")

local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 522a COMPLETE ===")
