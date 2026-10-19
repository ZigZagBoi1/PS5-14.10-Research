-- CRASH_CLASS: LOW
-- PROBE 55f: sys 674 virtual_query_all — full record layout dump
--
-- Context: 55e showed sys 674 returns 316+ VM regions (ret=0).
-- But prot/flags displayed as zeros — our 72-byte record parsing was wrong.
-- Need to dump raw bytes of the first ~20 records to find:
--   1. Actual field layout (start addr, end addr, prot, flags, type, etc.)
--   2. Hidden kernel pointers in fields we missed
--   3. Whether any record contains kernel VA range (0xFFFF8xxx)
--
-- RE says: record is 72 bytes, copy is min(stride, 72).
-- 72 bytes = 9 qwords or 18 dwords.

print("=== PROBE 55f: sys 674 FULL RECORD DUMP ===")
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
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end

local sc20 = make_syscall(20)
local sc674 = make_syscall(674)
local pid = to_num(select(2, pcall(function() return sc20() end)))
print("PID: " .. pid)

-- ============================================================
-- [A] Full raw dump of first 30 records (72 bytes each = 18 dwords)
-- ============================================================
print("")
print("[A] Raw 72-byte record dump (first 30 records)")
do
    local STRIDE = 72
    local MAX = 512
    local buf = memory.alloc(STRIDE * MAX + 0x100)
    -- Zero the entire buffer
    for i = 0, STRIDE * 32 - 1, 4 do safe_wd(buf + i, 0) end
    local countp = memory.alloc(16)
    safe_wq(countp, uint64(0))

    local ok, ret = pcall(function()
        return sc674(uint64(buf), uint64(STRIDE), uint64(MAX),
                      uint64(countp), uint64(0x40000000))
    end)
    if not ok then
        print("  674 CRASHED: " .. tostring(ret))
        return
    end
    print("  ret: " .. hexval(ret))
    local count = safe_rd(countp) or 0
    print("  total regions: " .. count)

    -- Dump first 30 records completely
    local dump_count = 30
    if dump_count > count then dump_count = count end
    if dump_count > MAX then dump_count = MAX end

    for i = 0, dump_count - 1 do
        local base = buf + i * STRIDE
        local line = string.format("  [%03d]", i)
        for d = 0, 17 do
            local v = safe_rd(base + d * 4) or 0
            line = line .. string.format(" %08X", v)
        end
        print(line)
    end

    -- ============================================================
    -- [B] Identify field layout by analyzing patterns
    -- ============================================================
    print("")
    print("[B] Field analysis")

    -- For each dword position, find how many records have nonzero values
    local nonzero_counts = {}
    local limit = count
    if limit > MAX then limit = MAX end
    for d = 0, 17 do
        local nz = 0
        for i = 0, limit - 1 do
            local v = safe_rd(buf + i * STRIDE + d * 4) or 0
            if v ~= 0 then nz = nz + 1 end
        end
        nonzero_counts[d] = nz
    end

    print("  Dword position nonzero counts (of " .. limit .. " records):")
    for d = 0, 17 do
        local pct = math.floor(nonzero_counts[d] * 100 / limit)
        if nonzero_counts[d] > 0 then
            print(string.format("    dword[%2d] (+0x%02X): %d nonzero (%d%%)",
                d, d * 4, nonzero_counts[d], pct))
        end
    end

    -- ============================================================
    -- [C] Kernel pointer scan across ALL 72 bytes (every qword alignment)
    -- ============================================================
    print("")
    print("[C] Full kernel pointer scan (all qword offsets)")
    local kptr_found = false
    for i = 0, limit - 1 do
        local base = buf + i * STRIDE
        for off = 0, 64, 4 do
            local lo = safe_rd(base + off)
            local hi = safe_rd(base + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                -- Filter out sentinels
                if not (hi == 0xFFFFFFFF and (lo == 0 or lo == 0xFFFFFFFF)) then
                    print(string.format("  rec[%d]+0x%02X: 0x%08X_%08X  <<< KERNEL PTR!",
                        i, off, hi, lo))
                    kptr_found = true
                end
            end
        end
    end
    if not kptr_found then
        print("  no kernel pointers found")
    end

    -- ============================================================
    -- [D] Look for records with high addresses (kernel VA space)
    -- Check qword[0] (presumed start addr) for kernel range
    -- ============================================================
    print("")
    print("[D] Records with addresses > 0x800000000000")
    for i = 0, limit - 1 do
        local base = buf + i * STRIDE
        -- Check first qword as address
        local lo = safe_rd(base) or 0
        local hi = safe_rd(base + 4) or 0
        if hi >= 0x8000 then
            print(string.format("  rec[%d] start: 0x%08X_%08X", i, hi, lo))
        end
        -- Check second qword as end address
        lo = safe_rd(base + 8) or 0
        hi = safe_rd(base + 12) or 0
        if hi >= 0x8000 then
            print(string.format("  rec[%d] end:   0x%08X_%08X", i, hi, lo))
        end
    end

    -- ============================================================
    -- [E] Try larger stride to see if there's more data per record
    -- Maybe 72 bytes isn't capturing everything
    -- ============================================================
    print("")
    print("[E] Test with stride=128 (extra padding)")
    local buf2 = memory.alloc(128 * 32)
    for i = 0, 128 * 4 - 1, 4 do safe_wd(buf2 + i, 0) end
    local countp2 = memory.alloc(16)
    safe_wq(countp2, uint64(0))

    local ok2, ret2 = pcall(function()
        return sc674(uint64(buf2), uint64(128), uint64(32),
                      uint64(countp2), uint64(0x40000000))
    end)
    if ok2 then
        print("  ret: " .. hexval(ret2))
        local c2 = safe_rd(countp2) or 0
        print("  count: " .. c2)
        -- Compare first record at stride 72 vs 128
        print("  stride=72 rec[0]:")
        local line1 = "   "
        for d = 0, 17 do
            line1 = line1 .. string.format(" %08X", safe_rd(buf + d * 4) or 0)
        end
        print(line1)
        print("  stride=128 rec[0]:")
        local line2 = "   "
        for d = 0, 17 do
            line2 = line2 .. string.format(" %08X", safe_rd(buf2 + d * 4) or 0)
        end
        print(line2)
        -- Check bytes 72-127 for extra data
        print("  stride=128 rec[0] bytes 72-127:")
        local extra = "   "
        local any_extra = false
        for d = 18, 31 do
            local v = safe_rd(buf2 + d * 4) or 0
            extra = extra .. string.format(" %08X", v)
            if v ~= 0 then any_extra = true end
        end
        if any_extra then print(extra) end
    end

    -- ============================================================
    -- [F] Second enumeration path: records from 0x80000000000+
    -- RE says there's a second path starting at 0x80000000000
    -- These might be kernel mappings!
    -- Check if any of the 316 records are from that range
    -- ============================================================
    print("")
    print("[F] Records analysis — address ranges")
    local ranges = {userlow=0, userhigh=0, system=0, gpu=0, other=0}
    for i = 0, limit - 1 do
        local base = buf + i * STRIDE
        local lo = safe_rd(base) or 0
        local hi = safe_rd(base + 4) or 0
        if hi == 0 and lo < 0x80000000 then
            ranges.userlow = ranges.userlow + 1
        elseif hi <= 0x0000000F then
            ranges.userhigh = ranges.userhigh + 1
        elseif hi >= 0x80000000 then
            ranges.system = ranges.system + 1
        else
            ranges.other = ranges.other + 1
        end
    end
    print(string.format("  userlow (0-2GB): %d", ranges.userlow))
    print(string.format("  userhigh (2GB-64GB): %d", ranges.userhigh))
    print(string.format("  system (>0x80000000_00000000): %d", ranges.system))
    print(string.format("  other: %d", ranges.other))

    -- ============================================================
    -- [G] Dump last 20 records (highest addresses — most likely to
    -- contain kernel mappings from the second enumeration path)
    -- ============================================================
    print("")
    print("[G] Last 20 records (highest addresses)")
    local start_idx = limit - 20
    if start_idx < 0 then start_idx = 0 end
    for i = start_idx, limit - 1 do
        local base = buf + i * STRIDE
        local line = string.format("  [%03d]", i)
        for d = 0, 17 do
            local v = safe_rd(base + d * 4) or 0
            line = line .. string.format(" %08X", v)
        end
        print(line)
    end
end

print("")
print("=== PROBE 55f COMPLETE ===")
