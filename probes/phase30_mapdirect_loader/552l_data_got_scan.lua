-- CRASH_CLASS: LOW
-- PROBE 552l: Scan eboot data segments for libkernel GOT entries
--
-- 552k found eboot layout:
--   seg1(text RX): 0x41490000, 0x494000
--   seg3(relro RO): 0x41A90000, 0x18000
--   seg2(data RW): 0x41C90000, 0x180000
--
-- DO NOT read backwards from text — XO pages before eboot kill process.
-- Scan seg2 and seg3 for pointers into libkernel text range.

print("=== PROBE 552l: eboot data GOT scan ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

-- Get eboot segments from dynlib_info
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)

local eb_text_lo = rd(N(ib) + 0x108) or 0
local eb_text_hi = rd(N(ib) + 0x10C) or 0
if eb_text_lo < 0 then eb_text_lo = eb_text_lo + 0x100000000 end
if eb_text_hi < 0 then eb_text_hi = eb_text_hi + 0x100000000 end
local eb_text_sz = rd(N(ib) + 0x110) or 0
if eb_text_sz < 0 then eb_text_sz = eb_text_sz + 0x100000000 end

-- seg3 (relro, prot=1)
local seg3_lo = rd(N(ib) + 0x128) or 0
local seg3_hi = rd(N(ib) + 0x12C) or 0
local seg3_sz = rd(N(ib) + 0x130) or 0
if seg3_lo < 0 then seg3_lo = seg3_lo + 0x100000000 end
if seg3_hi < 0 then seg3_hi = seg3_hi + 0x100000000 end
if seg3_sz < 0 then seg3_sz = seg3_sz + 0x100000000 end

-- seg2 (data, prot=3)
local seg2_lo = rd(N(ib) + 0x118) or 0
local seg2_hi = rd(N(ib) + 0x11C) or 0
local seg2_sz = rd(N(ib) + 0x120) or 0
if seg2_lo < 0 then seg2_lo = seg2_lo + 0x100000000 end
if seg2_hi < 0 then seg2_hi = seg2_hi + 0x100000000 end
if seg2_sz < 0 then seg2_sz = seg2_sz + 0x100000000 end

print(string.format("text: 0x%X%08X sz=0x%X", eb_text_hi, eb_text_lo, eb_text_sz))
print(string.format("seg3: 0x%X%08X sz=0x%X (relro)", seg3_hi, seg3_lo, seg3_sz))
print(string.format("seg2: 0x%X%08X sz=0x%X (data)", seg2_hi, seg2_lo, seg2_sz))

-- libkernel range
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
local lk_sz = rd(N(ib2) + 0x110) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_sz < 0 then lk_sz = lk_sz + 0x100000000 end
print(string.format("libkernel: 0x%X%08X sz=0x%X", lk_hi, lk_lo, lk_sz))

-- Also get libkernel data segments for wider matching
local lk_seg2_lo = rd(N(ib2) + 0x118) or 0
local lk_seg2_hi = rd(N(ib2) + 0x11C) or 0
local lk_seg2_sz = rd(N(ib2) + 0x120) or 0
if lk_seg2_lo < 0 then lk_seg2_lo = lk_seg2_lo + 0x100000000 end
if lk_seg2_hi < 0 then lk_seg2_hi = lk_seg2_hi + 0x100000000 end
if lk_seg2_sz < 0 then lk_seg2_sz = lk_seg2_sz + 0x100000000 end

local lk_base = lk_lo + lk_hi * 0x100000000
local lk_end = lk_base + lk_sz
-- Extended range: include data segments
local lk_ext_end = lk_end
if lk_seg2_sz > 0 then
    local s2 = lk_seg2_lo + lk_seg2_hi * 0x100000000 + lk_seg2_sz
    if s2 > lk_ext_end then lk_ext_end = s2 end
end
print(string.format("  text range: 0x%X - 0x%X", lk_base, lk_end))

-- Scan function
local function scan_segment(name, base_lo, base_hi, size)
    if size == 0 or size > 0x1000000 then return {} end
    local base = uint64(string.format("0x%X%08X", base_hi, base_lo))
    local results = {}
    print(string.format("\nScanning %s (0x%X bytes)...", name, size))
    for off = 0, size - 8, 8 do
        local v = rq(N(base) + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            local vaddr = vl + vh * 0x100000000
            if vaddr >= lk_base and vaddr < lk_end then
                local lk_off = vaddr - lk_base
                table.insert(results, {off = off, lk_off = lk_off})
            end
        end
    end
    return results
end

-- Scan both segments
local seg3_results = scan_segment("seg3(relro)", seg3_lo, seg3_hi, seg3_sz)
local seg2_results = scan_segment("seg2(data)", seg2_lo, seg2_hi, seg2_sz)

-- Merge and sort by libkernel offset
local all = {}
for _, r in ipairs(seg3_results) do
    table.insert(all, {seg = "relro", off = r.off, lk_off = r.lk_off})
end
for _, r in ipairs(seg2_results) do
    table.insert(all, {seg = "data", off = r.off, lk_off = r.lk_off})
end

-- Print all found entries
print(string.format("\n=== Found %d libkernel pointers ===", #all))
for i, e in ipairs(all) do
    if i <= 80 then
        print(string.format("  %s+0x%06X → lk+0x%05X", e.seg, e.off, e.lk_off))
    end
end

-- Unique offset catalog
print("")
print("=== Unique libkernel offsets ===")
local uniq = {}
for _, e in ipairs(all) do
    if not uniq[e.lk_off] then
        uniq[e.lk_off] = {count = 0, segs = {}}
    end
    uniq[e.lk_off].count = uniq[e.lk_off].count + 1
    uniq[e.lk_off].segs[e.seg] = true
end

local sorted = {}
for off, info in pairs(uniq) do
    table.insert(sorted, {off = off, count = info.count})
end
table.sort(sorted, function(a, b) return a.off < b.off end)

local known = {
    [0x15020] = "*** KILLS ***",
    [0x17810] = "GetDirectMemorySize OK",
    [0x17EF0] = "AllocateDirectMemory OK",
}

for _, s in ipairs(sorted) do
    local label = known[s.off] or ""
    print(string.format("  lk+0x%05X  (%d refs)  %s", s.off, s.count, label))
end

print(string.format("\nTotal unique offsets: %d", #sorted))
print("DONE")
