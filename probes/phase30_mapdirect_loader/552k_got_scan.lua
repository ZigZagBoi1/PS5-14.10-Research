-- CRASH_CLASS: LOW
-- PROBE 552k: Brute-force GOT scan for libkernel function addresses
--
-- The eboot base from dynlib_get_info is .text start, not ELF header.
-- Can't parse ELF headers directly. Instead:
--   1. Dump module info structure to find data segment
--   2. Scan backwards from text for ELF magic
--   3. Brute-force scan all readable pages near eboot for libkernel pointers
--   4. Cross-reference found offsets with known functions

print("=== PROBE 552k: GOT scan for libkernel imports ===")
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

-- Module info
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)

-- Read all dynlib_info fields
print("[1] eboot dynlib_info dump")
for off = 0, 0x15F, 4 do
    local v = rd(N(ib) + off)
    if v and v ~= 0 then
        local uv = v < 0 and v + 0x100000000 or v
        print(string.format("  +0x%03X: 0x%08X", off, uv))
    end
end

-- Read eboot name
local name0 = ""
for i = 0, 63 do
    local b = rd(N(ib) + 8 + i)
    if b then local c = b % 256; if c == 0 then break end
        if c >= 32 and c < 127 then name0 = name0 .. string.char(c) end
    end
end
print("  name: " .. name0)

local eb_text_lo = rd(N(ib) + 0x108) or 0
local eb_text_hi = rd(N(ib) + 0x10C) or 0
local eb_text_sz = rd(N(ib) + 0x110) or 0
if eb_text_lo < 0 then eb_text_lo = eb_text_lo + 0x100000000 end
if eb_text_hi < 0 then eb_text_hi = eb_text_hi + 0x100000000 end
if eb_text_sz < 0 then eb_text_sz = eb_text_sz + 0x100000000 end

-- Segment 2 (possible data or relro)
local eb_seg2_lo = rd(N(ib) + 0x118) or 0
local eb_seg2_hi = rd(N(ib) + 0x11C) or 0
local eb_seg2_sz = rd(N(ib) + 0x120) or 0
if eb_seg2_lo < 0 then eb_seg2_lo = eb_seg2_lo + 0x100000000 end
if eb_seg2_hi < 0 then eb_seg2_hi = eb_seg2_hi + 0x100000000 end
if eb_seg2_sz < 0 then eb_seg2_sz = eb_seg2_sz + 0x100000000 end

-- Segments 3, 4
local eb_seg3_lo = rd(N(ib) + 0x128) or 0
local eb_seg3_hi = rd(N(ib) + 0x12C) or 0
local eb_seg3_sz = rd(N(ib) + 0x130) or 0
if eb_seg3_lo < 0 then eb_seg3_lo = eb_seg3_lo + 0x100000000 end
if eb_seg3_hi < 0 then eb_seg3_hi = eb_seg3_hi + 0x100000000 end
if eb_seg3_sz < 0 then eb_seg3_sz = eb_seg3_sz + 0x100000000 end

local eb_seg4_lo = rd(N(ib) + 0x138) or 0
local eb_seg4_hi = rd(N(ib) + 0x13C) or 0
local eb_seg4_sz = rd(N(ib) + 0x140) or 0
if eb_seg4_lo < 0 then eb_seg4_lo = eb_seg4_lo + 0x100000000 end
if eb_seg4_hi < 0 then eb_seg4_hi = eb_seg4_hi + 0x100000000 end
if eb_seg4_sz < 0 then eb_seg4_sz = eb_seg4_sz + 0x100000000 end

print("")
print(string.format("  seg1(text): 0x%X%08X sz=0x%X", eb_text_hi, eb_text_lo, eb_text_sz))
print(string.format("  seg2:       0x%X%08X sz=0x%X", eb_seg2_hi, eb_seg2_lo, eb_seg2_sz))
print(string.format("  seg3:       0x%X%08X sz=0x%X", eb_seg3_hi, eb_seg3_lo, eb_seg3_sz))
print(string.format("  seg4:       0x%X%08X sz=0x%X", eb_seg4_hi, eb_seg4_lo, eb_seg4_sz))

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
print(string.format("\nlibkernel: 0x%X%08X size=0x%X", lk_hi, lk_lo, lk_sz))
local lk_base = lk_lo + lk_hi * 0x100000000
local lk_end = lk_base + lk_sz

-- [2] Scan backwards for ELF header
print("")
print("[2] Scan backwards from eboot text for ELF magic")
local eb_base = uint64(string.format("0x%X%08X", eb_text_hi, eb_text_lo))
for back = 0, 0x100000, 0x1000 do
    local addr = N(eb_base) - back
    if addr <= 0 then break end
    local d = rd(addr)
    if d == 0x464C457F then
        print(string.format("  ELF magic at eboot-0x%X (addr=0x%X)", back, addr))
        -- Dump some header info
        for hoff = 0, 0x40, 4 do
            local hv = rd(addr + hoff)
            if hv then print(string.format("    +0x%02X: 0x%08X",
                hoff, hv < 0 and hv + 0x100000000 or hv))
            end
        end
        break
    elseif d == nil then
        break  -- unmapped
    end
end

-- [3] Scan data segments for libkernel pointers
print("")
print("[3] Scan eboot segments for libkernel function pointers")

local segments = {}
if eb_seg2_sz > 0 and eb_seg2_sz < 0x1000000 then
    table.insert(segments, {
        name = "seg2",
        base = uint64(string.format("0x%X%08X", eb_seg2_hi, eb_seg2_lo)),
        size = eb_seg2_sz
    })
end
if eb_seg3_sz > 0 and eb_seg3_sz < 0x1000000 then
    table.insert(segments, {
        name = "seg3",
        base = uint64(string.format("0x%X%08X", eb_seg3_hi, eb_seg3_lo)),
        size = eb_seg3_sz
    })
end
if eb_seg4_sz > 0 and eb_seg4_sz < 0x1000000 then
    table.insert(segments, {
        name = "seg4",
        base = uint64(string.format("0x%X%08X", eb_seg4_hi, eb_seg4_lo)),
        size = eb_seg4_sz
    })
end

local found_imports = {}
for _, seg in ipairs(segments) do
    local scan_sz = math.min(seg.size, 0x200000)
    print(string.format("  scanning %s: %s sz=0x%X", seg.name, fmt(seg.base), scan_sz))
    local count = 0
    for off = 0, scan_sz - 8, 8 do
        local v = rq(N(seg.base) + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            local vaddr = vl + vh * 0x100000000
            if vaddr >= lk_base and vaddr < lk_end then
                local lk_off = vaddr - lk_base
                table.insert(found_imports, {seg = seg.name, off = off, lk_off = lk_off})
                if #found_imports <= 60 then
                    print(string.format("    %s+0x%06X → lk+0x%05X", seg.name, off, lk_off))
                end
                count = count + 1
            end
        end
    end
    print(string.format("    found %d libkernel pointers", count))
end

-- [4] Summary: catalog all unique libkernel offsets
print("")
print("[4] Unique libkernel offsets (potential function addresses)")
local offsets = {}
for _, f in ipairs(found_imports) do
    offsets[f.lk_off] = (offsets[f.lk_off] or 0) + 1
end
local sorted = {}
for off, count in pairs(offsets) do
    table.insert(sorted, {off = off, count = count})
end
table.sort(sorted, function(a, b) return a.off < b.off end)

local known = {
    [0x15020] = "KILLS (MapDirectMemory?)",
    [0x17810] = "GetDirectMemorySize OK",
    [0x17EF0] = "AllocateDirectMemory OK",
}

for _, s in ipairs(sorted) do
    local label = known[s.off] or ""
    print(string.format("  lk+0x%05X (%d refs) %s", s.off, s.count, label))
end

print("")
print("DONE")
