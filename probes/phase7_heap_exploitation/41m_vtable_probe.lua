-- 14.10 Probe 41m: dump and classify 0x1A3A4EE0 (the REAL common object header)
-- Context: 41l showed 0x142621xxx is a hash/bucket table of backpointers,
-- and the actual shared value at +0 of live heap objects is 0x1A3A4EE0.
-- Goals:
--   1. Dump the region around 0x1A3A4EE0 (hex, safe)
--   2. Classify each pointer-sized value: data / heap / likely-code
--      (NEVER dereference likely-code: XOM -> SIGBUS kills the loader.
--       A crash on read IS the oracle that it's a code page.)
--   3. Re-discover live objects this run by scanning the heap window for
--      dword == 0x1A3A4EE0, then dump their full structure.
-- Output is hex-only (41l sections 4/5 were garbled by raw binary prints).

print("=== 41m: VTABLE TARGET 0x1A3A4EE0 ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

local TARGET = 0x1A3A4EE0

-- ---------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------
local function hx(v, w)
    return string.format("%0" .. (w or 8) .. "x", v)
end

-- classify a 64-bit value by magnitude (regions observed in 41i-41l):
--   0x014xxxxxxx        low data mapping (bucket table region)
--   0x1Axxxxxx         low mapping (TARGET lives here)
--   0x3_1xxxxxxx       heap (per-run shifting)
--   0x4xxxxxxx-0x6xxxxxxx  code region (crash handler was 0x533118f4)
local function classify(v)
    if v == 0 then return "null" end
    if v < 0x10000 then return "small-int"
    elseif v < 0x10000000 then return "low??"
    elseif v < 0x20000000 then return "LOW-DATA"
    elseif v < 0x100000000 then return "low32?"
    elseif v < 0x200000000 then return "LOW-DATA-4G"
    elseif v >= 0x300000000 and v < 0x400000000 then return "HEAP"
    elseif v >= 0x40000000 and v < 0x80000000 then return "CODE??"
    elseif v >= 0x400000000 and v < 0x800000000 then return "hi-data?"
    else return "other" end
end

-- safe to deref only these (data/heap); anything else: label only
local function deref_ok(v)
    return (v >= 0x10000000 and v < 0x20000000)
        or (v >= 0x100000000 and v < 0x200000000)
        or (v >= 0x300000000 and v < 0x400000000)
end

-- ---------------------------------------------------------------
-- PART 1: dump TARGET region (qwords, hex)
-- ---------------------------------------------------------------
print("")
print("--- PART 1: region dump 0x1A3A4E00 .. 0x1A3A5000 ---")
for off = -0xE0, 0x120, 0x10 do
    local a = TARGET + off
    local lo = memory.read_dword(a):tonumber()
    local hi = memory.read_dword(a + 4):tonumber()
    local lo2 = memory.read_dword(a + 8):tonumber()
    local hi2 = memory.read_dword(a + 12):tonumber()
    print(string.format("0x%08x: %08x_%08x  %08x_%08x", a, hi, lo, hi2, lo2))
end

-- ---------------------------------------------------------------
-- PART 2: classify + selective deref of each qword entry
-- ---------------------------------------------------------------
print("")
print("--- PART 2: entry classification (deref = data/heap only) ---")
local interesting = {}
for off = 0, 0x100, 8 do
    local a = TARGET + off
    local hi = memory.read_dword(a + 4):tonumber()
    local lo = memory.read_dword(a):tonumber()
    local v = hi * 0x100000000 + lo
    local cls = classify(v)
    print(string.format("[+0x%02x] 0x%x  %s", off, v, cls))
    if cls ~= "null" and cls ~= "small-int" then
        table.insert(interesting, { off = off, val = v, cls = cls })
    end
end

print("")
print("--- PART 3: deref pass (tag printed BEFORE each read) ---")
for _, e in ipairs(interesting) do
    if deref_ok(e.val) then
        print(string.format("deref [+0x%02x] -> 0x%x :", e.off, e.val))
        for i = 0, 3 do
            local b = e.val + i * 8
            local hi = memory.read_dword(b + 4):tonumber()
            local lo = memory.read_dword(b):tonumber()
            print(string.format("    0x%x: %08x_%08x", b, hi, lo))
        end
    else
        print(string.format("skip  [+0x%02x] 0x%x (%s) — not safe to read",
            e.off, e.val, e.cls))
    end
end

-- ---------------------------------------------------------------
-- PART 4: find live objects this run (heap scan for dword TARGET)
-- ---------------------------------------------------------------
print("")
print("--- PART 4: heap scan for objects starting with 0x1A3A4EE0 ---")
-- windows derived from 41j/41k anchors (0x310856000, 0x310878000, 0x310924000)
local windows = {
    { 0x310800000, 0x310A00000 },
    { 0x310000000, 0x310800000 },
}
local hits = {}
for _, w in ipairs(windows) do
    local a = w[1]
    while a < w[2] and #hits < 32 do
        if memory.read_dword(a):tonumber() == TARGET then
            table.insert(hits, a)
        end
        a = a + 8
    end
    print(string.format("window 0x%x-0x%x: %d hits so far", w[1], w[2], #hits))
    if #hits >= 32 then break end
end

print("")
print("--- PART 5: object dumps (first 8 hits, 0x60 bytes each) ---")
for h = 1, math.min(#hits, 8) do
    local base = hits[h]
    print(string.format("object @ 0x%x:", base))
    for off = 0, 0x60, 0x10 do
        local a = base + off
        local lo = memory.read_dword(a):tonumber()
        local hi = memory.read_dword(a + 4):tonumber()
        local lo2 = memory.read_dword(a + 8):tonumber()
        local hi2 = memory.read_dword(a + 12):tonumber()
        print(string.format("  +0x%02x: %08x_%08x  %08x_%08x", off, hi, lo, hi2, lo2))
    end
end

-- ---------------------------------------------------------------
-- PART 6: verdict hints
-- ---------------------------------------------------------------
print("")
print("--- interpretation guide ---")
print("TARGET region = array of CODE?? pointers   -> real vtable, plan redirect")
print("TARGET region = mixed HEAP/LOW-DATA ptrs   -> type descriptor w/ links")
print("TARGET region = mostly small-int/null      -> struct, not a table at all")
print("loader died on a deref line                -> that address is XOM code")
print("=== 41m DONE ===")
