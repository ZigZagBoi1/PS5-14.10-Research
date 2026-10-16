-- 14.10 Probe 41q: anchor-relative scan (the 41p miss fix)
-- 41p scanned [0x310000000, 0x310A05520]: fully mapped, ZERO hits.
-- But 41p's anchor was 0x310BDCFC0 — the zone [0x310A05520, anchor]
-- was never scanned. 41k found objects ~136KB BELOW its anchor, so the
-- object field moves with the anchor. Fix: window relative to THIS
-- run's anchor, scanning downward from just under it.

print("=== 41q: ANCHOR-RELATIVE SCAN ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

local TARGET_LO = 0x1A3A4EE0

local function to_num(v)
    local ok, n = pcall(function() return v:tonumber() end)
    if ok then return n end
    return tonumber(v) or 0
end

local anchor_buf = memory.alloc(16)
local anchor = to_num(anchor_buf)
local heap_hi = math.floor(anchor / 0x100000000)
print(string.format("alloc anchor: 0x%x (hi=0x%x)", anchor, heap_hi))

-- ---------------------------------------------------------------
-- PART 1: scan DOWN from anchor-8 to anchor-4MB
-- ---------------------------------------------------------------
local BOT = anchor - 0x400000
print(string.format("scanning DOWN 0x%x -> 0x%x", anchor - 8, BOT))

local hits = {}
local a = anchor - (anchor % 8) - 8
local iter = 0
while a >= BOT do
    if memory.read_dword(a):tonumber() == TARGET_LO then
        table.insert(hits, a)
        print(string.format("HIT @ 0x%x (anchor-0x%x)", a, anchor - a))
        if #hits >= 24 then break end
    end
    a = a - 8
    iter = iter + 1
    if iter % 0x8000 == 0 then
        print(string.format("  ... 0x%x (%d hits)", a, #hits))
    end
end
print("scan done: " .. #hits .. " hits")

if #hits == 0 then
    print("still no hits — objects may live above anchor or in another arena")
    print("=== 41q DONE (no hits) ===")
    return
end

-- ---------------------------------------------------------------
-- PART 2: full header qwords
-- ---------------------------------------------------------------
print("")
print("--- full header qwords ---")
local real_P = 0
for i = 1, math.min(#hits, 8) do
    local base = hits[i]
    local qw_lo = memory.read_dword(base):tonumber()
    local qw_hi = memory.read_dword(base + 4):tonumber()
    print(string.format("obj @ 0x%x: +0 = %08x_%08x", base, qw_hi, qw_lo))
    if real_P == 0 and qw_hi ~= 0 then
        real_P = qw_hi * 0x100000000 + qw_lo
    end
end

if real_P == 0 then
    print("all high dwords 0 — TARGET is a genuine 32-bit value (tag/hash/id)")
    print("=== 41q DONE (no pointer) ===")
    return
end
print(string.format("real header pointer P = 0x%x", real_P))

-- ---------------------------------------------------------------
-- PART 3: dump at P (tag before each read)
-- ---------------------------------------------------------------
print("")
print("--- dump at P ---")
local entries = {}
for off = 0, 0x78, 8 do
    print(string.format("read P+0x%02x", off))
    local p = real_P + off
    local ql = memory.read_dword(p):tonumber()
    local qh = memory.read_dword(p + 4):tonumber()
    local v = qh * 0x100000000 + ql
    local cls = "other"
    if v == 0 then cls = "null"
    elseif v < 0x10000 then cls = "small-int"
    elseif qh == heap_hi then cls = "HEAP"
    elseif v >= 0x20000000 and v < 0x60000000 then cls = "CODE??"
    end
    print(string.format("  P+0x%02x: %08x_%08x  %s", off, qh, ql, cls))
    if v ~= 0 then table.insert(entries, { off = off, val = v, cls = cls }) end
end

-- ---------------------------------------------------------------
-- PART 4: one-level deref of heap entries
-- ---------------------------------------------------------------
print("")
print("--- deref heap entries ---")
for _, e in ipairs(entries) do
    if e.cls == "HEAP" then
        print(string.format("deref P+0x%02x -> 0x%x", e.off, e.val))
        for i = 0, 3 do
            local p = e.val + i * 8
            local ql = memory.read_dword(p):tonumber()
            local qh = memory.read_dword(p + 4):tonumber()
            print(string.format("    +%d: %08x_%08x", i * 8, qh, ql))
        end
    end
end

print("=== 41q DONE ===")
