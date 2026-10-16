-- 14.10 Probe 41o: header chase v2 — tight scan with keepalive prints
-- 41n died of silence: 4M-iteration scan produced no output for 30s and
-- the recv timeout killed the connection. Fixes:
--   * scan only [anchor-4MB, anchor+256KB] (41j/41k: live objects were
--     ~136KB BELOW the alloc anchor — heap grows by bump allocation)
--   * print a keepalive line every 64K iterations
-- Same goal: find objects with low dword 0x1A3A4EE0, read full qword P,
-- dump P's region, deref heap entries one level.

print("=== 41o: HEADER CHASE v2 ===")
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
-- PART 1: scan
-- ---------------------------------------------------------------
local WIN_BACK = 0x400000      -- 4 MB below anchor
local WIN_FWD  = 0x40000       -- 256 KB above
local lo = anchor - (anchor % 8) - WIN_BACK
local hi = anchor + WIN_FWD
print(string.format("scanning 0x%x .. 0x%x", lo, hi))

local hits = {}
local a = lo
local iter = 0
while a < hi do
    if memory.read_dword(a):tonumber() == TARGET_LO then
        table.insert(hits, a)
        print(string.format("HIT @ 0x%x", a))
        if #hits >= 24 then break end
    end
    a = a + 8
    iter = iter + 1
    if iter % 0x10000 == 0 then
        print(string.format("  ... 0x%x (%d hits)", a, #hits))
    end
end
print("scan done: " .. #hits .. " hits")

if #hits == 0 then
    print("no hits — will need wider/different window")
    print("=== 41o DONE (no hits) ===")
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
    print("all high dwords are 0 — TARGET is genuinely 32-bit (weird)")
    print("=== 41o DONE (no pointer) ===")
    return
end
print(string.format("real header pointer P = 0x%x", real_P))

-- ---------------------------------------------------------------
-- PART 3: object dump (first hit)
-- ---------------------------------------------------------------
print("")
print("--- object dump (first hit, 0x80 bytes) ---")
local base = hits[1]
for off = 0, 0x70, 0x10 do
    local p = base + off
    local l1 = memory.read_dword(p):tonumber()
    local h1 = memory.read_dword(p + 4):tonumber()
    local l2 = memory.read_dword(p + 8):tonumber()
    local h2 = memory.read_dword(p + 12):tonumber()
    print(string.format("  +0x%02x: %08x_%08x  %08x_%08x", off, h1, l1, h2, l2))
end

-- ---------------------------------------------------------------
-- PART 4: dump at P
-- ---------------------------------------------------------------
print("")
print("--- dump at P (tag before each read) ---")
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
-- PART 5: one-level deref of heap entries
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

print("=== 41o DONE ===")
