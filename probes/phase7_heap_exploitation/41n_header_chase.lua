-- 14.10 Probe 41n: chase the REAL object header pointer
-- 41m crashed: 0x1A3A4EE0 as a raw address is UNMAPPED (SIGSEGV, si_addr
-- 0x1A3A4E00 confirmed via crash record 0x13371337). Conclusion: the value
-- at object+0 is only the LOW dword of a 64-bit pointer — almost certainly
-- 0x00000003_1A3A4EE0, i.e. a HEAP object (0x3_1A3A4EE0 sits in the known
-- 0x3_1xxxxxxx heap range). Heap base shifts per run, so:
--   1. anchor = memory.alloc() -> learn this run's heap address
--   2. scan a window around the anchor for dword == 0x1A3A4EE0
--   3. read the FULL qword at +0 of each hit -> real pointer P
--   4. dump region at P, classify entries, one-level deref of heap entries
-- Never reads 0x1A3A4xxx directly again.

print("=== 41n: REAL HEADER POINTER CHASE ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

local TARGET_LO = 0x1A3A4EE0

local function to_num(v)
    local ok, n = pcall(function() return v:tonumber() end)
    if ok then return n end
    return tonumber(v) or 0
end

-- ---------------------------------------------------------------
-- PART 1: anchor on this run's heap
-- ---------------------------------------------------------------
local anchor_buf = memory.alloc(16)
local anchor = to_num(anchor_buf)
print(string.format("alloc anchor: 0x%x", anchor))

-- heap is 0x3_xxxxxxxx; take the address modulo to find low bits
local heap_hi = math.floor(anchor / 0x100000000)
print(string.format("heap high dword: 0x%x", heap_hi))

-- ---------------------------------------------------------------
-- PART 2: scan window around anchor for low dword == TARGET_LO
-- ---------------------------------------------------------------
local WIN = 0x1000000          -- +-16 MB
local lo = anchor - (anchor % 8) - WIN
local hi = anchor + WIN
print(string.format("scanning 0x%x .. 0x%x (step 8)", lo, hi))

local hits = {}
local a = lo
while a < hi do
    if memory.read_dword(a):tonumber() == TARGET_LO then
        table.insert(hits, a)
        if #hits >= 24 then break end
    end
    a = a + 8
end
print("hits: " .. #hits)
for i, h in ipairs(hits) do
    print(string.format("  hit %2d @ 0x%x", i, h))
end

if #hits == 0 then
    print("no objects found in window — widen WIN and retry")
    print("=== 41n DONE (no hits) ===")
    return
end

-- ---------------------------------------------------------------
-- PART 3: full qword at +0 of each hit -> the real pointer P
-- ---------------------------------------------------------------
print("")
print("--- PART 3: full header qwords ---")
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
    print("all headers have high dword 0 — TARGET really is a 32-bit value")
    print("=== 41n DONE (no pointer) ===")
    return
end
print(string.format("real header pointer P = 0x%x", real_P))

-- ---------------------------------------------------------------
-- PART 4: dump object structure around first hit (0x80 bytes)
-- ---------------------------------------------------------------
print("")
print("--- PART 4: object dump (first hit) ---")
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
-- PART 5: dump region at P (the shared header/type object)
-- ---------------------------------------------------------------
print("")
print("--- PART 5: dump at P (tag printed before each line) ---")
local entries = {}
for off = 0, 0x78, 8 do
    print(string.format("reading P+0x%02x ...", off))
    local p = real_P + off
    local ql = memory.read_dword(p):tonumber()
    local qh = memory.read_dword(p + 4):tonumber()
    local v = qh * 0x100000000 + ql
    local cls = "other"
    if v == 0 then cls = "null"
    elseif v < 0x10000 then cls = "small-int"
    elseif qh == heap_hi then cls = "HEAP(same arena)"
    elseif qh == 0 and ql >= 0x10000000 then cls = "low32"
    elseif v >= 0x20000000 and v < 0x60000000 then cls = "CODE??"
    end
    print(string.format("  P+0x%02x: %08x_%08x  %s", off, qh, ql, cls))
    if v ~= 0 then table.insert(entries, { off = off, val = v, cls = cls }) end
end

-- ---------------------------------------------------------------
-- PART 6: one-level deref of HEAP entries only (tag before each)
-- ---------------------------------------------------------------
print("")
print("--- PART 6: deref heap entries ---")
for _, e in ipairs(entries) do
    if e.cls == "HEAP(same arena)" then
        print(string.format("deref P+0x%02x -> 0x%x", e.off, e.val))
        for i = 0, 3 do
            local p = e.val + i * 8
            local ql = memory.read_dword(p):tonumber()
            local qh = memory.read_dword(p + 4):tonumber()
            print(string.format("    +%d: %08x_%08x", i * 8, qh, ql))
        end
    end
end

print("")
print("--- interpretation guide ---")
print("P contains several same-arena heap ptrs  -> shared type/proto object")
print("P entries deref to more tables           -> Lua proto/GC metadata")
print("any CODE?? entry in P                    -> function ptr = hijack target")
print("=== 41n DONE ===")
