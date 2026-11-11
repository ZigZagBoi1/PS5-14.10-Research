-- CRASH_CLASS: MODERATE
-- PROBE 1564a: does 548 op 3 MAP_FIXED across a boundary between two entries of
--              different backing objects leave an inconsistent split?
--
-- Context: 1548a measured op 3 MAP_FIXED carving INSIDE one device entry: eight
-- carves accepted at the requested address, boundary intact, carved page reads 0
-- while the uncarved neighbour still reads C0012800.  Every carve so far sat
-- wholly inside one entry.  FreeBSD's vm_map_find with MAP_FIXED must delete the
-- covered range and insert one new entry; when the covered range spans two
-- entries with different `object` pointers, the delete path
-- (vm_map_delete 0x8ac89370 -> vm_map_lookup_entry 0x8ac86c40) has to clip both.
-- If it clips only the first, or reuses one entry's object for the new mapping,
-- the result is a mapping whose pages come from the wrong pager -- a kernel-side
-- object confusion that userland can read and write through.
--
-- The discriminator is readable from userland: build an anon page directly
-- before the device window, put a distinct sentinel in it, then MAP_FIXED a
-- two-page range that spans BOTH entries.  Correct behaviour replaces both with
-- fresh anonymous pages: both read back whatever we store.  A bad split shows
-- either device content (C0012800-shaped) inside the range we re-mapped, or a
-- fault on the first store into it.
--
-- prior art:
--   results/phase36_realargs/1548a_map_fixed_over_device_entry_20261110_173458.txt
--     -- 8/8 in-entry carves accepted, rv == at, boundary intact, carved page
--        reads 0, uncarved neighbour still C0012800, fresh node mapping still
--        C0012800.
--   results/phase36_realargs/1534b_sys548_op0_descriptor_map_20261110_141234.txt
--     -- op 3 at a free address returns the address; at a mapped address it
--        returns 0.
--   results/phase36_realargs/1562a_sys548_subrange_maxprot_20261110_194204.txt
--     -- an op 3 carve at 0xF0000C000 landed and read back as anon prot 3.
--   docs/VM_LAYER_14_10.md sections 15 and 22.
--
-- Method:
--   [A] 674 by name (buf, 72, 400, cnt, 0x40000000, 0) to find SceGnmTrapData;
--       fall back to 0xF00004000 if the name is not found.
--   [B] 547 the window and the page before it.  The page before must be free or
--       already anon; if it is a device page the probe switches to the page
--       after the window.
--   [C] op 3 MAP_FIXED anon at P (one page), store 0x11111111, read back, and
--       read the device page to record its content (expect C0012800-shaped).
--   [D] op 3 MAP_FIXED 0x8000 at P -- one 16 KiB page either side of the
--       boundary between our anon page and the device entry.
--   [E] read P and P+0x4000, store 0xCAFEBABE to both, read back.  Both must
--       return what we stored.  Any 0xC0012xxx value, any zero where we stored,
--       or a kill is the finding.
--   [F] 547 both pages afterwards and restore nothing (the range is our anon).

print("=== PROBE 1564a: 548 op3 MAP_FIXED across a device/anon boundary ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end

local sc_mmap   = mk(477)
local sc_getpid = mk(20)
local sc_547    = mk(547)
local sc_548    = mk(548)
local sc674     = mk(674)

local PAGE = 0x4000

local ent  = memory.alloc(0x100)
local done = memory.alloc(8)

local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local function prep(start, len, prot, op)
    zero(ent, 0x40)
    wd(ent + 0x00, start % 4294967296)
    wd(ent + 0x04, math.floor(start / 4294967296))
    wd(ent + 0x10, len % 4294967296)
    wd(ent + 0x14, math.floor(len / 4294967296))
    wd(ent + 0x18, prot)
    pcall(function() memory.write_byte(uint64(ent + 0x1C), op) end)
    wd(done, 0xEEEEEEEE)
end

local function fire()
    local ok, rv = pcall(function()
        return sc_548(uint64(0), uint64(0), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    return ok and to_num(rv) or -999, rd(done)
end

local rec = memory.alloc(0x20)
local function prot_of(addr)
    local ok, rv = pcall(function() return sc_547(uint64(addr), uint64(rec)) end)
    if not ok or to_num(rv) ~= 0 then return nil end
    return rd(rec + 0x10), rq(rec), rq(rec + 8)
end

local function mmap_fixed(at, len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(at), uint64(len), uint64(3), uint64(0x1012),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

print(string.format("[0] pid=%d", to_num(sc_getpid())))

-- ---- [A] find the window ----
local W = nil
local buf = memory.alloc(0x8000)
local cnt = memory.alloc(0x10)
wd(cnt, 0)
local okA, rvA = pcall(function()
    return sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt),
                 uint64(0x40000000), uint64(0))
end)
local nA = rd(cnt)
print(string.format("[A] 674 rv=%s count=%s", tostring(okA and to_num(rvA) or -999), tostring(nA)))
if okA and to_num(rvA) == 0 and (nA or 0) > 0 then
    for i = 0, nA - 1 do
        local base = buf + i * 72
        local name = ""
        for o = 0x21, 0x30 do
            local c = rd(base + o)
            if c == nil or c == 0 then break end
            name = name .. string.char(c % 256)
        end
        if name:find("SceGnmTrapData") then W = rq(base) break end
    end
end
if not W then
    W = 0xF00004000
    print(string.format("[A] name not found; using the documented 0x%X", W))
else
    print(string.format("[A] SceGnmTrapData at 0x%X", W))
end

-- ---- [B] pick a free page next to the window ----
local pW, sW, eW = prot_of(W)
print(string.format("[B] 547(W=0x%X): prot=%s rec=[0x%X,0x%X)",
    W, tostring(pW), to_num(sW or 0), to_num(eW or 0)))
local P = W - PAGE
local pBefore = prot_of(P)
local side = "before"
if pBefore ~= nil then
    P = W + PAGE
    pBefore = prot_of(P)
    side = "after"
end
print(string.format("[B] candidate P=0x%X (%s the window) prot=%s",
    P, side, tostring(pBefore)))
if pBefore ~= nil then
    print("[B] the neighbouring page is mapped as well; a boundary test needs a")
    print("[B] free side, so the carve below replaces two device entries instead.")
end

-- ---- [C] carve one anon page next to the window ----
print("")
print(string.format("[C] op3 MAP_FIXED anon at P=0x%X", P))
local gotC = mmap_fixed(P, PAGE)
print(string.format("[C] mmap returned %s", tostring(gotC)))
local pC, sC, eC = prot_of(P)
print(string.format("[C] 547(P) prot=%s rec=[0x%X,0x%X)",
    tostring(pC), to_num(sC or 0), to_num(eC or 0)))
wq(P, 0x11111111)
local rC = rq(P)
print(string.format("[C] P holds 0x%X after store (want 0x11111111)", to_num(rC or 0)))
local devBefore = rq(W)
print(string.format("[C] W holds 0x%X (device content)", to_num(devBefore or 0)))
if gotC ~= P then
    print("[C] the carve did not land at P; [D] would describe an unexpected range")
end

-- ---- [D] carve a two-page range spanning the boundary ----
print("")
local START = math.min(P, W - PAGE)
print(string.format("[D] op3 MAP_FIXED 0x8000 at START=0x%X (spans anon|device)", START))
local gotD = mmap_fixed(START, 2 * PAGE)
print(string.format("[D] mmap returned %s", tostring(gotD)))
local pD, sD, eD = prot_of(START)
print(string.format("[D] 547(START) prot=%s rec=[0x%X,0x%X)",
    tostring(pD), to_num(sD or 0), to_num(eD or 0)))

-- ---- [E] both pages must now be our memory ----
print("")
local hi = START + PAGE
wq(START, 0xCAFEBABE)
wq(hi, 0xCAFEBABE)
local v0 = rq(START)
local v1 = rq(hi)
print(string.format("[E] START holds 0x%X hi holds 0x%X (want 0xCAFEBABE both)",
    to_num(v0 or 0), to_num(v1 or 0)))
if v0 == 0xCAFEBABE and v1 == 0xCAFEBABE then
    print("[E] both pages are fresh anonymous memory: the two-entry split is clean")
elseif v0 ~= 0xCAFEBABE and v1 ~= 0xCAFEBABE then
    print("[E] *** NEITHER PAGE TOOK THE STORE -- the re-map did not replace both")
else
    print("[E] *** ONE PAGE DID NOT TAKE THE STORE -- inconsistent split ***")
end

-- ---- [F] describe both pages afterwards ----
print("")
local p1, s1 = prot_of(START)
local p2, s2 = prot_of(hi)
print(string.format("[F] 547 START prot=%s [0x%X]   hi prot=%s [0x%X]",
    tostring(p1), to_num(s1 or 0), tostring(p2), to_num(s2 or 0)))
if gotD == START and p1 ~= nil and s1 ~= nil and to_num(s1) <= hi then
    print("[F] one record covers both pages")
elseif p1 ~= nil and p2 ~= nil then
    print("[F] two records: the split produced separate entries")
end

print("")
print("=== PROBE 1564a COMPLETE ===")
