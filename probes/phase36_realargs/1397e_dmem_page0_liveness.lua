-- CRASH_CLASS: LOW -- stores only into pages already proven writable (0x1000..0x4000 rungs).  Page 0
-- is read, twice, and never written.
-- PROBE 1397e: is the page-0 table live metadata for the window, or a static snapshot?
--
-- 1397d dumped all 0x1000 bytes at dmem0 offset 0.  It is not a flat register array: it is a table
-- of records.  0x300..0x520 holds triples like (C0017600, 00000216, FFFFFFFF); 0x800..0xBB0 holds
-- 64 five-dword records (C0038000, E0000C00, 0000000F, 00000100, N) at stride 0x14 with N running
-- 0, 0x400, 0x800 ... 0xB400.  A stride and an arithmetic counter mean the page describes other
-- memory rather than being register state.
--
-- If it describes the window itself - a page table or a DMA descriptor list for the device mapping -
-- then writing into the window should update it, and, more importantly, the entries could be
-- rewritten to point elsewhere.  If it is a static snapshot taken when the GPU came up, it will not
-- move when neighbouring pages are touched.
--
-- Test: snapshot page 0, write distinct markers at rungs 0x2000, 0x3000 and 0x4000, snapshot page 0
-- again, and diff.  Also confirm the rungs are independent pages (a marker at 0x2000 must not appear
-- at 0x3000), and check the page for drift across two reads with nothing in between.
--
-- -- prior art:
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (full page-0 dump, 4 GB of offsets)
--   results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt (all rungs writable)
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt (store persists, shared backing)

print("=== PROBE 1397e: PAGE-0 TABLE LIVENESS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wr(a, v) local ok = pcall(function() memory.write_dword(a, uint64(v)) end) return ok end
local function hex(v) return string.format("%08X", v) end
local function isva(v) return v > 0 and v < 0x8000000000 end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local fd0 = N(mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] dmem0 fd=%d", fd0))
local function mapit(off, prot)
    return N(mk(477)(uint64(0), uint64(0x1000), uint64(prot), uint64(1), uint64(fd0), uint64(off)))
end

-- ---------------------------------------------------------------- snapshot helper
local function snap(va)
    local t = {}
    for i = 0, 0x3FF do t[i] = rd(va + i * 4) or 0 end
    return t
end

local function diff(a, b, label)
    local n = 0
    for i = 0, 0x3FF do
        if a[i] ~= b[i] then
            n = n + 1
            if n <= 24 then
                print(string.format("   %s DIFF @+0x%03X : %s -> %s", label, i * 4, hex(a[i]), hex(b[i])))
            end
        end
    end
    print(string.format("   %s: %d of 1024 dwords changed", label, n))
    return n
end

-- ---------------------------------------------------------------- A
print("")
print("[A] map page 0 twice (two independent mappings) and diff")
local R1 = mapit(0, 1)
local R2 = mapit(0, 1)
print(string.format("   R1=0x%010X R2=0x%010X", R1, R2))
if isva(R1) and isva(R2) then
    local s1 = snap(R1)
    local s2 = snap(R2)
    diff(s1, s2, "same-page")
end

-- ---------------------------------------------------------------- B
print("")
print("[B] rungs 0x2000 / 0x3000 / 0x4000 are independent pages")
local M2 = mapit(0x2000, 3)
local M3 = mapit(0x3000, 3)
local M4 = mapit(0x4000, 3)
if isva(M2) and isva(M3) and isva(M4) then
    wr(M2, 0x11112222)
    wr(M3, 0x33334444)
    wr(M4, 0x55556666)
    print(string.format("   0x2000=%s 0x3000=%s 0x4000=%s",
        hex(rd(M2)), hex(rd(M3)), hex(rd(M4))))
    print(string.format("   cross-reads: M2+4k=%s M3+4k=%s", hex(rd(M2 + 0x1000)), hex(rd(M3 + 0x1000))))
else
    print(string.format("   map failed: %s", es()))
end

-- ---------------------------------------------------------------- C
print("")
print("[C] did writing those rungs change page 0?")
if isva(R1) then
    local s1 = snap(R1)
    diff(s1, snap(R1), "noop")
    print("   (if the table is live for the window, the markers above should have moved something)")
end

-- ---------------------------------------------------------------- D
print("")
print("[D] is the window's page 0 the SAME backing as /dev/gc's page 0?")
local fdg = N(mk(5)(uint64(str_addr("/dev/gc")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
local G0 = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fdg), uint64(0)))
if isva(G0) then
    print(string.format("   gc page0 first 6 dwords: %s %s %s %s %s %s",
        hex(rd(G0)), hex(rd(G0 + 4)), hex(rd(G0 + 8)), hex(rd(G0 + 0xC)), hex(rd(G0 + 0x10)), hex(rd(G0 + 0x14))))
else
    print(string.format("   gc map refused: %s", es()))
end

-- ---------------------------------------------------------------- E
print("")
print("[E] what does the offset do at 0x3FF000 / 0x400000 (page boundary markers)")
for _, off in ipairs({0x3FF000, 0x400000, 0x401000}) do
    local va = mapit(off, 1)
    if isva(va) then
        print(string.format("   off=0x%08X : %s %s %s %s", off, hex(rd(va)), hex(rd(va + 4)), hex(rd(va + 8)), hex(rd(va + 0xC))))
    else
        print(string.format("   off=0x%08X -> %s", off, es()))
    end
end

print("")
print("[F] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
if fdg > 0 then print(string.format("   gc    -> %d", N(mk(6)(uint64(fdg), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))) end

print("")
print("=== PROBE 1397e COMPLETE ===")
