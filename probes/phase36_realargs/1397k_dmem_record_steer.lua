-- CRASH_CLASS: MODERATE -- writes one dword inside a populated record of the dmem header, then remaps.
-- PROBE 1397k: is the 0x800 record table the map that backs the window?
--
-- 1397j proved page 0 of /dev/dmem0 is ordinary writable RAM: stores land, survive 500 ms, and are
-- visible through a fresh mapping, while the populated records at 0x800.. (stride 0x14:
-- addr, 0xE0000C00, 0x0000000F, 0x00000100, N with N = 0, 0x400, 0x800 ... 0xB400) stay put.
--
-- If those 64 records are the page table for the first 0x10000 of the window -- 64 x 0x400 -- then
-- changing record[0].addr moves what offset 0x000 reads, and changing record[63].addr moves what
-- offset 0xFC00 reads.  If the pager re-reads the table on each mmap, a munmap/mmap cycle will show
-- the new backing.  That would make a writable table that steers a device mapping: the first half of
-- an arbitrary-physical-read primitive on this console.
--
-- If nothing changes, the records were consumed once at open() and only the initial mapping saw them,
-- or they describe a different allocation than the window this process maps.
--
-- The probe restores both records and the capture stops after [E]; nothing is left perturbed.
--
-- -- prior art:
--   results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt (page 0 is writable RAM)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (the 0x14-stride table)
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt (populated pages 0x0F-0x16)

print("=== PROBE 1397k: IS THE 0x800 RECORD TABLE THE MAP? ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
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

local function pmap(off, prot)
    return N(mk(477)(uint64(0), uint64(0x1000), uint64(prot), uint64(1), uint64(fd0), uint64(off)))
end
local function punmap(va)
    return N(mk(73)(uint64(va), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0)))
end
local function checksum(va)
    local h = 2166136261
    for i = 0, 0x3FF do
        local v = rd(va + i * 4)
        if v == nil then v = 0 end
        h = (h * 16777619 + v) % 4294967296
        h = (h + i) % 4294967296
    end
    return h
end

-- ---------------------------------------------------------------- A
print("")
print("[A] baseline page 0")
local P0 = pmap(0, 3)
print(string.format("   map -> 0x%010X", P0))
if not isva(P0) then print("   ABORT: " .. es()) return end
local S0 = checksum(P0)
print(string.format("   checksum %s", hex(S0)))
print(string.format("   offset 0x000 : %s %s %s %s", hex(rd(P0)), hex(rd(P0 + 4)), hex(rd(P0 + 8)), hex(rd(P0 + 0xC))))
print(string.format("   offset 0x400 : %s %s %s %s", hex(rd(P0 + 0x400)), hex(rd(P0 + 0x404)), hex(rd(P0 + 0x408)), hex(rd(P0 + 0x40C))))
print(string.format("   offset 0xF00 : %s %s %s %s", hex(rd(P0 + 0xF00)), hex(rd(P0 + 0xF04)), hex(rd(P0 + 0xF08)), hex(rd(P0 + 0xF0C))))
print(string.format("   offset 0xFC00 (page 0x0F, needs off 0xF000) - skipped here"))
print("   records 0..3 at 0x800:")
for i = 0, 3 do
    local b = P0 + 0x800 + i * 0x14
    print(string.format("     [%d] %s %s %s %s %s", i, hex(rd(b)), hex(rd(b + 4)), hex(rd(b + 8)), hex(rd(b + 0xC)), hex(rd(b + 0x10))))
end
print("   records 61..63:")
for i = 61, 63 do
    local b = P0 + 0x800 + i * 0x14
    print(string.format("     [%d] %s %s %s %s %s", i, hex(rd(b)), hex(rd(b + 4)), hex(rd(b + 8)), hex(rd(b + 0xC)), hex(rd(b + 0x10))))
end

-- ---------------------------------------------------------------- B
print("")
print("[B] rewrite record[0].addr  C0038000 -> C0039000")
local R0 = P0 + 0x800
local old0 = rd(R0)
print(string.format("   before %s", hex(old0)))
wr(R0, 0xC0039000)
print(string.format("   after  %s (write-back check)", hex(rd(R0))))

print("")
print("[C] munmap + remap page 0, look for a shift")
print(string.format("   munmap -> %d", punmap(P0)))
local P0b = pmap(0, 3)
print(string.format("   remap -> 0x%010X", P0b))
if isva(P0b) then
    local S1 = checksum(P0b)
    print(string.format("   checksum %s (was %s) %s", hex(S1), hex(S0), (S1 == S0) and "SAME" or "CHANGED"))
    print(string.format("   offset 0x000 : %s %s %s %s", hex(rd(P0b)), hex(rd(P0b + 4)), hex(rd(P0b + 8)), hex(rd(P0b + 0xC))))
    print(string.format("   record[0]    : %s", hex(rd(P0b + 0x800))))
    -- restore through this mapping
    wr(P0b + 0x800, 0xC0038000)
    print(string.format("   restored record[0] -> %s", hex(rd(P0b + 0x800))))
    P0 = P0b
else
    print(string.format("   remap failed: %s -- cannot restore, record[0] stays rewritten", es()))
end

-- ---------------------------------------------------------------- D
print("")
print("[D] same test on record[63], which should cover offset 0xFC00")
local P15 = pmap(0xF000, 3)
if isva(P15) then
    local base = P15 + (0xFC00 - 0xF000)
    print(string.format("   page 0xF map -> 0x%010X, offset 0xFC00 reads %s %s %s %s",
        P15, hex(rd(base)), hex(rd(base + 4)), hex(rd(base + 8)), hex(rd(base + 0xC))))
    local R63 = P0 + 0x800 + 63 * 0x14
    print(string.format("   record[63] = %s %s %s %s %s", hex(rd(R63)), hex(rd(R63 + 4)), hex(rd(R63 + 8)), hex(rd(R63 + 0xC)), hex(rd(R63 + 0x10))))
    wr(R63, (rd(R63) + 0x1000) % 4294967296)
    print(string.format("   rewritten  = %s", hex(rd(R63))))
    punmap(P15)
    local P15b = pmap(0xF000, 3)
    if isva(P15b) then
        local b2 = P15b + 0xC00
        print(string.format("   after remap, offset 0xFC00 reads %s %s %s %s", hex(rd(b2)), hex(rd(b2 + 4)), hex(rd(b2 + 8)), hex(rd(b2 + 0xC))))
        P15 = P15b
    end
    -- restore through page 0
    wr(P0 + 0x800 + 63 * 0x14, rd(R63) - 0x1000)
    print(string.format("   record[63] restored -> %s", hex(rd(P0 + 0x800 + 63 * 0x14))))
end

-- ---------------------------------------------------------------- E
print("")
print("[E] final consistency")
print(string.format("   page0 checksum %s", hex(checksum(P0))))
print(string.format("   record[0] %s   record[63] %s", hex(rd(P0 + 0x800)), hex(rd(P0 + 0x800 + 63 * 0x14))))

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397k COMPLETE ===")
