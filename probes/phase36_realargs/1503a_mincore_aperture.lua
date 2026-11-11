-- CRASH_CLASS: LOW -- maps and asks mincore for residency. Reads one page that is already known
-- to be populated (phys 0). Never reads a page it has not first proven resident.
-- PROBE 1503a: mincore as a safe residency oracle over the dmem aperture
--
-- The aperture (phys 0 .. 0x11FFF0000) is CPU-mappable read-only, but reading a page the pager
-- has not backed faults and kills the loader (1397g died that way). 42f2 walked 278,528 pages
-- with pcall, but 1397g shows a hole fault is not survivable in every shape, so any bulk scan of
-- the 512 MiB of the direct-memory pool that falls inside the aperture (0x100000000..0x11FFF0000)
-- needs a non-faulting oracle.
--
-- mincore(78) is that candidate: 43l proved it works and reports 32/32 resident for a GPU mmap.
-- The question is whether it DISCRIMINATES on the dmem pager - whether a page the pager has never
-- backed reports non-resident. If it does, the pool slice becomes safely scannable for GPU page
-- tables; if every mapped page reports resident, mincore is useless here and the scan has to be
-- done one mmap at a time with the fault risk accepted.
--
-- [A] map phys 0..0x40000 (pages 0x00-0x3F; 0x00 and 0x0F-0x16 are populated, the rest unknown)
--     and ask mincore for 64 page bits. No reads of unknown pages.
-- [B] map phys 0x100000000 (the direct-memory pool start, inside the aperture) for 8 MiB and ask
--     mincore for 512 page bits. Count resident.
-- [C] sanity: read phys 0 (known populated) so the capture proves the mapping works.
--
-- -- prior art:
--   results/43l_mincore_kaslr_20261016_180845.txt (mincore works; GPU mmap 32/32 resident)
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the 0xF000 block; died on a hole)
--   results/phase36_realargs/1502a_dmem_aperture_edge_20261109_221730.txt (aperture top 0x11FFF0000)
--   results/phase36_realargs/1410a_* / 1411a_* (ACL windows)

print("=== PROBE 1503a: MINCORE OVER THE DMEM APERTURE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local FD = -1
local function dmap(off, len, prot)
    local ok, v = pcall(function()
        return mk(477)(uint64(0), uint64(len), uint64(prot), uint64(1),
                       uint64(FD), uint64(off))
    end)
    if not ok then return -999 end
    return sgn(v)
end

-- ---------------------------------------------------------------- [A] descriptor
print("")
print("--- [A] open /dev/dmem0 ---")
do
    local path = "/dev/dmem0"
    local pb = memory.alloc(#path + 2)
    for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
    pcall(function() memory.write_byte(pb + #path, 0) end)
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then FD = sgn(v) end
end
print(string.format("  fd=%d %s", FD, FD < 0 and es() or ""))
if FD < 0 then print("=== PROBE 1503a VOID ===") return end

-- ---------------------------------------------------------------- [B] mincore over far page 0
local VEC = memory.alloc(0x800)
local function mincore(va, len)
    for i = 0, 0x7F do pcall(function() memory.write_byte(VEC + i, 0) end) end
    local ok, v = pcall(function()
        return mk(78)(uint64(va), uint64(len), uint64(VEC), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(v)
end

print("")
print("--- [B] mincore over phys 0 .. 0x40000 (64 pages) ---")
print("    known populated: page 0x00 (registers) and 0x0F-0x16 (the ONION block)")
local A = dmap(0, 0x40000, 1)
if A >= 0 then
    local rv = mincore(A, 0x40000)
    print(string.format("  va=0x%X mincore rv=%d %s", A, rv, rv < 0 and es() or ""))
    if rv == 0 then
        local res, line = 0, {}
        for i = 0, 63 do
            local b = N(memory.read_byte(VEC + i))
            if b % 2 == 1 then res = res + 1 end
            if i % 16 == 0 then line[#line + 1] = string.format("  %02X:", i) end
            line[#line + 1] = string.format(" %02X", b)
            if i % 16 == 15 then print(table.concat(line)); line = {} end
        end
        print(string.format("  resident pages: %d of 64", res))
        if res < 64 then
            print("  *** mincore DISCRIMINATES on the dmem pager - usable as a scan oracle ***")
        else
            print("  mincore reports every mapped page resident - NOT an oracle here")
        end
    end
end

-- ---------------------------------------------------------------- [C] pool slice
print("")
print("--- [C] mincore over phys 0x100000000 (pool start) for 8 MiB ---")
local B = dmap(0x100000000, 0x800000, 1)
if B >= 0 then
    local rv = mincore(B, 0x800000)
    print(string.format("  va=0x%X mincore rv=%d %s", B, rv, rv < 0 and es() or ""))
    if rv == 0 then
        local res = 0
        for i = 0, 511 do
            if N(memory.read_byte(VEC + i)) % 2 == 1 then res = res + 1 end
        end
        print(string.format("  resident pages: %d of 512", res))
    end
else
    print(string.format("  pool offset refused rv=%s %s", tostring(B), es()))
end

-- ---------------------------------------------------------------- [D] sanity read
print("")
print("--- [D] sanity read of phys 0 (known populated) ---")
if A >= 0 then
    print(string.format("  phys 0: %08X %08X %08X %08X", rd(A) or 0xDEAD, rd(A + 4) or 0xDEAD,
                        rd(A + 8) or 0xDEAD, rd(A + 12) or 0xDEAD))
    print("  (expect C0012800 80000000 80000000 C0001200)")
else
    print("  no mapping")
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1503a COMPLETE ===")
