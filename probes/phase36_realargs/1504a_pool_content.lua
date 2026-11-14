-- CRASH_CLASS: LOW -- reads only, and only pages mincore has first reported resident.
-- PROBE 1504a: what is actually in the direct-memory pool inside the aperture?
--
-- RETRACTED 2026-11-10: 1503a did NOT prove mincore discriminates residency here. Its 0x40000
-- request writes only 16 bytes (0x40000 / 0x4000, the 16 KiB kernel page size) and all 16 read 0x0B
-- resident; the 0x00 above index 15 was never written by the kernel. mincore reports EVERY mapped
-- page resident on this pager, so it cannot classify holes. See row 1503a-correction in
-- results/INDEX.md and 1544a for the page size. What follows therefore reads only what it reads. That unlocks the one region that matters: the aperture tops out at
-- 0x11FFF0000 and the GPU direct-memory pool starts at 0x100000000, so the first 0x1FFF0000
-- (511.9 MiB) of the pool is CPU-mappable read-only. If the GPU's page tables are allocated out
-- of that pool, this is the only place a userland process could ever see them, and rewriting one
-- would let the GPU address physical memory.
--
-- This probe answers the cheap half: is there ANY content there. It scans 16 MiB from the pool
-- base page by page and reports
--   - which pages mincore calls resident,
--   - which resident pages are dense (nonzero byte count), with their first dwords,
--   - every occurrence of the 4-byte run 01 00 00 00, which in a little-endian qword means the
--     value has bits 32..63 == 0x00000001 - the signature of a PTE whose physical address lies in
--     0x100000000..0x1FFFFFFFF, i.e. a page-table entry pointing into this very pool.
--
-- -- prior art:
--   results/phase36_realargs/1503a_mincore_aperture_20261109_221835.txt (the residency oracle)
--   results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt (device windows: no kernel values)
--   results/phase36_realargs/1486a_gpu_pool_scan_20261109_203940.txt (pool mostly empty via 674 + 548)
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt (12 of 256 pages backed in the first 1 MiB)

print("=== PROBE 1504a: POOL CONTENT INSIDE THE APERTURE ===")

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
        return mk(477)(uint64(0), uint64(len), uint64(prot), uint64(1), uint64(FD), uint64(off))
    end)
    if not ok then return -999 end
    return sgn(v)
end

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
if FD < 0 then print("=== PROBE 1504a VOID ===") return end

local VEC = memory.alloc(0x2000)
local function mincore(va, len)
    for i = 0, 0x1FFF do pcall(function() memory.write_byte(VEC + i, 0) end) end
    local ok, v = pcall(function()
        return mk(78)(uint64(va), uint64(len), uint64(VEC), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(v)
end

-- ---------------------------------------------------------------- [B] map 16 MiB of pool
local POOL_OFF = 0x100000000
local POOL_LEN = 0x1000000
print("")
print(string.format("--- [B] map pool 0x%X .. 0x%X, prot 1 ---", POOL_OFF, POOL_OFF + POOL_LEN))
local base = dmap(POOL_OFF, POOL_LEN, 1)
if base < 0 then
    print(string.format("  refused rv=%s %s", tostring(base), es()))
    print("=== PROBE 1504a INCOMPLETE ===")
    return
end
print(string.format("  va=0x%X", base))

-- CORRECTED: the span is 0x1000000 / 0x4000 = 1024 pages, so mincore writes 1024 bytes.
local rv = mincore(base, POOL_LEN)
local resident = {}
local nres = 0
if rv == 0 then
    for i = 0, 4095 do
        if N(memory.read_byte(VEC + i)) % 2 == 1 then nres = nres + 1; resident[i] = true end
    end
    print(string.format("  resident: %d of 4096 pages", nres))
else
    print(string.format("  mincore rv=%d %s - falling back to no residency map", rv, es()))
end

-- ---------------------------------------------------------------- [C] density + PTE signature
print("")
print("--- [C] per-page density and physical-pointer scan ---")
local dense, hits = {}, 0
local REPORT = 0
local skipped = 0
for p = 0, 4095 do
    local va = base + p * 0x1000
    if rv == 0 and not resident[p] then
        skipped = skipped + 1
    else
    local okr, buf = pcall(function() return memory.read_buffer(va, 0x1000) end)
    if okr and type(buf) == "string" and #buf == 0x1000 then
        local nz = 0x1000 - select(2, buf:gsub("%z", ""))
        if nz > 512 then
            dense[#dense + 1] = { p = p, nz = nz }
            if REPORT < 12 then
                REPORT = REPORT + 1
                print(string.format("  dense page phys 0x%X nz=%d", POOL_OFF + p * 0x1000, nz))
                print(string.format("    %08X %08X %08X %08X %08X %08X %08X %08X",
                    rd(va), rd(va + 4), rd(va + 8), rd(va + 12),
                    rd(va + 16), rd(va + 20), rd(va + 24), rd(va + 28)))
            end
        end
        -- qwords whose bits 32..63 are exactly 0x00000001
        local i = 1
        while true do
            local s = buf:find("\1\0\0\0", i, true)
            if not s then break end
            -- the qword is aligned; report the containing qword if the run starts at its +4 byte
            if s % 8 == 5 then
                hits = hits + 1
                if hits <= 16 then
                    local off = (s - 5) / 8 * 8
                    local q = rd(va + off)
                    print(string.format("  POOL-PTR phys 0x%X dword=%08X",
                        POOL_OFF + p * 0x1000 + off, q or 0xDEAD))
                end
            end
            i = s + 1
        end
    end
    end
end
print(string.format("  non-resident pages skipped: %d", skipped))
print(string.format("  dense pages (>512 nonzero bytes): %d of the resident set", #dense))
print(string.format("  qwords with bits 32..63 == 1: %d", hits))

-- ---------------------------------------------------------------- [D] residency of the rest
print("")
print("--- [D] is the rest of the aperture-resident pool backed too? ---")
for _, off in ipairs({0x110000000, 0x118000000, 0x11F000000}) do
    local va = dmap(off, 0x800000, 1)
    if va >= 0 then
        local r2 = mincore(va, 0x800000)
        local c = 0
        if r2 == 0 then
            for i = 0, 511 do if N(memory.read_byte(VEC + i)) % 2 == 1 then c = c + 1 end end
        end
        print(string.format("  off 0x%X -> 0x%X mincore rv=%d resident %d/512", off, va, r2, c))
    else
        print(string.format("  off 0x%X -> rv=%s %s", off, tostring(va), es()))
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1504a COMPLETE ===")
