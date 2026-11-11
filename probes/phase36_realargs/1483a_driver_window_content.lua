-- CRASH_CLASS: LOW -- reads only, and only from mappings 1480c already moved to prot 3. Every
-- read is guarded; a fault leaves the region marked VOID instead of taking the process down.
-- PROBE 1483a: what is actually in the driver windows
--
-- 1480c moved 19 device windows to prot 3 and 1481b proved they are writable. 1481a and 1481c
-- only looked at the first few bytes of each, and the "full" read of 1481c covered the eleven
-- names guessed in advance. The register aperture SceGnmDriver is 64 KiB and only four dwords were
-- ever looked at; SceGnmDumpArea is 1 MiB and has never been read at all.
--
-- This dumps the non-zero content of the windows that hold data, and samples the large ones, so
-- the next experiment can be aimed at a structure instead of a name.
--
-- [A] SceGnmDriver  0xFE0000000, 64 KiB  - every non-zero dword with its offset
-- [B] SceGnmTrapCode 0xF00000000, 16 KiB - every non-zero dword, to see the shader body
-- [C] SceGnmDumpArea 0xFE0300000, 1 MiB  - non-zero dword count and the first 32
-- [D] the two eboot.bin windows and SceGnmDingDong, non-zero counts only
-- [E] SceKernelInternalMemory 0x880AD0000, 16 MiB - sampled every 64 KiB, non-zero where
--
-- -- prior art:
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (the 19 windows)
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (first 16 bytes each)
--   results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt (bulk read, 11 names)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the extents)

print("=== PROBE 1483a: DRIVER WINDOW CONTENT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local ent = memory.alloc(0x40)
local cnt = memory.alloc(0x10)

local function protect(addr, len)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(3)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    if not ok then return -999 end
    return N(rv)
end

local function rd(a)
    local v = nil
    pcall(function() v = N(memory.read_dword(a)) end)
    return v
end

local function dump_nonzero(label, base, size, cap)
    print("")
    print(string.format("--- %s 0x%X len 0x%X ---", label, base, size))
    local nz, shown, failed = 0, 0, 0
    for off = 0, size - 4, 4 do
        local v = rd(base + off)
        if v == nil then
            failed = failed + 1
        elseif v ~= 0 then
            nz = nz + 1
            if shown < cap then
                print(string.format("    +0x%-6X %08X", off, v))
                shown = shown + 1
            end
        end
    end
    print(string.format("    non-zero %d of %d dwords, unreadable %d, shown %d",
        nz, size / 4, failed, shown))
    return nz
end

-- ---------------------------------------------------------------- [A] register aperture
local a = protect(0xFE0000000, 0x10000)
print(string.format("[A] protect SceGnmDriver -> rv=%s", tostring(a)))
dump_nonzero("[A] SceGnmDriver", 0xFE0000000, 0x10000, 200)

-- ---------------------------------------------------------------- [B] shader body
dump_nonzero("[B] SceGnmTrapCode", 0xF00000000, 0x4000, 64)
dump_nonzero("[B] SceGnmTrapData", 0xF00004000, 0x4000, 40)

-- ---------------------------------------------------------------- [C] dump area
dump_nonzero("[C] SceGnmDumpArea", 0xFE0300000, 0x100000, 32)

-- ---------------------------------------------------------------- [D] the zeros, counted
print("")
print("--- [D] windows expected to be empty ---")
dump_nonzero("[D] eboot.bin 0xF0000000", 0xF0000000, 0x4000, 4)
dump_nonzero("[D] SceGnmDingDong", 0xFE0200000, 0x4000, 4)
dump_nonzero("[D] SceGnmMisc", 0xF01144000, 0x4000, 4)

-- ---------------------------------------------------------------- [E] kernel internal memory
print("")
print("--- [E] SceKernelInternalMemory sampled every 64 KiB ---")
local nzr = 0
for off = 0, 0x1000000 - 0x10000, 0x10000 do
    local v = rd(0x880AD0000 + off)
    if v and v ~= 0 then
        nzr = nzr + 1
        if nzr <= 16 then
            print(string.format("    +0x%-7X %08X", off, v))
        end
    end
end
print(string.format("[E] %d of 256 samples non-zero", nzr))

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1483a COMPLETE ===")
