-- CRASH_CLASS: MODERATE
-- PROBE 1410a: the /dev/dmem0 offset space - which GPU addresses map and what is there.
--
-- prior art:
--   results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152941.txt
--     off 0x100000000 maps, 0x200000000 EACCES, 0x400000000 EACCES,
--     0x1000000000 (64 GiB) MAPS and reads zero, 0x10000000000 EACCES.
--     So the refusal is not a simple ceiling: two far offsets are refused while a farther
--     one is accepted. 637(0, 0xFFFFFFFFFFFFF000) answers EINVAL, so the physical-memory
--     limit is not the thing being clamped and 637 does not open the window.
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt
--     offsets 0..0x100000000 map with prot 1 and 3; above 0x200000000 -> EACCES.
--   results/phase36_realargs/1397k_dmem_record_steer_20261109_143442.txt
--     page 0 +0x800 holds 48 records of stride 0x14, all (C0038000, E0000C00, F, 0x100, N)
--     with N = index*0x400; rewriting a record's address does not steer the mapping.
--   docs/DMEM_WINDOW_14_10.md
--
-- Question: is the accepted set a per-container chunk list (in which case an offset inside
-- another container's chunk would expose someone else's GPU memory) or a bit pattern test
-- on the offset? The pattern decides which.
--
-- Method: 1 GiB ladder from 0 to 0x2000000000 (512 GiB), mapping 0x1000 bytes prot=1 at
-- each rung and recording map-or-errno, WITHOUT reading. Then a 256 MiB ladder over the
-- first 4 GiB. Reads happen last, ascending, each preceded by its own print.

print("=== PROBE 1410a: DMEM OFFSET SPACE ===")

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

local sc477 = mk(477)
local function mapit(off, prot, len)
    return N(sc477(uint64(0), uint64(len or 0x1000), uint64(prot or 1), uint64(1), uint64(fd0), uint64(off)))
end
local function okmap(va) return va and va >= 0x10000 and va < 0x8000000000 end

print("")
print("[A] 1 GiB ladder, 0 .. 0x2000000000 (map only, no reads)")
local good = {}
local bad = 0
local line = ""
local first_err = nil
for i = 0, 512 do
    local off = i * 0x40000000
    local va = mapit(off, 1, 0x1000)
    if okmap(va) then
        line = line .. "o"
        good[#good + 1] = {off = off, va = va}
    else
        line = line .. "."
        bad = bad + 1
        if not first_err then first_err = {off = off, e = es()} end
    end
    if (#line == 64) then print(string.format("  %10X: %s", off - 63 * 0x40000000, line)) line = "" end
end
if #line > 0 then print(string.format("  (tail): %s", line)) end
print(string.format("  mapped=%d refused=%d  first refusal at off=0x%X errno=%s",
    #good, bad, first_err and first_err.off or 0, first_err and first_err.e or "-"))

print("")
print("[B] the mapped offsets")
for _, g in ipairs(good) do
    print(string.format("  off=0x%-14X va=0x%X", g.off, g.va))
end

print("")
print("[C] 256 MiB ladder over the first 4 GiB (map only)")
local line2 = ""
for i = 0, 16 do
    local off = i * 0x10000000
    local va = mapit(off, 1, 0x1000)
    if okmap(va) then line2 = line2 .. "o" else line2 = line2 .. "." end
end
print("  0..4GiB @256MiB: " .. line2)

print("")
print("[D] contents of the mapped offsets, ascending, each read pre-printed")
for _, g in ipairs(good) do
    print(string.format("  reading off=0x%X at 0x%X", g.off, g.va))
    print(string.format("    [0]=%s [4]=%s [8]=%s", hex4(rd(g.va)), hex4(rd(g.va + 4)), hex4(rd(g.va + 8))))
end

print("")
print("=== 1410a DONE ===")
