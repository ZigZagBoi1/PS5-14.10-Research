-- CRASH_CLASS: MODERATE
-- PROBE 1412a: the read-only 64 GiB window - contents, extent, and whether prot 2 is accepted.
--
-- prior art:
--   results/phase36_realargs/1411a_dmem_range_check_20261109_153133.txt
--     low window ends between 0x110000000 and 0x120000000; offset 0x1000000000 maps with
--     prot=1 but the SAME offset with prot=3 answers EACCES(13) - the 64 GiB window is
--     granted read-only. A mapping that starts inside the low window and runs past its end
--     answers EACCES, so the driver checks offset+length, not just offset.
--   results/phase36_realargs/1410a_dmem_offset_space_20261109_153054.txt
--     the only 1 GiB rung above 4 GiB that maps is exactly 0x1000000000 (64 GiB).
--   results/phase36_realargs/1376e / 1397f: every mapped page outside offset 0 and the
--     0xF000 block reads zero.
--   docs/DMEM_WINDOW_14_10.md
--
-- Why 64 GiB matters: the aperture we own is [0, ~4.5 GiB) and it reads as our own
-- (zeroed) memory. A second window at exactly 2^36 that the ACL grants READ-ONLY is a
-- different object - if it is the GPU's own page tables or firmware region, reading it is a
-- disclosure, and mapping it with prot=2 (write-only, no read) would be a write primitive
-- into memory we are not allowed to see.
-- Order: safe maps first, the 4.5 GiB top bracket, then extent, then the reads last.

print("=== PROBE 1412a: THE 64 GiB WINDOW ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function wr(a, v) return pcall(function() memory.write_dword(a, v) end) end

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
local function mapit(off, prot, len, flags)
    return N(sc477(uint64(0), uint64(len or 0x1000), uint64(prot or 1), uint64(flags or 1), uint64(fd0), uint64(off)))
end
local function okmap(va) return va and va >= 0x10000 and va < 0x8000000000 end

print("")
print("[A] top of the low window, 0x110000000 .. 0x120000000 at 16 MiB")
local top = nil
for i = 17, 18 do
    for j = 0, 15 do
        local off = i * 0x10000000 + j * 0x1000000
        local va = mapit(off, 1, 0x1000)
        if okmap(va) then
            top = off
        else
            print(string.format("  first refused inside this 16 MiB run: off=0x%X %s", off, es()))
            break
        end
    end
end
print(string.format("  highest offset that maps = 0x%X", top or 0))

print("")
print("[B] extent of the 64 GiB window (map only, no reads)")
for _, d in ipairs({0x1000, 0x10000, 0x100000, 0x400000, 0x1000000, 0x4000000, 0x8000000}) do
    local va = mapit(0x1000000000 + d, 1, 0x1000)
    print(string.format("  base+0x%-9X %s", d, okmap(va) and ("MAP va=0x" .. string.format("%X", va)) or es()))
end
for _, len in ipairs({0x1000, 0x200000, 0x10000000}) do
    local va = mapit(0x1000000000, 1, len)
    print(string.format("  base len=0x%-9X %s", len, okmap(va) and ("MAP va=0x" .. string.format("%X", va)) or es()))
end

print("")
print("[C] protection variants at the 64 GiB base")
for _, prot in ipairs({0, 1, 2, 3, 5, 7, 0x13}) do
    local va = mapit(0x1000000000, prot, 0x1000)
    print(string.format("  prot=0x%-3X %s", prot, okmap(va) and ("MAP va=0x" .. string.format("%X", va)) or es()))
end
print("  MAP_PRIVATE (flags=2), prot=1:")
local vp = mapit(0x1000000000, 1, 0x1000, 2)
print(string.format("    %s", okmap(vp) and ("MAP va=0x" .. string.format("%X", vp)) or es()))

print("")
print("[D] contents of the 64 GiB page (reads last, each pre-printed)")
local va = mapit(0x1000000000, 1, 0x1000)
if okmap(va) then
    print(string.format("  mapped at 0x%X", va))
    local nz = 0
    for i = 0, 255 do
        print(string.format("  reading +0x%X", i * 4))
        local v = rd(va + i * 4)
        if v ~= nil and v ~= 0 then
            nz = nz + 1
            print(string.format("    +0x%03X = %s", i * 4, hex4(v)))
        end
    end
    print(string.format("  non-zero dwords in the first 1 KiB: %d", nz))
else
    print(string.format("  base no longer maps: %s", es()))
end

print("")
print("=== 1412a DONE ===")
