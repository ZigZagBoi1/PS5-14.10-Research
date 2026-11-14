-- CRASH_CLASS: MODERATE
-- PROBE 1411a: does /dev/dmem0 validate the whole offset range, or only its start?
--
-- prior art:
--   results/phase36_realargs/1410a_dmem_offset_space_20261109_153054.txt
--     1 GiB ladder 0..0x2000000000 (512 rungs): only 0, 0x40000000, 0x80000000,
--     0xC0000000, 0x100000000 and 0x1000000000 map; first refusal at 0x140000000 (EACCES).
--     256 MiB ladder 0..0x100000000: all 17 rungs map. Every mapped rung reads zero
--     except offset 0 (GPU register block).
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt
--     0x100000000 maps, 0x200000000 EACCES; single mappings up to len 0x80000000 succeed.
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt
--     two descriptors share one backing store; a store lands and is visible twice.
--   results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt
--     a store into a prot=1 mapping faults (killed the process).
--   docs/DMEM_WINDOW_14_10.md
--
-- Shape of the accepted set: [0, 0x140000000) contiguous, then nothing until a single rung
-- at 0x1000000000. Two questions follow.
--   (1) Is the window bound checked against offset+length, or against offset alone? If only
--       the start is checked, a mapping that STARTS inside the window but runs past its end
--       installs pages the caller is not entitled to - the classic ACL off-by-one.
--   (2) Is it really a window, or is the 64 GiB rung the base of a second region? Sweep its
--       neighbourhood at 64 MiB.
-- Order: safe maps first, the boundary-crossing reads last, each read pre-printed.

print("=== PROBE 1411a: DMEM RANGE CHECK ===")

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
local function mapit(off, prot, len)
    return N(sc477(uint64(0), uint64(len or 0x1000), uint64(prot or 1), uint64(1), uint64(fd0), uint64(off)))
end
local function okmap(va) return va and va >= 0x10000 and va < 0x8000000000 end

print("")
print("[A] exact end of the low window, 0x100000000 .. 0x180000000 at 256 MiB")
local edge = nil
for i = 16, 24 do
    local off = i * 0x10000000
    local va = mapit(off, 1, 0x1000)
    local tag = okmap(va) and "MAP" or es()
    print(string.format("  off=0x%-12X %s", off, tag))
    if not okmap(va) and not edge then edge = off end
end
print(string.format("  first refused = 0x%X", edge or 0))

print("")
print("[B] the 64 GiB rung neighbourhood, 64 MiB steps around 0x1000000000")
for i = -2, 4 do
    local off = 0x1000000000 + i * 0x4000000
    local va = mapit(off, 1, 0x1000)
    print(string.format("  off=0x%-14X %s", off, okmap(va) and "MAP" or es()))
end

print("")
print("[C] 64 GiB region: how much can one mapping cover, and is it writable")
for _, len in ipairs({0x1000, 0x40000000, 0x40000000 * 4}) do
    local va = mapit(0x1000000000, 3, len)
    if okmap(va) then
        print(string.format("  len=0x%-10X map=0x%X", len, va))
        wr(va, 0x41424344)
        print(string.format("    write+read [0] = %s", hex4(rd(va))))
        print(string.format("    reading [0x1000] at 0x%X", va + 0x1000))
        print(string.format("    [0x1000]=%s", hex4(rd(va + 0x1000))))
    else
        print(string.format("  len=0x%-10X %s", len, es()))
    end
end

print("")
print("[D] cross the low-window end with one mapping that STARTS inside it")
print("    (a page installed past the window end would be an ACL escape)")
for _, len in ipairs({0x140000000, 0x180000000, 0x200000000}) do
    local va = mapit(0, 3, len)
    if okmap(va) then
        print(string.format("  off=0 len=0x%-10X map=0x%X  covers 0..0x%X", len, va, len))
        print(string.format("    first dword after the window end, about to read 0x%X", va + 0x140000000))
        print(string.format("    [0x140000000]=%s", hex4(rd(va + 0x140000000))))
    else
        print(string.format("  off=0 len=0x%-10X %s", len, es()))
    end
end

print("")
print("[E] start inside the window and let the length run past the top into 64 GiB")
for _, spec in ipairs({{0x100000000, 0x40000000}, {0x100000000, 0x1000000000}, {0x13F000000, 0x2000000}}) do
    local off, len = spec[1], spec[2]
    local va = mapit(off, 1, len)
    if okmap(va) then
        print(string.format("  off=0x%X len=0x%X map=0x%X", off, len, va))
        local far = va + len - 0x1000
        print(string.format("    about to read the last page 0x%X", far))
        print(string.format("    [last]=%s", hex4(rd(far))))
    else
        print(string.format("  off=0x%X len=0x%X %s", off, len, es()))
    end
end

print("")
print("=== 1411a DONE ===")
