-- CRASH_CLASS: MODERATE
-- PROBE 1442a: is the GPU MMIO register aperture mappable through /dev/dmem0?
--
-- The dmem offset is used as a GPU physical address with no translation
-- (scout DmemDriver, docs/DMEM_WINDOW_14_10.md), and the throughput of the whole
-- window is 0..0x110000000 plus a small read-only window at 64 GiB.  Page 0 of
-- the window holds GPU *addresses*, not register values: the first dwords are
-- 80000000C0012800 and 80000000C0001200, i.e. pointers into the GPU's 0x8000_0000
-- aperture - and 0xC0012800 is the RDNA2 register block base this project already
-- identified from the GPU side (probes/phase22_threaded_races/116a).
--
-- 1410a mapped 1 GiB rungs and found everything above offset 0 zero, which would
-- be expected if the aperture is not a flat identity map at those rungs but *is*
-- present at the specific 64 KB window the firmware uses.  This probe therefore
-- walks a fine ladder around both candidate bases (0x80000000 and 0xC0000000)
-- at page granularity, maps each page read-only, and dumps the first 16 dwords.
--
-- Read-only: no store is attempted anywhere.  A hang here would come from reading
-- a register that blocks, so each page prints its offset before the read.
--
-- Prior art:
--   1410a  results/phase36_realargs/1410a_dmem_offset_space_20261109_153054.txt
--   116a   probes/phase22_threaded_races/116a_gpu_register_map.lua
--   1397g  results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1442a: DMEM MMIO APERTURE SWEEP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(p)
    local ok, v = pcall(function() return to_num(memory.read_dword(p)) end)
    if ok then return v end
    return nil
end
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local m5, m477, m73 = sc(5), sc(477), sc(73)
local fd = to_num(m5(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0)))
print(string.format("open(/dev/dmem0) -> %d", fd))

local function mmap(off, prot)
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(0x1000), uint64(prot or 1), uint64(1),
            uint64(fd), uint64(off))
    end)
    if not ok then return nil, "EXC" end
    local v = to_num(r)
    if v < 0x10000 or v > 0x8000000000 then return nil, es() end
    return v
end

local function page(off)
    local va, e = mmap(off, 1)
    if not va then
        print(string.format("  %#010x -> FAILED (%s)", off, tostring(e)))
        return
    end
    local t = {}
    for i = 0, 15 do
        t[i + 1] = string.format("%08X", rd(va + i * 4) or 0)
    end
    local nonzero = 0
    for i = 1, 16 do
        if t[i] ~= "00000000" then nonzero = nonzero + 1 end
    end
    print(string.format("  %#010x -> %#x  nz=%2d  %s", off, va, nonzero,
        table.concat(t, " ")))
    pcall(function() m73(uint64(va), uint64(0x1000)) end)
end

print("[A] around 0xC0000000 (the register block base named by page 0)")
for _, off in ipairs({
    0xC0000000, 0xC0001000, 0xC0002000, 0xC0008000, 0xC000F000,
    0xC0010000, 0xC0011000, 0xC0012000, 0xC0013000, 0xC0018000,
    0xC0020000, 0xC0040000, 0xC0080000, 0xC0100000,
}) do page(off) end
print("")

print("[B] around 0x80000000")
for _, off in ipairs({
    0x80000000, 0x80001000, 0x80010000, 0x80080000, 0x80100000,
    0x800000000, 0x800001000, 0x800100000,
}) do page(off) end
print("")

print("[C] the exact addresses page 0 points at, page-aligned")
for _, off in ipairs({
    0xC0012000, 0xC0001000, 0xC0055000, 0xC0055800,
}) do page(off) end
print("")

print("[D] control: offset 0 and 0x10000000")
page(0x0)
page(0x10000000)
print("")

print("=== PROBE 1442a COMPLETE ===")
