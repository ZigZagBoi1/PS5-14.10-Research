-- CRASH_CLASS: LOW
-- PROBE 532g: Read /dev/gc MMIO page and explore structure
--
-- 532f: /dev/gc mmap(off=0, MAP_SHARED) gives 16KB, first dword=0xFFFFFFFF.
-- This is likely GPU MMIO (memory-mapped I/O registers).
-- Read the full 16KB and look for non-0xFFFFFFFF values.
-- Also try: larger mmap sizes, different page alignments.

print("=== PROBE 532g: GC MMIO READ ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)

-- Open /dev/gc
local devpath = memory.alloc(32)
zero(devpath, 32)
wd(devpath + 0, 0x7665642F)   -- /dev
wd(devpath + 4, 0x00636700 + 0x2F)  -- /gc\0
-- Actually: "/dev/gc" = 2F 64 65 76 2F 67 63 00
-- dword[0] = 0x7665642F  ("/dev")
-- dword[1] = 0x0063672F  ("/gc\0")
zero(devpath, 32)
wd(devpath + 0, 0x7665642F)  -- /dev
wd(devpath + 4, 0x0063672F)  -- /gc\0

local ok_o, gc_fd = pcall(function()
    return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
end)
print("gc_fd=" .. q(gc_fd))

-- Try different mmap sizes
print("")
print("[1] Size tests")
local sizes = { 0x4000, 0x8000, 0x10000, 0x40000, 0x100000 }
for _, sz in ipairs(sizes) do
    local ok_m, va = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(3),
            uint64(1), gc_fd, uint64(0))
    end)
    local van = to_num(va)
    if van < 0 then van = van + 0x100000000 end
    local vah = 0
    if type(va) == "table" and va.h then vah = va.h; if vah < 0 then vah = vah + 0x100000000 end end
    if ok_m and vah ~= 0xFFFFFFFF and van ~= 0 then
        print(string.format("  size=0x%X → OK (%s)", sz, q(va)))
        pcall(function() sc_munmap(va, uint64(sz)) end)
    else
        print(string.format("  size=0x%X → FAIL", sz))
    end
end

-- Map 16KB and dump interesting dwords
print("")
print("[2] MMIO dump (16KB)")
local ok_m, mmio = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), gc_fd, uint64(0))
end)
print("mmio=" .. q(mmio))

local mmio_n = to_num(mmio)
if mmio_n < 0 then mmio_n = mmio_n + 0x100000000 end

-- Count non-FFFFFFFF and non-zero values
local interesting = 0
local ff_count = 0
local zero_count = 0
local sample_addrs = {}

for off = 0, 0x3FFC, 4 do
    local v = rd(mmio_n + off)
    if v then
        if v < 0 then v = v + 0x100000000 end
        if v == 0xFFFFFFFF then
            ff_count = ff_count + 1
        elseif v == 0 then
            zero_count = zero_count + 1
        else
            interesting = interesting + 1
            if #sample_addrs < 32 then
                table.insert(sample_addrs, { off = off, val = v })
            end
        end
    end
end

print(string.format("  0xFFFFFFFF: %d dwords", ff_count))
print(string.format("  0x00000000: %d dwords", zero_count))
print(string.format("  other:      %d dwords", interesting))

if #sample_addrs > 0 then
    print("")
    print("  Interesting values:")
    for _, s in ipairs(sample_addrs) do
        print(string.format("    [+0x%04X] = 0x%08X", s.off, s.val))
    end
end

-- [3] Try to read MMIO and identify AMD GPU registers
-- On AMD GPUs:
-- 0x000-0x3FF: General BIF (bus interface)
-- 0x2000-0x2FFF: GFX
-- 0x3000-0x3FFF: Display
-- The mapping might be MMIO BAR0 of the GPU
print("")
print("[3] Known AMD register offsets")
local known_regs = {
    { off = 0x00, name = "BIF_BX0" },
    { off = 0x08, name = "BIF_BX0+8" },
    { off = 0x50, name = "GRBM_STATUS" },
    { off = 0x54, name = "GRBM_STATUS2" },
    { off = 0xA0, name = "CP_STAT" },
    { off = 0xFC, name = "CP_ME_CNTL" },
    { off = 0x0200, name = "SDMA0_STATUS" },
    { off = 0x0400, name = "MM_INDEX" },
    { off = 0x0404, name = "MM_DATA" },
}
for _, r in ipairs(known_regs) do
    if r.off < 0x4000 then
        local v = rd(mmio_n + r.off)
        if v then
            if v < 0 then v = v + 0x100000000 end
            print(string.format("  [+0x%04X] %-16s = 0x%08X", r.off, r.name, v))
        end
    end
end

-- [4] Write test: can we write to this MMIO region?
print("")
print("[4] Write test")
local test_off = 0x100
local orig = rd(mmio_n + test_off)
if orig then
    if orig < 0 then orig = orig + 0x100000000 end
    print(string.format("  [+0x%04X] before = 0x%08X", test_off, orig))
    local ok_w = pcall(function() memory.write_dword(mmio + uint64(test_off), 0x12345678) end)
    local after = rd(mmio_n + test_off)
    if after then
        if after < 0 then after = after + 0x100000000 end
        print(string.format("  [+0x%04X] after  = 0x%08X (wrote 0x12345678, ok=%s)",
            test_off, after, tostring(ok_w)))
        if after ~= orig then
            print("  *** MMIO WRITE WORKS ***")
            -- Restore
            pcall(function() memory.write_dword(mmio + uint64(test_off), orig) end)
        else
            print("  (write had no effect or register is read-only)")
        end
    end
end

print("")
print("=== 532g DONE ===")
