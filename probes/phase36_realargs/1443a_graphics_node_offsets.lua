-- CRASH_CLASS: MODERATE
-- PROBE 1443a: the offset space of the graphics nodes, with the correct mmap shape
--
-- 1395a swept /dev/gc offsets with flags=0x1002 and MAP_ANON-style arguments and
-- concluded "gc maps offsets 0 and 0x1000 only, larger offsets EINVAL".  That same
-- probe measured /dev/dmem0 as "offset 0 and 0x1000 only, 0x10000000 EINVAL",
-- which 1397b later disproved completely: dmem maps its whole 4 GiB space with
-- flags=1 (MAP_SHARED) and the fd in arg5.  So the gc result came from the wrong
-- shape and has never been re-measured.
--
-- /dev/gc is the AMD graphics node.  If its d_mmap exposes the BAR or the MMIO
-- aperture at any offset, a mapping returns register values instead of zeros -
-- and a writable mapping there is direct GPU control without the driver.
--
-- Read-only: prot 1, no stores.  Every offset prints before the read.
--
-- Prior art:
--   1395a  results/phase36_realargs/1395a_dev_mmap_offset_wrap_20261109_141742.txt
--   1397b  results/phase36_realargs/1397b_dmem_offset_ladder_20261109_142645.txt
--   docs/DMEM_WINDOW_14_10.md
--   docs/DEVICE_IOCTL_14_10.md

print("=== PROBE 1443a: GRAPHICS NODE OFFSET SPACE ===")
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

local OFFS = {
    0x0, 0x1000, 0x10000, 0x100000, 0x1000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0xC0000000, 0xC0013000, 0xC0100000, 0xC1000000,
    0x100000000, 0x1001000000,
}

local function sweep(path, prot)
    local fd = to_num(m5(uint64(str_addr(path)), uint64(0x4002), uint64(0)))
    print(string.format("--- %s open -> %d  prot=%d", path, fd, prot))
    if fd < 0 then return end
    for _, off in ipairs(OFFS) do
        local ok, r = pcall(function()
            return m477(uint64(0), uint64(0x1000), uint64(prot), uint64(1),
                uint64(fd), uint64(off))
        end)
        local va = nil
        if ok then
            local v = to_num(r)
            if v >= 0x10000 and v <= 0x8000000000 then va = v end
        end
        if not va then
            print(string.format("  %#012x -> FAILED (%s)", off, es()))
        else
            local t, nz = {}, 0
            for i = 0, 7 do
                local d = rd(va + i * 4)
                t[i + 1] = string.format("%08X", d or 0)
                if d and d ~= 0 then nz = nz + 1 end
            end
            print(string.format("  %#012x -> %#x nz=%d  %s", off, va, nz, table.concat(t, " ")))
            pcall(function() m73(uint64(va), uint64(0x1000)) end)
        end
    end
    pcall(function() m5(uint64(fd)) end)
end

sweep("/dev/gc", 1)
sweep("/dev/gc", 3)
sweep("/dev/dce", 1)
sweep("/dev/ajm", 1)

print("")
print("=== PROBE 1443a COMPLETE ===")
