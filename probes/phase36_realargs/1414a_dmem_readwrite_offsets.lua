-- CRASH_CLASS: HIGH
-- PROBE 1414a: /dev/dmem0 read/pread and write/pwrite at offsets the mmap ACL refuses.
--
-- prior art:
--   results/phase36_realargs/1411a_dmem_range_check_20261109_153133.txt
--     d_mmap checks offset+length: a mapping starting inside the low window and running past
--     its end answers EACCES, and the 64 GiB window is granted read-only (prot 1/0 only).
--   results/phase36_realargs/1412a_dmem_64g_window_20261109_153207.txt
--     aperture [0, ~0x110000000) RW; 0x1000000000 maps read-only; content mostly zero.
--   results/phase36_realargs/1413a_dmem_ioctl_acl_20261109_153304.txt
--     every dmem ioctl in the 0x80 group returns EPERM(1); no /dev/dmem/cntN nodes exist.
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt
--     mmap of offset 0x1000 is writable and aliases through /dev/dmem1.
--   results/phase17_new_vectors/278a_node_ioctl_sweep.lua - ioctl only; no probe in this tree
--     has ever called read()/write()/pread()/pwrite() on a dmem descriptor.
--   docs/DEVICE_IOCTL_14_10.md, docs/DMEM_WINDOW_14_10.md
--
-- Hypothesis: the window bounds and the read-only grant at 64 GiB live in the driver's
-- d_mmap handler. d_read and d_write are different entry points and may resolve the offset
-- through a common helper WITHOUT the ACL - a very ordinary shape of bug in a device driver,
-- and one no sweep has touched. If pwrite accepts an offset that mmap refuses, the node is an
-- arbitrary GPU-memory writer, and if pread accepts one, an arbitrary GPU-memory reader.
--
-- Order: reads first, then a write at a known-good offset, then the ACL-refused offsets.
-- A write past the ACL is the interesting case and the last thing this probe does.

print("=== PROBE 1414a: DMEM READ/WRITE OFFSETS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function wr(a, v) return pcall(function() memory.write_dword(a, v) end) end

print(string.format("[0] pid=%d", sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local sc_open, sc_close = mk(5), mk(6)
local sc_pread, sc_pwrite, sc_lseek, sc_read, sc_write = mk(475), mk(476), mk(478), mk(3), mk(4)

local fd = sg(sc_open(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] open(/dev/dmem0, O_RDWR)=%d", fd))

local buf = memory.alloc(0x1000)
local function fill(v) for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(buf + off, v) end) end end
local function dump(n)
    local parts = {}
    for i = 0, math.min(n or 8, 16) - 1 do parts[#parts + 1] = hex4(rd(buf + i * 4)) end
    return table.concat(parts, " ")
end

if fd >= 0 then
    print("")
    print("[A] pread(fd, buf, 0x40, offset) - does d_read resolve the same offset space")
    for _, off in ipairs({0, 0x1000, 0xF000, 0x110000000, 0x120000000, 0x1000000000, 0x200000000}) do
        fill(0xDEADBEEF)
        local rv = sg(sc_pread(uint64(fd), uint64(buf), uint64(0x40), uint64(off), uint64(0), uint64(0)))
        print(string.format("  off=0x%-12X rv=%d errno=%s  %s", off, rv, es(), dump(8)))
    end

    print("")
    print("[B] lseek + read, in case d_read uses the descriptor offset and d_pread is separate")
    for _, off in ipairs({0, 0x1000, 0x120000000}) do
        local s = sg(sc_lseek(uint64(fd), uint64(off), uint64(0)))
        fill(0xDEADBEEF)
        local rv = sg(sc_read(uint64(fd), uint64(buf), uint64(0x40), uint64(0), uint64(0), uint64(0)))
        print(string.format("  lseek=0x%-12X -> %d  read rv=%d errno=%s  %s", off, s, rv, es(), dump(4)))
    end

    print("")
    print("[C] pwrite of a marker at offset 0x1000 (in the allowed window), verified by mmap")
    wr(buf, 0x52535455)
    local wv = sg(sc_pwrite(uint64(fd), uint64(buf), uint64(0x10), uint64(0x1000), uint64(0), uint64(0)))
    print(string.format("  pwrite rv=%d errno=%s", wv, es()))
    local sc477 = mk(477)
    local va = N(sc477(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd), uint64(0x1000)))
    if va >= 0x10000 and va < 0x8000000000 then
        print(string.format("  mmap view [0]=%s (expected 52535455)", hex4(rd(va))))
    else
        print(string.format("  mmap refused: %s", es()))
    end

    print("")
    print("[D] pwrite at offsets the mmap ACL refuses - the ACL-bypass test")
    for _, off in ipairs({0x120000000, 0x200000000, 0x1000000000, 0x10000000000}) do
        fill(0x0)
        wr(buf, 0x4B4F4E55)
        local rv = sg(sc_pwrite(uint64(fd), uint64(buf), uint64(0x10), uint64(off), uint64(0), uint64(0)))
        print(string.format("  pwrite off=0x%-13X rv=%d errno=%s", off, rv, es()))
        local va2 = N(sc477(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd), uint64(off)))
        if va2 >= 0x10000 and va2 < 0x8000000000 then
            print(string.format("    mmap view [0]=%s", hex4(rd(va2))))
        else
            print(string.format("    mmap of the same offset refused: %s", es()))
        end
    end

    pcall(function() sc_close(uint64(fd)) end)
end

print("")
print("=== 1414a DONE ===")
