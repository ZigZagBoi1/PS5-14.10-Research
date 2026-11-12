-- CRASH_CLASS: MODERATE -- writes go only into the 0x1000-offset pages of /dev/dmem0 and
-- /dev/gc, which read as all-zero and all-FF.  The GPU register block at /dev/dmem0 offset 0
-- is READ ONLY in this probe: a stray store into GPU MMIO is what hangs a console.
-- PROBE 1396b: are the device mappings a game process can read also writable?
--
-- 1395a established that /dev/dmem0 and /dev/dmem1 map at offsets 0 and 0x1000, and that the
-- offset-0 page of dmem0 reads the GPU register block (0x80000000C0012800 and friends) while the
-- offset-0x1000 page reads all zeros.  /dev/gc maps the same two offsets and reads 0xFFFFFFFF
-- everywhere.  Every earlier note in this tree said reading a GPU mapping kills the process; that
-- is now false for these two nodes, which means the pages are genuinely mapped and faults are
-- being serviced by a cdev pager.
--
-- A cdev pager honours the mapping's protection bits at fault time, so "readable" says nothing
-- about "writable": the PTE may well be read-only and a store would fault (and, per 381a, the
-- store path swallows faults and reports success).  The only way to tell is to store and read
-- back.  If the store lands, this process has a writable kernel-pager-backed window, which is the
-- first one measured on 14.10.
--
-- The store targets are deliberately the 0x1000-offset pages - the all-zero page of dmem0 (a
-- scratch or pool page) and the all-FF page of gc.  A store into the register block at dmem0
-- offset 0 is never issued: the GPU must not be poked blind.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt (offsets, contents)
--   results/phase36_realargs/1399a_blockpool_device_20261109_142445.txt (write path -> ENXIO on the pool fd)
--   docs/DEVICE_IOCTL_14_10.md (the /dev node census)

print("=== PROBE 1396b: DEVICE MAPPING WRITABILITY ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wr(a, v) local ok = pcall(function() memory.write_dword(a, uint64(v)) end) return ok end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIG_IGN for SIGSYS so an absent slot returns -1 instead of killing us.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

-- ---------------------------------------------------------------- A
print("")
print("[A] map the candidate pages")
local MAPS = {}
local function domap(node, off)
    local path = str_addr(node)
    local fd = N(mk(5)(uint64(path), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
    if fd < 0 then print(string.format("   open(%s) -> %d %s", node, fd, es())) return end
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(1), uint64(fd), uint64(off)))
    if va < 0 and va > -4096 then
        print(string.format("   %s off=0x%X mmap -> %d %s", node, off, va, es()))
    else
        print(string.format("   %s fd=%d off=0x%X -> va=0x%X : %s %s %s %s",
            node, fd, off, va % 4294967296, hex4(rd(va)), hex4(rd(va+4)), hex4(rd(va+8)), hex4(rd(va+0xC))))
        MAPS[#MAPS + 1] = {node, off, va, fd}
    end
end
function hex4(v) if v == nil then return "????" end return string.format("%08X", v) end

domap("/dev/dmem0", 0)
domap("/dev/dmem0", 0x1000)
domap("/dev/dmem1", 0)
domap("/dev/dmem1", 0x1000)
domap("/dev/gc", 0)
domap("/dev/gc", 0x1000)

-- ---------------------------------------------------------------- B
print("")
print("[B] store, then read back.  Only 0x1000-offset pages are written.")
for _, m in ipairs(MAPS) do
    local node, off, va = m[1], m[2], m[3]
    if off == 0x1000 then
        local before = hex4(rd(va))
        wr(va, 0xDEADBEEF)
        wr(va + 4, 0xCAFEBABE)
        local a1 = hex4(rd(va))
        local a2 = hex4(rd(va + 4))
        local redo = wr(va, 0x12345678)
        local a3 = hex4(rd(va))
        print(string.format("   %s off=0x1000 before=%s after=%s/%s rewrote->%s (wr_ok=%s)",
            node, before, a1, a2, a3, tostring(redo)))
        -- verify from a second mapping of the same offset
        local fd2 = N(mk(5)(uint64(str_addr(node)), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
        local va2 = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd2), uint64(off)))
        if va2 > 0 then
            print(string.format("      second map va=0x%X reads %s %s", va2 % 4294967296, hex4(rd(va2)), hex4(rd(va2 + 4))))
            pcall(function() return mk(6)(uint64(fd2), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        end
    else
        print(string.format("   %s off=0x0 NOT written (registers), reads %s %s", node, hex4(rd(va)), hex4(rd(va + 4))))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] protection as the VM system sees it (547)")
for _, m in ipairs(MAPS) do
    local out = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(out + i, uint64(0xFFFFFFFF)) end) end
    local rv = N(mk(547)(uint64(m[3]), uint64(out), uint64(0x40), uint64(0), uint64(0), uint64(0)))
    print(string.format("   %s off=0x%X 547 -> %d %s : %s %s %s %s",
        m[1], m[2], rv, es(), hex4(rd(out)), hex4(rd(out + 4)), hex4(rd(out + 8)), hex4(rd(out + 0xC))))
end

-- ---------------------------------------------------------------- D
print("")
print("[D] close")
for _, m in ipairs(MAPS) do
    local rv = N(mk(6)(uint64(m[4]), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("   close(%d) -> %d", m[4], rv))
end

print("")
print("=== PROBE 1396b COMPLETE ===")
