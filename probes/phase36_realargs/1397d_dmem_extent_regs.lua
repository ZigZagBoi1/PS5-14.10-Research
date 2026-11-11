-- CRASH_CLASS: LOW -- maps and reads only.  No store is issued anywhere; the previous probe's store
-- went into a read-only mapping and killed the process, so this one writes nothing at all.
-- PROBE 1397d: extent of the dmem window and a full dump of the register page.
--
-- 1397c mapped every rung 0..0x10000000 with prot=1 AND prot=3 (all accepted; the earlier "EINVAL
-- above 0x1000" in 1395a was a different argument shape) and found only rung 0 carrying data the
-- driver did not zero-fill: C0012800 80000000 80000000 C0001200 00000000 C0055800 2EC47FC0
-- FFFFFFFF.  Every other rung reads zero except rung 0x10000, whose +0x18 read 00000523.
--
-- Two things are needed before any store into rung 0 is attempted:
--   1. how far the window goes.  If 0x20000000 and 0x40000000 also map, the node is a linear
--      mapping of a large device space and the zero pages are unallocated DMem, not a fixed stub.
--   2. the complete contents of rung 0.  Those eight dwords are 32-bit register values, and the
--      register map is what decides which of them is safe to write.  A dump costs nothing; a blind
--      store into an unknown GC register costs a console power cycle.
--
-- -- prior art:
--   results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt (all rungs map, all writable)
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt (0x1000 page is real RAM)
--   docs/DEAD_ENDS.md (/dev/dmem0 bullet: "phys 0 = GPU HW reg 0x80000000_C0012800")

print("=== PROBE 1397d: dmem EXTENT + REGISTER PAGE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function isva(v) return v > 0 and v < 0x8000000000 end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

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

local fd0 = N(mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] dmem0 fd=%d", fd0))

local function mapit(off, prot, len)
    return N(mk(477)(uint64(0), uint64(len or 0x1000), uint64(prot), uint64(1), uint64(fd0), uint64(off)))
end

-- ---------------------------------------------------------------- A
print("")
print("[A] how far does the window go (prot=1, 0x1000 each)")
local HI = {
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x100000000, 0x200000000,
    0x400000000, 0x800000000, 0xFFFFFFFFFFFFF000,
}
for _, off in ipairs(HI) do
    local va = mapit(off, 1)
    if isva(va) then
        print(string.format("   off=0x%012X va=0x%010X : %s %s %s %s", off, va,
            hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC))))
    else
        print(string.format("   off=0x%012X -> %d %s", off, va, es()))
    end
end

-- ---------------------------------------------------------------- B
print("")
print("[B] large lengths (prot=1, offset 0x1000)")
for _, len in ipairs({0x2000, 0x10000, 0x100000, 0x1000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000}) do
    local va = mapit(0x1000, 1, len)
    if isva(va) then
        print(string.format("   len=0x%09X va=0x%010X : %s %s", len, va, hex4(rd(va)), hex4(rd(va + 4))))
    else
        print(string.format("   len=0x%09X -> %d %s", len, va, es()))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] full dump of the register page (dmem0 offset 0), 8 dwords per line")
local REG = mapit(0, 1)
if isva(REG) then
    for row = 0, 0x7F do
        local base = REG + row * 0x20
        local parts = {}
        for i = 0, 7 do
            parts[#parts + 1] = hex4(rd(base + i * 4))
        end
        print(string.format("   %04X: %s", row * 0x20, table.concat(parts, " ")))
    end
else
    print(string.format("   register page refused: %s", es()))
end

-- ---------------------------------------------------------------- D
print("")
print("[D] close")
print(string.format("   close(%d) -> %d", fd0, N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397d COMPLETE ===")
