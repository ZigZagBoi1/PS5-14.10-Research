-- CRASH_CLASS: LOW -- the only store is the marker already proven safe at offset 0x1000.  Everything
-- else is a read-only mapping of a device page.
-- PROBE 1397c: contents along the /dev/dmem0 offset ladder.
--
-- 1397b mapped every rung from 0 to 0x10000000 with prot=1 and got a VA back for all twenty, but
-- its success test treated a 0x311xxxxxx VA as a failure, so the contents were never printed.  Two
-- facts make this worth a second run: the same rung (0x10000000) is refused with prot=3, and /dev/gc
-- stops mapping above 0x2000.  So the node has an access rule that depends on both offset and
-- protection, and it is the protection-3 boundary that decides whether a page is writable.
--
-- The question is what the offset indexes.  If it is a linear byte offset into a device address
-- space, consecutive rungs hold unrelated pages and 0x1000 is physical 0x1000.  If it is a window
-- id, the rungs will alias or return identical data.  Test: read every rung, then store a marker at
-- 0x1000 (the one page already proven writable) and re-read every other rung looking for it.
--
-- Access-rule matrix: for each rung try prot=1 and prot=3 and report which is accepted.  The first
-- rung that accepts prot=3 above 0x1000 is the interesting one; a writable page at an arbitrary
-- offset is the primitive.
--
-- -- prior art:
--   results/phase36_realargs/1397b_dmem_offset_ladder_20261109_142645.txt (all 20 rungs map with prot=1)
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt (0x1000 writable, shared backing)
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt (prot=3 refused above 0x1000)

print("=== PROBE 1397c: dmem0 LADDER CONTENTS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wr(a, v) local ok = pcall(function() memory.write_dword(a, uint64(v)) end) return ok end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
-- userland VAs here are 40-bit (0x311xxxxxx, 0x37Fxxxxxx); -1 is the failure value
local function isva(v) return v > 0 and v < 18446744073709551616 and v ~= -1 end

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

local function mapit(off, prot)
    return N(mk(477)(uint64(0), uint64(0x1000), uint64(prot), uint64(1), uint64(fd0), uint64(off)))
end

-- ---------------------------------------------------------------- A
print("")
print("[A] contents of every rung (prot=1)")
local OFFS = {
    0, 0x1000, 0x2000, 0x3000, 0x4000, 0x8000, 0xC000, 0x10000, 0x20000,
    0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000,
    0x2000000, 0x4000000, 0x8000000, 0x10000000,
}
local VA = {}
for _, off in ipairs(OFFS) do
    local va = mapit(off, 1)
    if isva(va) then
        VA[off] = va
        print(string.format("   off=0x%08X va=0x%010X : %s %s %s %s %s %s %s %s",
            off, va, hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC)),
            hex4(rd(va + 0x10)), hex4(rd(va + 0x14)), hex4(rd(va + 0x18)), hex4(rd(va + 0x1C))))
    else
        print(string.format("   off=0x%08X -> refuse %s", off, es()))
    end
end

-- ---------------------------------------------------------------- B
print("")
print("[B] prot=3 acceptance per rung (writable?)")
for _, off in ipairs(OFFS) do
    local va = mapit(off, 3)
    if isva(va) then
        print(string.format("   off=0x%08X prot=3 OK va=0x%010X : %s %s", off, va, hex4(rd(va)), hex4(rd(va + 4))))
    else
        local e = es()
        print(string.format("   off=0x%08X prot=3 -> %d %s", off, va, e))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] alias test: store 0xA5A5A5A5 at the 0x1000 rung, re-read every rung")
if VA[0x1000] then
    wr(VA[0x1000], 0xA5A5A5A5)
    print(string.format("   wrote 0xA5A5A5A5 at va=0x%010X (0x1000 rung), reads %s", VA[0x1000], hex4(rd(VA[0x1000]))))
    for _, off in ipairs(OFFS) do
        if off ~= 0x1000 and VA[off] then
            local v = rd(VA[off])
            local tag = ""
            if v == 0xA5A5A5A5 then tag = "  <-- ALIASED" end
            print(string.format("   off=0x%08X reads %s%s", off, hex4(v), tag))
        end
    end
end

-- ---------------------------------------------------------------- D
print("")
print("[D] does the store survive a fresh mapping of 0x1000?")
local va = mapit(0x1000, 1)
if isva(va) then
    print(string.format("   fresh map va=0x%010X reads %s %s", va, hex4(rd(va)), hex4(rd(va + 4))))
else
    print(string.format("   fresh map refused: %s", es()))
end

print("")
print("[E] close")
print(string.format("   close(%d) -> %d", fd0, N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397c COMPLETE ===")
