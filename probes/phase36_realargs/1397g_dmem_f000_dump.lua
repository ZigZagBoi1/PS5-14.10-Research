-- CRASH_CLASS: LOW -- read-only.  No store anywhere.
-- PROBE 1397g: what lives at dmem offsets 0xF000-0x17000?
--
-- 1397f mapped the low 1 MiB and found eleven non-zero pages beyond the ones this session wrote: page
-- 0x000 (the static table), page 0x00F (BEEB03FF 00000003 7E000280 5E000100) and pages 0x011-0x016
-- (00000002 00000002 00000002 00000000, then a three-2s pattern that shifts by a dword).  Everything
-- else in 4 GiB is zero.
--
-- Two readings fit.  One: this is device memory the firmware/GPU initialised at boot and the rest of
-- the window is unallocated.  Two: the page is a command or descriptor block - 0xBEEB03FF is a Sony
-- magic and 0x7E000280 / 0x5E000100 have the shape of type-1 PM4 register-write headers.
--
-- The dump decides.  A register-init sequence is a long run of (address, value) pairs; a command
-- buffer starts with a packet header and is dense; a counter array is a run of small identical
-- values.  This probe prints pages 0x00F, 0x010 and 0x011 in full and the first 0x100 bytes of
-- 0x012-0x016, which is enough to size the structure and read its first records.
--
-- -- prior art:
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt (the non-zero page list)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (page-0 table dump)

print("=== PROBE 1397g: dmem 0xF000-0x17000 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex(v) return string.format("%08X", v) end
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

-- one 0x20000 mapping covers 0xF000..0x20000 contiguously (1397e proved contiguity)
local BASE = N(mk(477)(uint64(0), uint64(0x20000), uint64(1), uint64(1), uint64(fd0), uint64(0xF000)))
print(string.format("[0] map 0xF000 len 0x20000 -> 0x%010X", BASE))
if not isva(BASE) then
    print(string.format("   refused: %s", es()))
    print("=== PROBE 1397g ABORT ===")
    return
end

local function dump(off, dwords, label)
    print("")
    print(string.format("[%s] offset 0x%05X, %d dwords", label, off, dwords))
    local va = BASE + (off - 0xF000)
    local per = 8
    for row = 0, math.floor(dwords / per) - 1 do
        local parts = {}
        local allzero = true
        for i = 0, per - 1 do
            local v = rd(va + (row * per + i) * 4) or 0
            parts[#parts + 1] = hex(v)
            if v ~= 0 then allzero = false end
        end
        if not allzero then
            print(string.format("   %05X: %s", off + row * per * 4, table.concat(parts, " ")))
        end
    end
end

dump(0xF000, 0x400, "A")
dump(0x10000, 0x100, "B")
dump(0x11000, 0x100, "C")
dump(0x12000, 0x40, "D")
dump(0x13000, 0x40, "E")
dump(0x14000, 0x40, "F")
dump(0x15000, 0x40, "G")
dump(0x16000, 0x40, "H")

-- how far do the non-zero pages go?
print("")
print("[I] non-zero pages from 0x17000 to 0x40000")
local nz = 0
for p = 0x17, 0x3F do
    local base = BASE + (p * 0x1000 - 0xF000)
    local a, b, c, d = rd(base), rd(base + 4), rd(base + 8), rd(base + 0xC)
    if (a or 0) ~= 0 or (b or 0) ~= 0 or (c or 0) ~= 0 or (d or 0) ~= 0 then
        nz = nz + 1
        print(string.format("   page 0x%03X : %s %s %s %s", p, hex(a), hex(b), hex(c), hex(d)))
    end
end
print(string.format("   [I] %d of 41 pages non-zero", nz))

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397g COMPLETE ===")
