-- CRASH_CLASS: MODERATE -- rewrites one dword of a populated record, remaps, restores.
-- PROBE 1397l: does record[0] steer the 0xF000 window?
--
-- 1397k showed the records start at 0x800 with stride 0x14 = (addr, E0000C00, 0000000F, 00000100, N),
-- N running 0x0, 0x400, 0x800 ..., i.e. 64 chunks of 0x400 = 0x10000 bytes, which is exactly the
-- span 0xF000..0x1EFFF where 1397g found the populated block.  Records 61..63 read zero, so the
-- table may stop earlier than 64, or the last records are simply unused.
--
-- The self-verifying test: record[0].addr = C0038000 and the window at 0xF000 reads a distinctive
-- dword.  If record[0] covers window 0xF000, then setting it to C0039000 must make offset 0xF000
-- read what offset 0xF400 read before -- the neighbouring chunk.  No content guesswork: the answer
-- is a byte comparison between two windows we have both measured.
--
-- Mapping pages are unmapped and remapped around the edit because the pager installs PTEs at mmap
-- time; the record only matters if something re-reads it.  Everything is restored in [F].
--
-- -- prior art:
--   results/phase36_realargs/1397k_dmem_record_steer_20261109_143442.txt (records 0..3, 61..63 zero)
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (0xF000 = BEEB03FF ...)

print("=== PROBE 1397l: DOES RECORD[0] STEER 0xF000? ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
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

local function pmap(off, prot)
    return N(mk(477)(uint64(0), uint64(0x1000), uint64(prot), uint64(1), uint64(fd0), uint64(off)))
end
local function punmap(va)
    return N(mk(73)(uint64(va), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0)))
end

-- ---------------------------------------------------------------- A
print("")
print("[A] record extent on page 0")
local P0 = pmap(0, 3)
print(string.format("   map -> 0x%010X", P0))
if not isva(P0) then print("   ABORT: " .. es()) return end
local last = -1
for i = 0, 60 do
    local b = P0 + 0x800 + i * 0x14
    local a0 = rd(b)
    if a0 ~= nil and a0 ~= 0 then last = i end
    if i < 6 or (a0 ~= 0 and a0 ~= 0xC0038000) then
        print(string.format("     [%02d] %s %s %s %s %s", i, hex(rd(b)), hex(rd(b + 4)), hex(rd(b + 8)), hex(rd(b + 0xC)), hex(rd(b + 0x10))))
    end
end
print(string.format("   last non-zero record index = %d", last))

-- ---------------------------------------------------------------- B
print("")
print("[B] baseline of the first two 0x400 chunks at 0xF000")
local P15 = pmap(0xF000, 3)
print(string.format("   page 0xF map -> 0x%010X", P15))
if not isva(P15) then print("   ABORT: " .. es()) return end
local function dump8(base, tag)
    local out = {}
    for k = 0, 7 do out[#out + 1] = hex(rd(base + k * 4)) end
    print(string.format("   %s %s", tag, table.concat(out, " ")))
end
dump8(P15 + 0x000, "0xF000+0x000:")
dump8(P15 + 0x400, "0xF000+0x400:")

-- ---------------------------------------------------------------- C
print("")
print("[C] point record[0] at the next physical chunk (C0038000 -> C0039000)")
local R0 = P0 + 0x800
print(string.format("   record[0] before: %s", hex(rd(R0))))
wr(R0, 0xC0039000)
print(string.format("   record[0] after : %s", hex(rd(R0))))

-- ---------------------------------------------------------------- D
print("")
print("[D] unmap and remap 0xF000")
print(string.format("   munmap -> %d", punmap(P15)))
local P15b = pmap(0xF000, 3)
print(string.format("   remap -> 0x%010X", P15b))
if isva(P15b) then
    dump8(P15b + 0x000, "after 0x000:")
    dump8(P15b + 0x400, "after 0x400:")
    print("   If the record steers the window, 'after 0x000' must equal the old '0x400' line.")
    P15 = P15b
end

-- ---------------------------------------------------------------- E
print("")
print("[E] a chunk the table did not describe: point record[0] at 0x00000000")
wr(R0, 0x00000000)
punmap(P15)
local P15c = pmap(0xF000, 3)
if isva(P15c) then
    dump8(P15c + 0x000, "zero-addr 0x000:")
    P15 = P15c
end

-- ---------------------------------------------------------------- F
print("")
print("[F] restore and verify")
wr(P0 + 0x800, 0xC0038000)
print(string.format("   record[0] -> %s", hex(rd(P0 + 0x800))))
punmap(P15)
local P15d = pmap(0xF000, 3)
if isva(P15d) then
    dump8(P15d + 0x000, "restored 0x000:")
end

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397l COMPLETE ===")
