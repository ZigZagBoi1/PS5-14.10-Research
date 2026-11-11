-- CRASH_CLASS: MODERATE -- stores only into the all-zero tail of page 0 (0xBC000+0xBF0, past every
-- populated record) and the tail of the 0x16 page.  No populated record is modified in this probe.
-- PROBE 1397j: is page 0 writable, and does a store there survive?
--
-- 1397i measured that pages 0x00 and 0x0F-0x16 are byte-identical across two passes 1.5 s apart while
-- every page this session wrote (0x01-0x04 markers) came back zero after the loader process changed
-- pid, so the device allocates per process while the populated structures are kernel-initialised and
-- outlive it.  Nothing has yet stored into page 0 itself.
--
-- Writing into a populated record is the experiment that could hang a console, and it is not this
-- probe.  This one writes only past 0xBC0, where page 0 has been zero in every dump, plus the tail of
-- the 0x80-stride record array.  If those stores land and read back, the page is ordinary writable
-- RAM behind the pager and the next question is what consumes it.  If they read back unchanged, the
-- page is memory-mapped device state that ignores writes.
--
-- -- prior art:
--   results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt (static over 1.5 s)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (full page-0 dump)
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the 0x80-stride records)

print("=== PROBE 1397j: PAGE 0 AND RECORD BLOCK WRITABILITY ===")

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

-- ---------------------------------------------------------------- A
print("")
print("[A] page 0: tail write")
local P0 = pmap(0, 3)
print(string.format("   page0 map -> 0x%010X", P0))
if isva(P0) then
    local before = rd(P0 + 0xBF0)
    print(string.format("   +0xBF0 before = %s", hex(before)))
    wr(P0 + 0xBF0, 0xAAAA5555)
    wr(P0 + 0xBF4, 0x11112222)
    print(string.format("   +0xBF0 after  = %s / %s", hex(rd(P0 + 0xBF0)), hex(rd(P0 + 0xBF4))))
    -- is the record table intact?
    print(string.format("   record 0x800 still %s %s (unchanged expected)", hex(rd(P0 + 0x800)), hex(rd(P0 + 0x804))))
    print(string.format("   dword 0 still %s (pointer-looking, unchanged expected)", hex(rd(P0))))
end

-- ---------------------------------------------------------------- B
print("")
print("[B] page 0x16 tail write")
local P16 = pmap(0x16000, 3)
print(string.format("   page16 map -> 0x%010X", P16))
if isva(P16) then
    local b1 = rd(P16 + 0xF00)
    print(string.format("   +0xF00 before = %s", hex(b1)))
    wr(P16 + 0xF00, 0xBBBB6666)
    print(string.format("   +0xF00 after  = %s", hex(rd(P16 + 0xF00))))
end

-- ---------------------------------------------------------------- C
print("")
print("[C] sleep 500 ms and re-read")
local ts = memory.alloc(0x10)
pcall(function() memory.write_qword(ts, uint64(0)) end)
pcall(function() memory.write_qword(ts + 8, uint64(500000000)) end)
print(string.format("   nanosleep -> %d", N(mk(240)(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
if isva(P0) then
    print(string.format("   page0 +0xBF0 = %s %s", hex(rd(P0 + 0xBF0)), hex(rd(P0 + 0xBF4))))
end
if isva(P16) then
    print(string.format("   page16 +0xF00 = %s", hex(rd(P16 + 0xF00))))
end

-- ---------------------------------------------------------------- D
print("")
print("[D] fresh mapping of page 0 sees the writes?")
local P0b = pmap(0, 1)
if isva(P0b) then
    print(string.format("   fresh page0 +0xBF0 = %s %s", hex(rd(P0b + 0xBF0)), hex(rd(P0b + 0xBF4))))
else
    print(string.format("   fresh map refused: %s", es()))
end

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397j COMPLETE ===")
