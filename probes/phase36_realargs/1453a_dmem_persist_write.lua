-- CRASH_CLASS: LOW
-- PROBE 1453a: is the /dev/dmem ONION block shared kernel memory, or a per-process copy?
--
-- Context:
--   /dev/dmem0 maps a 4 GiB RW window whose page 0 is a static table and whose 0xF000 block carries
--   BEEB03FF 00000003 7E000280 5E000100 plus the ASCII "COrbisMemory ONION", followed from 0x11000 by
--   a stride-0x80 record array with a stable 32-byte body and runs of AFAFAFAF.  Stores into page 0
--   and into page 0x16 land and stick (1397j), and the record table in page 0 does not steer the
--   mapping (1397k/1397l).  What has never been measured: whether a store into the populated block
--   survives the process.
--
--   The loader spawns a fresh process per TCP connection (observed: pid 350, 357, 402, 416, 423, 432
--   across one session, with per-connection userland ASLR), so "survives the process" is testable
--   without a relaunch: this probe writes a signature, and probe 1454a -- sent as a separate
--   connection, therefore a different process -- reads it back.
--     signature present  -> the window maps memory that outlives the process = shared kernel memory,
--                           and a store into it is a kernel write
--     signature absent   -> the driver copies kernel-initialised structures into per-process pages
--                           and the window is not a kernel write path
--
-- -- prior art:
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the ONION block and 0x11000 records)
--   results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt (23 pages stable over 1.5 s)
--   results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt (page 0 and page 0x16 stores land)
--   results/phase36_realargs/1397k_dmem_record_steer_20261109_143442.txt (records do not steer the map)
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1453a: DMEM BLOCK PERSISTENCE (WRITE) ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function sgn(v) local n=N(v) if n<0 then return -1 end return n end
local function isva(v) return v > 0x10000 and v < 0x8000000000 end
local function rdd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return nil end
local function wrd(a,v) return (pcall(function() memory.write_dword(a, uint64(v)) end)) end

local OPEN, CLOSE, MMAP, MUNMAP, GETPID, NANOSLEEP = mk(5), mk(6), mk(477), mk(73), mk(20), mk(240)

local function getpid() return sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))) end
local function hex(v) if v==nil then return "????????" end return string.format("%08X", v) end

-- string -> mapped buffer for open()
local function str_addr(s)
    local b = N(memory.alloc(0x100))
    for i = 0, 0x40, 8 do pcall(function() memory.write_qword(b + i, uint64(0)) end) end
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(string.byte(s, i))) end) end
    return b
end

local function dev_map(path, off, len, prot)
    local p = str_addr(path)
    local ok, fd = pcall(function() return OPEN(uint64(p), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -1, -1 end
    fd = sgn(fd)
    if fd < 0 then return -1, -1 end
    local ok2, va = pcall(function()
        return MMAP(uint64(0), uint64(len), uint64(prot), uint64(0x1), uint64(fd), uint64(off))
    end)
    if not ok2 then return fd, -1 end
    local n = N(va)
    if not isva(n) then return fd, -1 end
    return fd, n
end

local SIG_F000 = 0xCAFEBABE
local SIG_11040 = 0xDEAD1234
local SIG_0F020 = 0x0F0F0F0F

print(string.format("[0] pid=%d", getpid()))
print("")

local function do_block(tag, off, dump_offsets)
    local fd, va = dev_map("/dev/dmem0", off, 0x1000, 3)
    if va <= 0 then
        print(string.format("[%s] map at 0x%X FAILED (fd=%d)", tag, off, fd))
        return nil
    end
    print(string.format("[%s] offset 0x%X -> 0x%X", tag, off, va))
    local vals = {}
    for i = 1, #dump_offsets do
        vals[i] = rdd(va + dump_offsets[i])
    end
    for i = 1, #dump_offsets do
        print(string.format("   +0x%03X = %s", dump_offsets[i], hex(vals[i])))
    end
    return va, vals
end

--------------------------------------------------------------------------
-- [A] the ONION header at 0xF000
--------------------------------------------------------------------------
local vaA = do_block("A", 0xF000, {0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20})
if vaA then
    local o = 0x20
    wrd(vaA + o, SIG_0F020)
    local back = rdd(vaA + o)
    print(string.format("[A] wrote %s at +0x%X, read back %s", hex(SIG_0F020), o, hex(back)))
end
print("")

--------------------------------------------------------------------------
-- [B] read-only record of the 0x11000 array (NOT written: it is live-looking metadata)
--------------------------------------------------------------------------
local vaB = do_block("B", 0x11000, {0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44})
if vaB then print("[B] read only -- no store into the record array") end
print("")

--------------------------------------------------------------------------
-- [C] page 0 tail: proven safe to write by 1397j
--------------------------------------------------------------------------
local vaC = do_block("C", 0x0, {0x800, 0x804, 0x808, 0x80C, 0xBF0})
if vaC then
    wrd(vaC + 0xBF0, SIG_F000)
    local b = rdd(vaC + 0xBF0)
    print(string.format("[C] wrote %s at page0+0xBF0, read back %s", hex(SIG_F000), hex(b)))
end
print("")

--------------------------------------------------------------------------
-- [D] page 0x16 tail: also proven safe to write by 1397j
--------------------------------------------------------------------------
local vaD = do_block("D", 0x16000, {0xF00, 0xF04, 0xF08})
if vaD then
    wrd(vaD + 0xF00, SIG_11040)
    local b = rdd(vaD + 0xF00)
    print(string.format("[D] wrote %s at page16+0xF00, read back %s", hex(SIG_11040), hex(b)))
end

print("")
print(string.format("[E] survivor pid=%d -- 1454a must read page0+0xBF0 (= %s), page16+0xF00 (= %s) and 0xF000+0x20 (unwritten control)",
    getpid(), hex(SIG_F000), hex(SIG_11040)))
print("")
print("=== PROBE 1453a COMPLETE ===")
