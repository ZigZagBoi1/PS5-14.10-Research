-- CRASH_CLASS: LOW
-- PROBE 1455a: post-restart check of the /dev/dmem signatures (run after the process changed)
--
-- Context:
--   1453a (pid 439) wrote 0F0F0F0F at 0xF000+0x20 (originally 5362724F), CAFEBABE at page0+0xBF0
--   and DEAD1234 at page16+0xF00.  1454a read all three back and found them -- but with pid 439 on
--   both sides, so the loader had NOT spawned a new process and the persistence question stayed open.
--   The loader does change pid between runs (350, 357, 402, 416, 423, 432, 439 across this session)
--   when it restarts, so this probe must be run after a pid change.
--
--     signatures still present, 0xF000+0x20 != 5362724F -> the window maps memory shared across
--                           processes: a store through it is a kernel write into something that
--                           outlives us
--     signatures gone, 0xF000+0x20 == 5362724F        -> the driver regenerates the populated block
--                           in each process's own pages and the window is not a cross-process write
--
-- -- prior art:
--   results/phase36_realargs/1453a_dmem_persist_write_20261109_174007.txt (pid 439, the writes)
--   results/phase36_realargs/1454a_dmem_persist_read_20261109_174019.txt (pid 439, same process)
--   results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt (markers from a run two
--     pids earlier were gone: pages 0x01-0x04 read zero)
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1455a: DMEM PERSISTENCE ACROSS A PROCESS CHANGE ===")
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

local pid = getpid()
print(string.format("[0] pid=%d  (1453a/1454a ran as pid 439; a DIFFERENT value is required here)", pid))
print("")

local vA, vC, vD = nil, nil, nil
local va = dev_map(0xF000)
if va > 0 then vA = rdd(va + 0x20) print(string.format("[A] 0xF000+0x20 = %s  (written 0F0F0F0F, original 5362724F)", hex(vA))) end
va = dev_map(0x0)
if va > 0 then vC = rdd(va + 0xBF0) print(string.format("[C] page0+0xBF0  = %s  (written CAFEBABE, original 00000000)", hex(vC))) end
va = dev_map(0x16000)
if va > 0 then vD = rdd(va + 0xF00) print(string.format("[D] page16+0xF00 = %s  (written DEAD1234, original 00000000)", hex(vD))) end

print("")
local survived = 0
if vA == 0x0F0F0F0F then survived = survived + 1 end
if vC == 0xCAFEBABE then survived = survived + 1 end
if vD == 0xDEAD1234 then survived = survived + 1 end
print(string.format("[VERDICT] pid=%d survived=%d/3", pid, survived))
if pid == 439 then
    print("   pid unchanged -- this run cannot answer the question; re-run after the loader restarts")
elseif survived > 0 then
    print("   SHARED: the dmem window maps memory that outlives the process")
else
    print("   PRIVATE: the populated block is regenerated per process")
end
print("")
print("=== PROBE 1455a COMPLETE ===")
