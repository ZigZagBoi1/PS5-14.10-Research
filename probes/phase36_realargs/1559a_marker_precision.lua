-- CRASH_CLASS: LOW
-- PROBE 1559a: which 64-bit value paths in this loader are exact?
--
-- Context: 1554a printed "H reads 0x11223344556677" BEFORE thr_create, with
-- zero(Hv) having just run. Two suspects:
--   (a) memory.write_qword/read_qword lose bits for values above 2^53, and
--   (b) string.format("%X", <raw uint64 table>) does not format the value at
--       all, but reads an unrelated integer.
-- 1557a's arm check used the same %X-on-raw-uint64 idiom and printed a perfect
-- 0x11223344556677, which may have been the same artifact. Every race probe in
-- this tree depends on that comparison, so it has to be settled.
--
-- prior art:
--   results/phase36_realargs/1555a_memory_write_paths_20261110_193430.txt
--     -- [A] write_qword(0x11223344556677) read back as 0x1122334455666C.
--   results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193528.txt
--     -- H printed MARKER before any child existed.
--   results/phase36_realargs/1557a_unmap_pte_removal_20261110_192806.txt
--     -- the same idiom printed a clean value; the child's RAX in the raw dump
--        was genuinely 0x0011223344556677.
--
-- Method: no syscalls beyond one mmap. Store the same value three ways and read
-- it back three ways, then repeat with a value that fits in 32 bits.

print("=== PROBE 1559a: 64-bit value paths ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_mmap = mk(477)
local sc_getpid = mk(20)

local function rawq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return v end
    return nil
end

local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

print(string.format("[0] pid=%d", to_num(sc_getpid())))
local P = mmap_anon(0x4000)
if not P then print("=== ABORT ===") return end
print(string.format("[0] P=0x%X", P))

local BIG  = 0x0011223344556677   -- 53 bits, exactly representable as a double
local BIGS = "0x0011223344556677"
local SMALL = 0xDEADBEEF          -- 32 bits

local function show(tag, a)
    local r = rawq(a)
    print(string.format("%s raw %%X      = 0x%X", tag, r))
    print(string.format("%s to_num %%X   = 0x%X", tag, to_num(r)))
    print(string.format("%s to_num %%d   = %d", tag, to_num(r)))
end

print("")
print("[A] store BIG from a Lua number")
pcall(function() memory.write_qword(uint64(P), uint64(BIG)) end)
show("[A]", P)

print("")
print("[B] store BIG from a hex string")
pcall(function() memory.write_qword(uint64(P), uint64(BIGS)) end)
show("[B]", P)

print("")
print("[C] store SMALL (32-bit)")
pcall(function() memory.write_qword(uint64(P), uint64(SMALL)) end)
show("[C]", P)

print("")
print("[D] round-trip: read, write the same value back, read again")
local r1 = rawq(P)
pcall(function() memory.write_qword(uint64(P + 8), r1) end)
show("[D src ]", P)
show("[D dst ]", P + 8)
print(string.format("[D] src to_num = %d, dst raw %%X = 0x%X", to_num(r1), rawq(P + 8)))

print("")
print("[E] the value the race probes actually compare")
for _, v in ipairs({ { "BIG-by-table", BIG }, { "SMALL", SMALL } }) do
    local name, val = v[1], v[2]
    pcall(function() memory.write_qword(uint64(P), uint64(val)) end)
    local back = rawq(P)
    local ok = rawequal(back, uint64(val))
    print(string.format("[E] %-13s written=0x%X read(%%X)=0x%X rawequal=%s",
        name, val, back, tostring(ok)))
end

print("")
print("=== PROBE 1559a COMPLETE ===")
