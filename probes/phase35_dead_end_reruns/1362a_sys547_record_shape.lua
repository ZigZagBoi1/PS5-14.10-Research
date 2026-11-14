-- CRASH_CLASS: LOW (query only, no memory reads outside our own buffers)
-- PROBE 1362a: what does sys 547 actually fill in the region record?
--
-- 1361a asked 547 for every 64 KB block of the eboot text and got prot=0 for all
-- of them (results/phase35_dead_end_reruns/1361a_eboot_gadgets_dword_20261109_113907.txt),
-- so the record layout this probe assumed is wrong or the call needs a shape it
-- did not use. 1343b measured `0=U1 4=3 8=U2 c=3` on a page we had just mmapped
-- (docs/ARG23_CLASSES_14_10.md:74). Here we ask about addresses whose protection
-- is known independently - a fresh memory.alloc buffer (prot 3), the GPU mmap
-- (prot 3), the eboot text base from 593 (prot 5 per CLAUDE.md: only p=0x3 and
-- p=0x5 are readable) - and print the whole 0x40-byte record for each, plus one
-- 3-argument variant to see whether a size slot changes the answer.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1361a_eboot_gadgets_dword_20261109_113907.txt
--   docs/ARG23_CLASSES_14_10.md:65-84 (the seven writers, 547 record)
--   probes/phase17_new_vectors/114a_secC.lua:264-272

print("=== PROBE 1362a: SYS 547 RECORD SHAPE ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return N(v) end
    return nil
end
local function fmt(a)
    if type(a) == "table" and a.tonumber then a = a:tonumber() end
    return string.format("0x%X", tonumber(a) or 0)
end

local sc547 = mk(547)
local sc593 = mk(593)
local sc477 = mk(477)
local sc20 = mk(20)

local okp, pv = pcall(function() return sc20() end)
print("[0] pid=" .. (okp and N(pv) or 0))

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local EBN = N(eb_lo) + N(eb_hi) * 4294967296
print(string.format("[0] eboot text base=" .. fmt(EBN)))

-- a heap buffer we own (memory.alloc is calloc'd, prot 3)
local heap = memory.alloc(0x100)
wq(N(heap), uint64(0x4142434445464748))

-- the GPU mmap used everywhere as the heap R/W primitive
local gpu = nil
local okg, gv = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)
if okg and gv ~= nil then gpu = N(gv) end
print("[0] heap=" .. fmt(N(heap)) .. "  gpu=" .. fmt(gpu or 0))

local qout = memory.alloc(0x40)
local function dump(tag, addr, nargs)
    for i = 0, 0x3C, 4 do wd(N(qout) + i, 0xDEADBEEF) end
    local ok, rv
    if nargs == 2 then
        ok, rv = pcall(function() return sc547(uint64(addr), uint64(qout)) end)
    else
        ok, rv = pcall(function() return sc547(uint64(addr), uint64(qout), uint64(0x10)) end)
    end
    local parts = {}
    for i = 0, 0x3C, 4 do
        local v = rd(N(qout) + i)
        parts[#parts + 1] = string.format("%X", v or 0)
    end
    print(string.format("  %s %s nargs=%d ok=%s rv=%s", tag, fmt(addr), nargs,
        tostring(ok), ok and fmt(rv) or "EXC"))
    print("      " .. table.concat(parts, " "))
end

print("")
print("[A] 2-argument form")
dump("eboot", EBN, 2)
dump("eboot+0x1000", EBN + 0x1000, 2)
dump("heap", N(heap), 2)
if gpu and gpu ~= 0 then dump("gpu", gpu, 2) end

print("")
print("[B] 3-argument form (size slot)")
dump("heap", N(heap), 3)

print("")
print("[C] same address twice, in case the record is a cursor")
dump("heap", N(heap), 2)
dump("heap", N(heap), 2)

print("")
print("=== PROBE 1362a COMPLETE ===")
