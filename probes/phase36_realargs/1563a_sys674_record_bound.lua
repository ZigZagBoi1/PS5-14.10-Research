-- CRASH_CLASS: LOW
-- PROBE 1563a: is 674's record count bounded by anything the caller declares, or
--              does the kernel write one 72-byte record per map entry into a
--              buffer whose size it never learns?
--
-- Context: syscall 674 (`query_memory` / VM map enumeration) is called by every
-- GPU-window probe in this tree as
--     674(buf, 72, MAXR, countp, 0x40000000, 0)
-- and the corpus always sizes buf as MAXR*72 (1481f uses CAP records).  The
-- syscall has NO buffer-length argument: arg2 is the record stride and arg3 is
-- the record limit.  If the kernel trusts arg3 and writes one stride per map
-- entry, then declaring a limit larger than the buffer overruns it -- and the
-- overrun lands wherever the caller pointed the buffer.  This tree's map has
-- ~317 entries, so a 4 KiB buffer with a 400-record limit would take ~22 KiB of
-- kernel-written data.
--
-- This is a write primitive of fixed content into an attacker-chosen address,
-- which is why it is worth measuring rather than assuming.  The probe keeps
-- every write inside one 477 region, so a positive result is a measurement, not
-- a crash.
--
-- prior art:
--   probes/phase36_realargs/1481f_full_map_dump.lua:27-40
--     -- the canonical shape: 674(buf, 72, CAP, cnt, 0x40000000, 0), buf sized
--        CAP*72, cnt read back after the call.  No probe in the corpus has ever
--        declared a record limit larger than the buffer.
--   docs/HANDLER_CLAIM_CORRECTIONS.md:554 -- the copyout per record is
--     min(0x48, uap[8]); that bounds the STRIDE, not the number of records.
--   results/phase17_new_vectors/55e_vm_map_kernel_ptr_20261018_*.txt
--     -- 317 records enumerated with full 72-byte records, all user VAs.
--   results/phase36_realargs/1481a_gpu_windows_scan_20261110_*.txt
--     -- the same shape used to find SceGnm* windows by name at rec+0x21.
--
-- Method, on one 0x10000 (four page) 477 region:
--   [A] fill all four pages with 0xA5, call 674(buf, 72, 400, cnt) and count
--       how many bytes from buf onward differ from 0xA5, and how far the
--       furthest differing byte is.  Count the records the kernel reports in
--       cnt.  If the written span exceeds the 0x4000 first page, the kernel
--       wrote more than the page the caller might have offered -- the write is
--       bounded only by the map size, not by the buffer.
--   [B] same, limit 8 and limit 0: does the limit ever truncate?  (It should.)
--   [C] same, limit 4000 with the buffer at the START of the region so the
--       span is still inside our mapping; report the furthest byte.
--   [D] countp = a 4 KiB page of 0xEE: check the kernel writes only one dword.
-- The only numbers that matter are "furthest byte written" and "records
-- reported"; nothing here can fault as long as the region is 0x10000 and the
-- map stays under 4000 entries.

print("=== PROBE 1563a: sys 674 record-count bound ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end

local sc_mmap   = mk(477)
local sc_getpid = mk(20)
local sc674     = mk(674)

local REGION = 0x10000

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

local function fill(base, len, val)
    for off = 0, len - 4, 4 do wd(base + off, val) end
end

-- Furthest byte offset from base that is not 0xA5A5A5A5, and the count of
-- differing dwords.  Scans dwords, so the reported span is dword-granular.
local function span(base, len)
    local last, n = -1, 0
    for off = 0, len - 4, 4 do
        local v = rd(base + off)
        if v ~= nil and v ~= 0xA5A5A5A5 then
            n = n + 1
            last = off
        end
    end
    return last, n
end

local function run674(tag, base, stride, limit, cntp)
    local ok, rv = pcall(function()
        return sc674(uint64(base), uint64(stride), uint64(limit),
                     uint64(cntp), uint64(0x40000000), uint64(0))
    end)
    local r = ok and to_num(rv) or -999
    local c = rd(cntp)
    print(string.format("%s rv=%d count=%s (limit=%d stride=%d)",
        tag, r, tostring(c), limit, stride))
    return r, c
end

print(string.format("[0] pid=%d", to_num(sc_getpid())))
local buf = mmap_anon(REGION)
print(string.format("[0] region=0x%X len=0x%X", to_num(buf or 0), REGION))
if not buf then
    print("=== VOID: no region ===")
    return
end
local cnt = memory.alloc(0x1000)

-- ---- [A] the honest record count, with a limit larger than the buffer ----
print("")
print("[A] 674(buf, 72, 400, cnt) over a 0x10000 region, first page only offered")
fill(buf, REGION, 0xA5A5A5A5)
local rA, cA = run674("[A]", buf, 72, 400, cnt)
local lastA, nA = span(buf, REGION)
print(string.format("[A] differing dwords=%d furthest offset=0x%X", nA, lastA))
if lastA >= 0x4000 then
    print("[A] *** WRITE EXCEEDS THE FIRST PAGE: the record count is limited by")
    print("[A] *** arg3 alone, not by any buffer length the caller supplies ***")
elseif lastA >= 0 then
    print("[A] all writes stayed inside the first 16 KiB page")
end

-- ---- [B] does the limit truncate? ----
print("")
for _, lim in ipairs({8, 1, 0}) do
    fill(buf, REGION, 0xA5A5A5A5)
    local r, c = run674("[B lim=" .. lim .. "]", buf, 72, lim, cnt)
    local last, n = span(buf, REGION)
    print(string.format("[B lim=%d] differing dwords=%d furthest=0x%X", lim, n, last))
end

-- ---- [C] a large limit on a region we own end to end ----
print("")
print("[C] 674(buf, 72, 4000, cnt) -- the map has ~317 entries")
fill(buf, REGION, 0xA5A5A5A5)
local rC, cC = run674("[C]", buf, 72, 4000, cnt)
local lastC, nC = span(buf, REGION)
print(string.format("[C] differing dwords=%d furthest=0x%X", nC, lastC))
print("[C] if furthest stays below 0x10000 the kernel stopped at the map size")

-- ---- [D] how much of countp does the kernel touch? ----
print("")
print("[D] countp sentinel 0xEEEEEEEE over 0x1000")
fill(cnt, 0x1000, 0xEEEEEEEE)
local rD = run674("[D]", buf, 72, 16, cnt)
local lastD, nD = span(cnt, 0x1000)
print(string.format("[D] countp differing dwords=%d furthest=0x%X (want 1/0x0)", nD, lastD))

print("")
print("=== PROBE 1563a COMPLETE ===")
