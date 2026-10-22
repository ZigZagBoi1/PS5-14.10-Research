-- CRASH_CLASS: LOW
-- PROBE 348a: does the GPU pool hand back pages it never zeroed?
--
-- Every route to kernel memory on this console is measured dead, but the GPU
-- pool is physical memory handed to us as normal mappings. If those pages come
-- out of a shared physical allocator without being zeroed, a freshly mapped
-- chunk can contain whatever the previous owner had - which is how a KASLR leak
-- would look. Nothing has ever scanned this pool; earlier scans covered the
-- malloc heap and the module data segments. This allocates chunks and samples
-- every 2 MiB page for kernel-shaped pointers and printable strings.

print("=== PROBE 348a: GPU POOL LEFTOVER SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function addr_str(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", to_num(h), to_num(l))
end
local function num_str(n)
    return string.format("0x%X_%08X", math.floor(n / 4294967296), n % 4294967296)
end

local Z = uint64(0)
local sc477 = make_syscall(477)
local CHUNK_MB = 64
local CHUNK = CHUNK_MB * 0x100000

local mapped = {}
local total = 0
for i = 1, 12 do
    local ok, rv = pcall(function()
        return sc477(Z, uint64(CHUNK), uint64(0x33), uint64(0x1002),
            uint64(0xFFFFFFFF), Z)
    end)
    if not ok then break end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    -- A refused mmap comes back as a value whose low half is -1, not as the
    -- 0xFFFF...FFFF pair the earlier probes assumed: get_hi_lo sees a plain
    -- number and reports (0, -1). Reading at that address killed the run at
    -- "total mapped = 768 MiB". Judge the rebuilt address instead of the halves.
    local probe = hi * 4294967296 + lo
    if probe <= 0 or probe >= 0x800000000000 then
        print(string.format("  mmap refused at %d (hi=0x%X lo=0x%X)", i, hi, lo))
        break
    end
    -- The mmap result is a uint64 object, and uint64 + number is rejected by the
    -- loader (242a died that way). A userland address is below 2^53, so rebuild
    -- it as an ordinary number and do the offsets in plain arithmetic.
    local base = hi * 4294967296 + lo
    mapped[#mapped + 1] = base
    total = total + CHUNK
    print(string.format("  chunk %2d = %s", i, num_str(base)))
end
print(string.format("  total mapped = %d MiB", math.floor(total / 0x100000)))

local kptr, kstr, nz = 0, 0, 0
local samples = {}
local strsamples = {}
local dumps = {}
local hot = {}

local function is_printable(b)
    return b >= 0x20 and b < 0x7F
end

local function note_qword(base, off, ci)
    local qh, ql = get_hi_lo(memory.read_qword(base + off))
    local hi, lo = to_num(qh), to_num(ql)
    if hi == 0 and lo == 0 then return false end
    nz = nz + 1
    if hi >= 0xFFFF8000 and not (hi == 0xFFFFFFFF and lo == 0xFFFFFFFF) then
        kptr = kptr + 1
        if #samples < 8 then
            samples[#samples + 1] = string.format("chunk%d+0x%X = 0x%08X%08X", ci, off, hi, lo)
        end
    end
    if #dumps < 2 then
        local parts = {}
        for k = 0, 7 do
            local h2, l2 = get_hi_lo(memory.read_qword(base + off + k * 8))
            parts[#parts + 1] = string.format("%08X%08X", to_num(h2), to_num(l2))
        end
        dumps[#dumps + 1] = string.format("chunk%d+0x%X: %s", ci, off, table.concat(parts, " "))
    end
    if #strsamples < 8 then
        local str = ""
        for k = 0, 15 do
            local b = to_num(memory.read_byte(base + off + k))
            if not is_printable(b) then str = "" break end
            str = str .. string.char(b)
        end
        if #str >= 12 then
            kstr = kstr + 1
            strsamples[#strsamples + 1] = string.format("chunk%d+0x%X = %q", ci, off, str)
        end
    end
    return true
end

if #mapped == 0 then
    print("  no chunk mapped: the pool is already spent in this process")
end

-- Phase 1: the first 64 KiB of the first chunk, every qword. A zeroed allocator
-- shows here immediately; anything else is worth the coarse pass below.
-- One whole chunk at every qword: 16.7% of the pool, and a complete 64 MiB of
-- contiguous physical memory, which is where a leftover structure would sit.
if mapped[1] then
    print("  [A] dense scan of chunk 1, every qword (64 MiB)")
    local found = 0
    for off = 0, CHUNK - 8, 8 do
        if note_qword(mapped[1], off, 1) then found = found + 1 end
    end
    print(string.format("      nonzero qwords = %d of %d", found, 8388608))
end

-- Phase 2: every 8 KiB across every chunk.
print("  [B] coarse scan, one qword per 8 KiB")
for ci, base in ipairs(mapped) do
    for off = 0, CHUNK - 8, 0x2000 do
        if note_qword(base, off, ci) and #hot < 2 then
            hot[#hot + 1] = { ci, base, off }
        end
    end
end

-- Phase 3: if the coarse pass found anything, read that window properly.
for _, h in ipairs(hot) do
    print(string.format("  [C] dense window at chunk%d+0x%X", h[1], h[3]))
    local from = h[3] - 0x8000
    if from < 0 then from = 0 end
    for off = from, from + 0x10000 - 8, 8 do
        note_qword(h[2], off, h[1])
    end
end

print(string.format("  scanned: nonzero=%d kernel-shaped=%d strings>=12=%d", nz, kptr, kstr))
for _, s in ipairs(dumps) do print("  FIRST-NONZERO " .. s) end
for _, s in ipairs(samples) do print("  KPTR " .. s) end
for _, s in ipairs(strsamples) do print("  STR  " .. s) end

print("")
print("=== 348a DONE ===")
