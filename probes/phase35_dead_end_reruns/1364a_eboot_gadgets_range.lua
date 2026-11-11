-- CRASH_CLASS: LOW (only reads the page range sys 547 reports readable)
-- PROBE 1364a: eboot gadget inventory, range taken from the 547 region record
--
-- 1361a failed for a reason this probe removes: it asked 547 per 64 KB block and
-- read the protection dword from a buffer it never touched first, and every block
-- came back as 0, so nothing was scanned
-- (results/phase35_dead_end_reruns/1361a_eboot_gadgets_dword_20261109_113907.txt).
-- 1362a then poisoned the record buffer with 0xDEADBEEF before each call and got
-- a coherent answer every time
-- (results/phase35_dead_end_reruns/1362a_sys547_record_shape_20261109_113946.txt):
--
--   +0x00 region start (u32)   +0x04 prot (u32)
--   +0x08 region end   (u32)   +0x0C prot (u32)
--   +0x10 memory type          +0x14 flags
--
-- Measured on this boot: eboot text 0x2ACC000-0x2F60000 prot 5 type 5 flags
-- 0x61042C; a heap buffer 0x107C0000-0x107D0000 prot 3 type 3; a GPU mmap
-- 0x105F8000-0x105FC000 prot 3 type 0x33.
--
-- So one query describes the whole text region, including its end. That removes
-- the per-block map: ask once, scan start..end only if prot is 3 or 5, page by
-- page with 1024 read_dword calls assembled into a string (memory.read_buffer
-- with a bulk size faulted in 1360a; memory.read_dword is the proven path, 1403h
-- used it over 1.1 MB twice).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1362a_sys547_record_shape_20261109_113946.txt
--   results/phase35_dead_end_reruns/1361a_eboot_gadgets_dword_20261109_113907.txt
--   results/phase35_dead_end_reruns/1360a_eboot_ring0_gadgets_20261109_113530.txt
--   results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062908.txt
--   probes/phase17_new_vectors/106a_sigreturn_srop.lua:80-95 (593 eboot base)

print("=== PROBE 1364a: EBOOT GADGET INVENTORY (547 range) ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rdP(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return N(v) end
    return nil
end
local function rd(a) return N(memory.read_dword(a)) end

local sc593 = mk(593)
local sc547 = mk(547)
local sc20 = mk(20)

local okp, pv = pcall(function() return sc20() end)
print("[0] pid=" .. (okp and N(pv) or 0))

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rdP(N(info) + 0x108) or 0
local eb_hi = rdP(N(info) + 0x10C) or 0
local EBN = N(eb_lo) + N(eb_hi) * 4294967296
print(string.format("[0] eboot text base from 593 = 0x%X", EBN))

local qout = memory.alloc(0x40)
local function record(addr)
    for i = 0, 0x3C, 4 do wd(N(qout) + i, 0xDEADBEEF) end
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(qout)) end)
    if not ok then return nil end
    return {
        rv = N(rv),
        start = rdP(N(qout) + 0),
        f4 = rdP(N(qout) + 4),
        stop = rdP(N(qout) + 8),
        fc = rdP(N(qout) + 0xC),
        prot = rdP(N(qout) + 0x10),
        flags = rdP(N(qout) + 0x14),
    }
end

local r = record(EBN)
if not r or r.rv ~= 0 then
    print("[!] 547 returned no record for the eboot base - aborting")
    return
end
-- 1362a measured the six dwords of the record on this boot: eboot text
-- {start=0x2ACC000, +4=0, end=0x2F60000, +0xC=0, +0x10=5, flags=0x61042C},
-- heap {start, +4=3, end, +0xC=3, +0x10=3, 0x610020}, GPU {start, +4=3, end,
-- +0xC=3, +0x10=0x33, 0x610020}. So the protection lives at +0x10, not +4:
-- 1361a read +4, saw 0 for every eboot block and scanned nothing.
print(string.format("[1] region 0x%X-0x%X  dwords: %d %d %d %d",
    r.start, r.stop, r.f4, r.fc, r.prot, r.flags))
print(string.format("[1] self-test dwords at 0x%X: %08X %08X %08X %08X %08X %08X %08X %08X",
    r.start, rdP(r.start) or 0, rdP(r.start + 4) or 0, rdP(r.start + 8) or 0,
    rdP(r.start + 12) or 0, rdP(r.start + 16) or 0, rdP(r.start + 20) or 0,
    rdP(r.start + 24) or 0, rdP(r.start + 28) or 0))
if not (r.prot == 3 or r.prot == 5 or r.prot == 0x33) then
    print("[!] range is not readable - aborting")
    return
end

local SCAN_START = r.start
local SCAN_END = r.stop
if SCAN_END <= SCAN_START or SCAN_END - SCAN_START > 0x800000 then
    print("[!] implausible range - aborting")
    return
end

-- Lua 5.1 has no \xNN escape: "\x5C\xC3" would compile to the four characters
-- x 5 C x C 3 (lua 5.1 read_string keeps the escaped character verbatim), which
-- is why the first version of this scan matched nothing. Every pattern is built
-- with string.char instead.
local C = string.char
local PATS = {
    { name = "pop rsp; ret",        p = C(0x5C, 0xC3),           want = 8 },
    { name = "pop rax; ret",        p = C(0x58, 0xC3),           want = 4 },
    { name = "pop rdi; ret",        p = C(0x5F, 0xC3),           want = 4 },
    { name = "pop rsi; ret",        p = C(0x5E, 0xC3),           want = 4 },
    { name = "pop rdx; ret",        p = C(0x5A, 0xC3),           want = 4 },
    { name = "pop rbx; ret",        p = C(0x5B, 0xC3),           want = 4 },
    { name = "mov rax,cr4; ret",    p = C(0x0F, 0x20, 0xE0, 0xC3),   want = 4 },
    { name = "mov cr4,rax; ret",    p = C(0x0F, 0x22, 0xE0, 0xC3),   want = 4 },
    { name = "mov [rdi],rax; ret",  p = C(0x48, 0x89, 0x07, 0xC3),   want = 6 },
    { name = "mov rax,[rdi]; ret",  p = C(0x48, 0x8B, 0x07, 0xC3),   want = 6 },
    { name = "mov [rsi],rax; ret",  p = C(0x48, 0x89, 0x06, 0xC3),   want = 4 },
    { name = "mov rax,[rsi]; ret",  p = C(0x48, 0x8B, 0x06, 0xC3),   want = 4 },
    { name = "mov [rdi],rbx; ret",  p = C(0x48, 0x89, 0x1F, 0xC3),   want = 4 },
    { name = "mov eax,ebx; ret",    p = C(0x89, 0xD8, 0xC3),       want = 4 },
    { name = "mov rax,rbx; ret",    p = C(0x48, 0x89, 0xD8, 0xC3),   want = 4 },
    { name = "cpuid; ret",          p = C(0x0F, 0xA2, 0xC3),       want = 4 },
    { name = "swapgs",              p = C(0x0F, 0x01, 0xF8),       want = 4 },
    { name = "iretq",               p = C(0x48, 0xCF),           want = 4 },
}
local CPUID = C(0x0F, 0xA2)

local hits = {}
local counts = {}
for i = 1, #PATS do hits[i] = {}; counts[i] = 0 end
local cpuid_sites = {}

local PAGE = 0x1000
local OVER = 16
local prev_tail = ""
local off = SCAN_START
local scanned = 0
local mark = 0

while off < SCAN_END do
    local parts = {}
    for d = 0, PAGE / 4 - 1 do
        local v = rd(off + d * 4)
        parts[#parts + 1] = string.char(v % 256, math.floor(v / 256) % 256,
            math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256)
    end
    local page = prev_tail .. table.concat(parts)
    scanned = scanned + PAGE
    local base = off - #prev_tail
    for i = 1, #PATS do
        local init = 1
        while true do
            local a = string.find(page, PATS[i].p, init, true)
            if not a then break end
            counts[i] = counts[i] + 1
            if #hits[i] < PATS[i].want then
                hits[i][#hits[i] + 1] = base + a - 1 - SCAN_START
            end
            init = a + 1
            if init > #page then break end
        end
    end
    local init = 1
    while #cpuid_sites < 10 do
        local a = string.find(page, CPUID, init, true)
        if not a then break end
        local w = {}
        local tail = string.sub(page, a, a + 15)
        for j = 1, #tail do w[#w + 1] = string.format("%02X", string.byte(tail, j)) end
        cpuid_sites[#cpuid_sites + 1] = { off = base + a - 1 - SCAN_START, hex = table.concat(w, " ") }
        init = a + 1
        if init > #page then break end
    end
    prev_tail = string.sub(page, -OVER)
    off = off + PAGE
    if scanned - mark >= 0x40000 then
        mark = scanned
        print(string.format("[2] scanned 0x%X / 0x%X", scanned, SCAN_END - SCAN_START))
    end
end

print(string.format("[3] scanned %d bytes of 0x%X", scanned, SCAN_END - SCAN_START))
print("")
for i = 1, #PATS do
    print(string.format("[%s] count=%d", PATS[i].name, counts[i]))
    for k = 1, #hits[i] do
        print(string.format("    eboot+0x%X", hits[i][k]))
    end
end
print("")
print("[cpuid sites]")
for k = 1, #cpuid_sites do
    print(string.format("    eboot+0x%X  %s", cpuid_sites[k].off, cpuid_sites[k].hex))
end
print("")
print("=== PROBE 1364a COMPLETE ===")
