-- CRASH_CLASS: LOW
-- PROBE 1403f: scan full eboot for clean rdtsc/rdtscp/clflush gadgets
--
-- Looking for:
--   0F 31 C3         rdtsc; ret (clean, full 32-bit EAX)
--   0F 31 48 89 07   rdtsc; mov [rdi],rax (immediate store before clobber)
--   0F 01 F9         rdtscp (also puts TSC in EAX:EDX, proc ID in ECX)
--   0F AE 38..3F     clflush [reg] (cache line flush)
--   0F AE E8         lfence
--   0F AE F0         mfence
-- Scans full eboot .text (~4.6MB at 0x4000 granularity)

print("=== 1403f: gadget scan ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local eboot_n = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Eboot .text size (scan up to 4.8MB to be safe)
local SCAN_SIZE = 0x4C0000  -- 4.75 MB
print(string.format("scanning %d KB...", SCAN_SIZE / 1024))

-- Results storage
local rdtsc_ret = {}      -- 0F 31 C3
local rdtsc_mov = {}      -- 0F 31 48 89 07 (rdtsc; mov [rdi],rax)
local rdtscp = {}          -- 0F 01 F9
local clflush = {}         -- 0F AE 38..3F
local lfence = {}          -- 0F AE E8
local mfence = {}          -- 0F AE F0

-- Scan 4 bytes at a time, checking patterns at each byte position
-- Keep previous dword to check cross-boundary patterns
local prev = nil
local count = 0

for off = 0, SCAN_SIZE - 4, 4 do
    local d = rd(eboot_n + off)
    if not d then break end

    local b = {}
    b[0] = d % 256
    b[1] = math.floor(d / 256) % 256
    b[2] = math.floor(d / 65536) % 256
    b[3] = math.floor(d / 16777216) % 256

    -- Check within this dword
    for p = 0, 1 do
        -- rdtsc;ret = 0F 31 C3
        if b[p] == 0x0F and b[p+1] == 0x31 and b[p+2] == 0xC3 then
            rdtsc_ret[#rdtsc_ret+1] = off + p
        end
        -- rdtscp = 0F 01 F9
        if b[p] == 0x0F and b[p+1] == 0x01 and b[p+2] == 0xF9 then
            rdtscp[#rdtscp+1] = off + p
        end
        -- clflush = 0F AE 38..3F
        if b[p] == 0x0F and b[p+1] == 0xAE and b[p+2] >= 0x38 and b[p+2] <= 0x3F then
            clflush[#clflush+1] = {off + p, b[p+2]}
        end
        -- lfence = 0F AE E8
        if b[p] == 0x0F and b[p+1] == 0xAE and b[p+2] == 0xE8 then
            lfence[#lfence+1] = off + p
        end
        -- mfence = 0F AE F0
        if b[p] == 0x0F and b[p+1] == 0xAE and b[p+2] == 0xF0 then
            mfence[#mfence+1] = off + p
        end
    end

    -- Check position 2 (pattern needs next dword for 3rd byte)
    -- rdtsc at pos 2: 0F at b[2], 31 at b[3], C3 at next[0]
    -- We'll handle cross-boundary with prev

    -- Cross-boundary: last bytes of prev + first bytes of current
    if prev then
        local pb = {}
        pb[0] = prev % 256
        pb[1] = math.floor(prev / 256) % 256
        pb[2] = math.floor(prev / 65536) % 256
        pb[3] = math.floor(prev / 16777216) % 256

        -- Pattern starting at prev byte 2 (spans into current byte 0)
        if pb[2] == 0x0F and pb[3] == 0x31 and b[0] == 0xC3 then
            rdtsc_ret[#rdtsc_ret+1] = off - 2
        end
        if pb[2] == 0x0F and pb[3] == 0x01 and b[0] == 0xF9 then
            rdtscp[#rdtscp+1] = off - 2
        end
        if pb[2] == 0x0F and pb[3] == 0xAE and b[0] >= 0x38 and b[0] <= 0x3F then
            clflush[#clflush+1] = {off - 2, b[0]}
        end
        if pb[2] == 0x0F and pb[3] == 0xAE and b[0] == 0xE8 then
            lfence[#lfence+1] = off - 2
        end
        if pb[2] == 0x0F and pb[3] == 0xAE and b[0] == 0xF0 then
            mfence[#mfence+1] = off - 2
        end

        -- Pattern starting at prev byte 3 (spans into current bytes 0-1)
        if pb[3] == 0x0F and b[0] == 0x31 and b[1] == 0xC3 then
            rdtsc_ret[#rdtsc_ret+1] = off - 1
        end
        if pb[3] == 0x0F and b[0] == 0x01 and b[1] == 0xF9 then
            rdtscp[#rdtscp+1] = off - 1
        end
        if pb[3] == 0x0F and b[0] == 0xAE and b[1] >= 0x38 and b[1] <= 0x3F then
            clflush[#clflush+1] = {off - 1, b[1]}
        end
        if pb[3] == 0x0F and b[0] == 0xAE and b[1] == 0xE8 then
            lfence[#lfence+1] = off - 1
        end
        if pb[3] == 0x0F and b[0] == 0xAE and b[1] == 0xF0 then
            mfence[#mfence+1] = off - 1
        end
    end

    -- Also check for rdtsc;mov_rdi pattern: 0F 31 48 89 07
    -- Within current: only pos 0 can fit 5 bytes... no, across boundary better
    -- Just check 0F 31 at any position and peek next bytes
    for p = 0, 3 do
        if b[p] == 0x0F then
            local next_b = nil
            if p + 1 <= 3 then
                next_b = b[p+1]
            end
            if next_b == 0x31 then
                -- Found rdtsc, check what follows
                local follow = {}
                for j = 1, 6 do
                    local fb = rd(eboot_n + off + p + 2 + j - 1)
                    if fb then
                        follow[j] = fb % 256
                    end
                end
                -- Check for 48 89 07 (mov [rdi],rax) right after
                if follow[1] == 0x48 and follow[2] == 0x89 and follow[3] == 0x07 then
                    rdtsc_mov[#rdtsc_mov+1] = off + p
                end
            end
        end
    end

    prev = d
    count = count + 1
    if count % 0x40000 == 0 then
        print(string.format("  scanned %d KB...", (count * 4) / 1024))
    end
end

-- ============================================================
-- Results
-- ============================================================
print("")
print("=== results ===")

print(string.format("rdtsc;ret (0F 31 C3): %d hits", #rdtsc_ret))
for i = 1, math.min(#rdtsc_ret, 10) do
    local off = rdtsc_ret[i]
    -- Read 8 bytes for context
    local d1 = rd(eboot_n + off)
    local d2 = rd(eboot_n + off + 4)
    print(string.format("  +0x%06X d1=%08X d2=%08X", off, d1 or 0, d2 or 0))
end

print(string.format("rdtsc;mov[rdi],rax: %d hits", #rdtsc_mov))
for i = 1, math.min(#rdtsc_mov, 10) do
    print(string.format("  +0x%06X", rdtsc_mov[i]))
end

print(string.format("rdtscp (0F 01 F9): %d hits", #rdtscp))
for i = 1, math.min(#rdtscp, 10) do
    local off = rdtscp[i]
    local d1 = rd(eboot_n + off)
    local d2 = rd(eboot_n + off + 4)
    print(string.format("  +0x%06X d1=%08X d2=%08X", off, d1 or 0, d2 or 0))
end

print(string.format("clflush (0F AE 38-3F): %d hits", #clflush))
for i = 1, math.min(#clflush, 10) do
    local off = clflush[i][1]
    local modrm = clflush[i][2]
    local d = rd(eboot_n + off)
    print(string.format("  +0x%06X modrm=%02X d=%08X", off, modrm, d or 0))
end

print(string.format("lfence: %d  mfence: %d", #lfence, #mfence))
for i = 1, math.min(#lfence, 5) do
    print(string.format("  lfence +0x%06X", lfence[i]))
end
for i = 1, math.min(#mfence, 5) do
    print(string.format("  mfence +0x%06X", mfence[i]))
end

-- Also check for rdtsc immediately followed by ret at other positions
-- by scanning for 31 C3 (which is xor eax,ecx / ret — different from 0F 31 C3)
-- Let's look for all rdtsc hits regardless of what follows
print("")
print("=== all rdtsc (0F 31) hits ===")
local all_rdtsc = {}
prev = nil
for off = 0, SCAN_SIZE - 4, 4 do
    local d = rd(eboot_n + off)
    if not d then break end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    if b0 == 0x0F and b1 == 0x31 then all_rdtsc[#all_rdtsc+1] = off end
    if b1 == 0x0F and b2 == 0x31 then all_rdtsc[#all_rdtsc+1] = off + 1 end
    if b2 == 0x0F and b3 == 0x31 then all_rdtsc[#all_rdtsc+1] = off + 2 end
    if prev then
        local pb3 = math.floor(prev / 16777216) % 256
        if pb3 == 0x0F and b0 == 0x31 then all_rdtsc[#all_rdtsc+1] = off - 1 end
    end
    prev = d
end

print(string.format("total rdtsc: %d", #all_rdtsc))
for i = 1, math.min(#all_rdtsc, 20) do
    local off = all_rdtsc[i]
    -- Read 8 bytes after rdtsc to see what follows
    local d1 = rd(eboot_n + off + 2)  -- bytes after 0F 31
    if d1 then
        local fb0 = d1 % 256
        local fb1 = math.floor(d1 / 256) % 256
        local fb2 = math.floor(d1 / 65536) % 256
        local fb3 = math.floor(d1 / 16777216) % 256
        print(string.format("  +0x%06X → %02X %02X %02X %02X",
            off, fb0, fb1, fb2, fb3))
    end
end

print("")
print("=== 1403f DONE ===")
