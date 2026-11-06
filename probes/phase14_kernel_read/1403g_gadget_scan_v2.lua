-- CRASH_CLASS: LOW
-- PROBE 1403g: lean gadget scan — full eboot 4.6MB
--
-- Scans for 3-byte patterns only, no extra reads.
-- Reports offset + surrounding 4 bytes for context.
-- Patterns: rdtsc;ret, rdtscp, clflush, lfence, mfence

print("=== 1403g: gadget scan v2 ===")

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

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

local SIZE = 0x4C0000  -- 4.75 MB

-- We'll store just counts and first few offsets
local hits = {
    rdtsc_ret = {},  -- 0F 31 C3
    rdtscp = {},     -- 0F 01 F9
    clflush = {},    -- 0F AE [38-3F]
    lfence = {},     -- 0F AE E8
    mfence = {},     -- 0F AE F0
    all_rdtsc = {},  -- 0F 31 (any following byte)
}

-- Scan: read 2 consecutive dwords, extract 8 bytes, check all positions
local prev_d = nil
for off = 0, SIZE - 4, 4 do
    local d = rd(ebn + off)
    if not d then break end

    local b = {}
    b[0] = d % 256
    b[1] = math.floor(d / 256) % 256
    b[2] = math.floor(d / 65536) % 256
    b[3] = math.floor(d / 16777216) % 256

    -- Check 3-byte patterns starting at positions 0 and 1 within this dword
    for p = 0, 1 do
        local x, y, z = b[p], b[p+1], b[p+2]
        if x == 0x0F and y == 0x31 then
            hits.all_rdtsc[#hits.all_rdtsc+1] = {off + p, z}
            if z == 0xC3 then
                hits.rdtsc_ret[#hits.rdtsc_ret+1] = off + p
            end
        end
        if x == 0x0F and y == 0x01 and z == 0xF9 then
            hits.rdtscp[#hits.rdtscp+1] = off + p
        end
        if x == 0x0F and y == 0xAE then
            if z >= 0x38 and z <= 0x3F then hits.clflush[#hits.clflush+1] = {off + p, z} end
            if z == 0xE8 then hits.lfence[#hits.lfence+1] = off + p end
            if z == 0xF0 then hits.mfence[#hits.mfence+1] = off + p end
        end
    end

    -- Cross-boundary: prev byte 2-3 + current byte 0
    if prev_d then
        local p2 = math.floor(prev_d / 65536) % 256
        local p3 = math.floor(prev_d / 16777216) % 256
        -- Pattern at prev+2
        if p2 == 0x0F and p3 == 0x31 then
            hits.all_rdtsc[#hits.all_rdtsc+1] = {off - 2, b[0]}
            if b[0] == 0xC3 then hits.rdtsc_ret[#hits.rdtsc_ret+1] = off - 2 end
        end
        if p2 == 0x0F and p3 == 0x01 and b[0] == 0xF9 then
            hits.rdtscp[#hits.rdtscp+1] = off - 2
        end
        if p2 == 0x0F and p3 == 0xAE then
            if b[0] >= 0x38 and b[0] <= 0x3F then hits.clflush[#hits.clflush+1] = {off - 2, b[0]} end
            if b[0] == 0xE8 then hits.lfence[#hits.lfence+1] = off - 2 end
            if b[0] == 0xF0 then hits.mfence[#hits.mfence+1] = off - 2 end
        end
        -- Pattern at prev+3
        if p3 == 0x0F and b[0] == 0x31 then
            hits.all_rdtsc[#hits.all_rdtsc+1] = {off - 1, b[1]}
            if b[1] == 0xC3 then hits.rdtsc_ret[#hits.rdtsc_ret+1] = off - 1 end
        end
        if p3 == 0x0F and b[0] == 0x01 and b[1] == 0xF9 then
            hits.rdtscp[#hits.rdtscp+1] = off - 1
        end
        if p3 == 0x0F and b[0] == 0xAE then
            if b[1] >= 0x38 and b[1] <= 0x3F then hits.clflush[#hits.clflush+1] = {off - 1, b[1]} end
            if b[1] == 0xE8 then hits.lfence[#hits.lfence+1] = off - 1 end
            if b[1] == 0xF0 then hits.mfence[#hits.mfence+1] = off - 1 end
        end
    end

    prev_d = d
end

-- ============================================================
-- Results
-- ============================================================
print("")
print("=== RESULTS ===")
print(string.format("rdtsc;ret: %d", #hits.rdtsc_ret))
for i = 1, math.min(#hits.rdtsc_ret, 20) do
    print(string.format("  +0x%06X", hits.rdtsc_ret[i]))
end

print(string.format("rdtscp: %d", #hits.rdtscp))
for i = 1, math.min(#hits.rdtscp, 20) do
    print(string.format("  +0x%06X", hits.rdtscp[i]))
end

print(string.format("clflush: %d", #hits.clflush))
for i = 1, math.min(#hits.clflush, 20) do
    print(string.format("  +0x%06X modrm=%02X", hits.clflush[i][1], hits.clflush[i][2]))
end

print(string.format("lfence: %d  mfence: %d", #hits.lfence, #hits.mfence))
for i = 1, math.min(#hits.lfence, 10) do
    print(string.format("  lfence +0x%06X", hits.lfence[i]))
end
for i = 1, math.min(#hits.mfence, 10) do
    print(string.format("  mfence +0x%06X", hits.mfence[i]))
end

-- All rdtsc hits with their following byte
print(string.format("all rdtsc: %d", #hits.all_rdtsc))
for i = 1, math.min(#hits.all_rdtsc, 30) do
    local off = hits.all_rdtsc[i][1]
    local fb = hits.all_rdtsc[i][2]
    print(string.format("  +0x%06X next=%02X", off, fb))
end

print("")
print("=== 1403g DONE ===")
