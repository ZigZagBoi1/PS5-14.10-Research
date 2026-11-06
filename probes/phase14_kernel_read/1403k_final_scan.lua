-- CRASH_CLASS: LOW
-- PROBE 1403k: final eboot gadget scan 0x3A0000-0x494000
--
-- 1403h covered 0-0x3A0000 (3.625MB). 1403j confirmed pages
-- from 0x3A0000 to 0x490000+ are readable. This scans the rest.
-- Looking for rdtsc;ret, rdtscp, clflush, lfence, mfence.

print("=== 1403k: final scan 3.625-4.58MB ===")

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

local CHUNK = 0x1000
local START_OFF = 0x3A0000
local MAX_OFF = 0x494000

local rdtsc_ret = {}
local rdtscp = {}
local clflush = {}
local lfence_hits = {}
local mfence_hits = {}
local all_rdtsc = {}
local scanned = 0
local skipped = 0

for page_off = START_OFF, MAX_OFF - CHUNK, CHUNK do
    local test = rd(ebn + page_off)
    if not test then
        skipped = skipped + 1
        -- skip this page
    else
        local prev = nil
        for off = page_off, page_off + CHUNK - 4, 4 do
            local d = rd(ebn + off)
            if not d then break end

            local b0 = d % 256
            local b1 = math.floor(d / 256) % 256
            local b2 = math.floor(d / 65536) % 256
            local b3 = math.floor(d / 16777216) % 256

            for p = 0, 1 do
                local x, y, z
                if p == 0 then x, y, z = b0, b1, b2
                else x, y, z = b1, b2, b3 end

                if x == 0x0F and y == 0x31 then
                    all_rdtsc[#all_rdtsc+1] = {off + p, z}
                    if z == 0xC3 then rdtsc_ret[#rdtsc_ret+1] = off + p end
                end
                if x == 0x0F and y == 0x01 and z == 0xF9 then
                    rdtscp[#rdtscp+1] = off + p
                end
                if x == 0x0F and y == 0xAE then
                    if z >= 0x38 and z <= 0x3F then clflush[#clflush+1] = {off + p, z} end
                    if z == 0xE8 then lfence_hits[#lfence_hits+1] = off + p end
                    if z == 0xF0 then mfence_hits[#mfence_hits+1] = off + p end
                end
            end

            if prev then
                local p2 = math.floor(prev / 65536) % 256
                local p3 = math.floor(prev / 16777216) % 256
                if p2 == 0x0F and p3 == 0x31 then
                    all_rdtsc[#all_rdtsc+1] = {off - 2, b0}
                    if b0 == 0xC3 then rdtsc_ret[#rdtsc_ret+1] = off - 2 end
                end
                if p2 == 0x0F and p3 == 0x01 and b0 == 0xF9 then rdtscp[#rdtscp+1] = off - 2 end
                if p2 == 0x0F and p3 == 0xAE then
                    if b0 >= 0x38 and b0 <= 0x3F then clflush[#clflush+1] = {off - 2, b0} end
                    if b0 == 0xE8 then lfence_hits[#lfence_hits+1] = off - 2 end
                    if b0 == 0xF0 then mfence_hits[#mfence_hits+1] = off - 2 end
                end

                if p3 == 0x0F and b0 == 0x31 then
                    all_rdtsc[#all_rdtsc+1] = {off - 1, b1}
                    if b1 == 0xC3 then rdtsc_ret[#rdtsc_ret+1] = off - 1 end
                end
                if p3 == 0x0F and b0 == 0x01 and b1 == 0xF9 then rdtscp[#rdtscp+1] = off - 1 end
                if p3 == 0x0F and b0 == 0xAE then
                    if b1 >= 0x38 and b1 <= 0x3F then clflush[#clflush+1] = {off - 1, b1} end
                    if b1 == 0xE8 then lfence_hits[#lfence_hits+1] = off - 1 end
                    if b1 == 0xF0 then mfence_hits[#mfence_hits+1] = off - 1 end
                end
            end
            prev = d
        end
        scanned = scanned + CHUNK
    end
end

print("")
print(string.format("scanned %d KB, skipped %d pages", scanned / 1024, skipped))
print("")

print(string.format("rdtsc;ret (0F 31 C3): %d", #rdtsc_ret))
for i = 1, math.min(#rdtsc_ret, 20) do
    print(string.format("  +0x%06X", rdtsc_ret[i]))
end

print(string.format("rdtscp (0F 01 F9): %d", #rdtscp))
for i = 1, math.min(#rdtscp, 20) do
    print(string.format("  +0x%06X", rdtscp[i]))
end

print(string.format("clflush: %d", #clflush))
for i = 1, math.min(#clflush, 20) do
    print(string.format("  +0x%06X modrm=%02X", clflush[i][1], clflush[i][2]))
end

print(string.format("lfence: %d  mfence: %d", #lfence_hits, #mfence_hits))
for i = 1, math.min(#lfence_hits, 10) do print(string.format("  lfence +0x%06X", lfence_hits[i])) end
for i = 1, math.min(#mfence_hits, 10) do print(string.format("  mfence +0x%06X", mfence_hits[i])) end

print(string.format("all rdtsc (0F 31): %d", #all_rdtsc))
for i = 1, math.min(#all_rdtsc, 30) do
    print(string.format("  +0x%06X next=%02X", all_rdtsc[i][1], all_rdtsc[i][2]))
end

print("")
print("=== 1403k DONE ===")
