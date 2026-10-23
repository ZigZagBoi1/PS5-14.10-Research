-- CRASH_CLASS: LOW
-- PROBE 160g: PI-mutex EXIT diagnostic — single child
--
-- Minimal test: 1 child LOCKs PI mutex via sa, thr_exits.
-- Main observes: does m_owner get cleared? Are waiters woken?
-- Then main tries LOCK on the dead-owner mutex.
--
-- This establishes baseline behavior before multi-contender races.

print("=== PROBE 160g: PI EXIT DIAGNOSTIC ===")
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

-- Ignore ALL catchable signals (1-31 except 9=SIGKILL)
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
for sig = 1, 31 do
    if sig ~= 9 then
        wq(N(act), uint64(1)); wd(N(act) + 8, 0)
        pcall(function() sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
print("all signals ignored (1-31 except 9)")

-- Shared area
local shared = memory.alloc(0x200)
local MUTEX  = N(shared)
local EXIT_S = N(shared) + 0x10   -- thr_exit sentinel
local RET_S  = N(shared) + 0x20   -- LOCK return stored by child
for off = 0, 0x2C, 4 do wd(N(shared) + off, 0) end

-- Stack + context
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
    local tid = rq(N(tid_buf))
    return tr, tid
end

local sc_umtx = mk(454)

-- ========== TEST 1: Child getpid via sa (sanity) ==========
print("")
print("[1] Child getpid via sa (sanity check)")
local GETPID_RET = N(shared) + 0x30
local GETPID_SENT = N(shared) + 0x38
wd(GETPID_RET, 0)
wq(GETPID_SENT, uint64(0))

local CB = N(stk) + 0x4000
local p = 0
-- getpid
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(20))
p = cp(CB, p, sa)
-- store rax to GETPID_RET
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", GETPID_RET)))
p = cp(CB, p, eaddr(G.mov_w))
-- sentinel
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", GETPID_SENT)))
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64("0xDEAD"))
p = cp(CB, p, eaddr(G.mov_w))
-- spin
p = cp(CB, p, eaddr(G.jmp_loop))

local tr1, tid1 = spawn(CB)
print(string.format("  spawn ret=%s tid=%s", fmt(tr1), fmt(tid1)))

-- Wait for sentinel
for i = 1, 50000 do
    local s = rq(GETPID_SENT)
    if s and N(s) ~= 0 then break end
    if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
end

local gpid = rq(GETPID_RET)
local gsent = rq(GETPID_SENT)
print(string.format("  child_getpid=%s (expect 0x%X) sent=%s", fmt(gpid), pid, fmt(gsent)))

if gpid == nil or N(gpid) ~= pid then
    print("  SANITY FAILED — child ROP not working!")
    print("=== 160g ABORT ===")
    return
end
print("  SANITY OK")

if not alive() then print("DIED after test 1!") return end

-- ========== TEST 2: Child LOCK PI mutex, observe ==========
print("")
print("[2] Child LOCKs PI mutex, main observes")

-- Clear mutex
wd(MUTEX, 0)
wd(EXIT_S, 0); wd(EXIT_S + 4, 0)
wq(RET_S, uint64(0))

-- Chain: LOCK → store rax → sentinel → spin
CB = N(stk) + 0x6000
p = 0
-- LOCK
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(454))
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", MUTEX)))
p = cp(CB, p, eaddr(G.pop_rsi)); p = cp(CB, p, uint64(5))
p = cp(CB, p, sa)
-- store rax (LOCK return)
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", RET_S)))
p = cp(CB, p, eaddr(G.mov_w))
-- sentinel
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", EXIT_S)))
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64("0xBBBB"))
p = cp(CB, p, eaddr(G.mov_w))
-- spin
p = cp(CB, p, eaddr(G.jmp_loop))

local tr2, tid2 = spawn(CB)
print(string.format("  spawn ret=%s tid=%s", fmt(tr2), fmt(tid2)))

for i = 1, 50000 do
    local s = rq(EXIT_S)
    if s and N(s) ~= 0 then break end
    if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
end

local m_after_lock = rd(MUTEX) or 0
local lock_ret = rq(RET_S)
local lock_sent = rq(EXIT_S)
print(string.format("  LOCK ret=%s sent=%s", fmt(lock_ret), fmt(lock_sent)))
print(string.format("  m_owner=0x%08X (child TID should be here)", m_after_lock))

if m_after_lock == 0 then
    print("  LOCK didn't write TID — unexpected!")
end

if not alive() then print("DIED after test 2!") return end

-- ========== TEST 3: Child LOCK → thr_exit, observe m_owner ==========
print("")
print("[3] Child LOCKs then thr_exits — observe cleanup")

wd(MUTEX, 0)
local EXIT3_STATE = N(shared) + 0x40
local EXIT3_SENT = N(shared) + 0x48
wq(EXIT3_STATE, uint64(0))
wq(EXIT3_SENT, uint64(0))
wq(RET_S, uint64(0))

-- Chain: LOCK → store rax → thr_exit(EXIT3_STATE)
CB = N(stk) + 0x8000
p = 0
-- LOCK
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(454))
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", MUTEX)))
p = cp(CB, p, eaddr(G.pop_rsi)); p = cp(CB, p, uint64(5))
p = cp(CB, p, sa)
-- store rax
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", RET_S)))
p = cp(CB, p, eaddr(G.mov_w))
-- sentinel before exit
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", EXIT3_SENT)))
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64("0xCCCC"))
p = cp(CB, p, eaddr(G.mov_w))
-- thr_exit (state_ptr = EXIT3_STATE → kernel writes 1 here)
p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(431))
p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", EXIT3_STATE)))
p = cp(CB, p, sa)

local tr3, tid3 = spawn(CB)
print(string.format("  spawn ret=%s tid=%s", fmt(tr3), fmt(tid3)))

-- Wait for thr_exit sentinel
for i = 1, 100000 do
    local s = rd(EXIT3_STATE)
    if s and s ~= 0 then break end
    if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
end

local state3 = rd(EXIT3_STATE) or 0
local sent3 = rq(EXIT3_SENT)
local lock3_ret = rq(RET_S)
local m_after_exit = rd(MUTEX) or 0
print(string.format("  thr_exit state=%d sent=%s lock_ret=%s", state3, fmt(sent3), fmt(lock3_ret)))
print(string.format("  m_owner after exit = 0x%08X", m_after_exit))

if m_after_exit == 0 then
    print("  *** KERNEL CLEARED m_owner ON EXIT ***")
elseif state3 == 1 then
    print("  m_owner NOT cleared (dead TID remains) — confirmed from prior sessions")
else
    print("  thr_exit may not have completed (state=" .. state3 .. ")")
end

if not alive() then print("DIED after test 3!") return end

-- ========== TEST 4: Main LOCKs dead-owner mutex ==========
print("")
print("[4] Main LOCKs mutex with dead child owner")
print(string.format("  m_owner before = 0x%08X", rd(MUTEX) or 0))

local mret = nil
local mok = pcall(function()
    mret = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  LOCK pcall=%s ret=%s", tostring(mok), fmt(mret)))
print(string.format("  m_owner after = 0x%08X", rd(MUTEX) or 0))

if mok and mret and N(mret) == 0 then
    print("  *** MAIN ACQUIRED DEAD-OWNER MUTEX ***")
    -- Unlock: write 0 to m_owner
    wd(MUTEX, 0)
    print("  cleared m_owner")
elseif not mok then
    print("  LOCK pcall failed — might have blocked forever?")
else
    print(string.format("  LOCK returned error: %s", fmt(mret)))
end

if not alive() then print("DIED after test 4!") return end

-- ========== TEST 5: Rapid 1-child LOCK/EXIT + main contend (10 rounds) ==========
print("")
print("[5] Rapid LOCK/EXIT + main contend (10 rounds)")

local anomalies = 0
for round = 1, 10 do
    if not alive() then print(string.format("  DIED R%d!", round)) break end

    wd(MUTEX, 0)
    local R_STATE = N(shared) + 0x50
    wd(R_STATE, 0); wd(R_STATE + 4, 0)

    -- Child: LOCK → thr_exit (no sleep, immediate exit)
    CB = N(stk) + 0x4000 + ((round - 1) % 4) * 0x1000
    p = 0
    p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(454))
    p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", MUTEX)))
    p = cp(CB, p, eaddr(G.pop_rsi)); p = cp(CB, p, uint64(5))
    p = cp(CB, p, sa)
    p = cp(CB, p, eaddr(G.pop_rax)); p = cp(CB, p, uint64(431))
    p = cp(CB, p, eaddr(G.pop_rdi)); p = cp(CB, p, uint64(string.format("0x%X", R_STATE)))
    p = cp(CB, p, sa)

    spawn(CB)

    -- Main: short spin then contend
    for i = 1, 20 do native.fcall_with_rax(stub, 20) end

    -- Check if child exited already
    local child_done = (rd(R_STATE) or 0) ~= 0

    -- Main tries LOCK
    mret = nil
    mok = pcall(function()
        mret = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0))
    end)

    local mword = rd(MUTEX) or 0
    local r_state = rd(R_STATE) or 0

    if not mok or (mret and N(mret) ~= 0) then
        anomalies = anomalies + 1
        print(string.format("  R%d: ANOMALY mok=%s mret=%s mword=0x%X done=%s state=%d",
            round, tostring(mok), fmt(mret), mword, tostring(child_done), r_state))
    elseif round <= 3 or round == 10 then
        print(string.format("  R%d: ok mret=%s mword=0x%X done_before=%s state=%d",
            round, fmt(mret), mword, tostring(child_done), r_state))
    end

    -- Clean up: wait for child + clear mutex
    for i = 1, 50000 do
        if (rd(R_STATE) or 0) ~= 0 then break end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    wd(MUTEX, 0)
end

print(string.format("[5] anomalies=%d", anomalies))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 160g COMPLETE ===")
