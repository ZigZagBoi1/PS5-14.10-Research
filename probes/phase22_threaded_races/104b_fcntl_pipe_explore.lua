-- CRASH_CLASS: MODERATE
-- PROBE 104b: fcntl and pipe deep exploration
--
-- 104a discovered: pipe() returns real fds, fcntl(F_GETFL) works.
-- dup2 is kernel-blocked but fcntl F_DUPFD might bypass it.
-- Pipe fds have different internal kernel structures than sockets.
--
-- Tests:
--   A: F_DUPFD (cmd=0) — alternative to dup2
--   B: F_DUPFD_CLOEXEC (cmd=17) — dup with close-on-exec
--   C: F_SETFL (cmd=4) — set O_NONBLOCK
--   D: F_GETFD/F_SETFD (cmd=1/2) — close-on-exec flag
--   E: pipe() deep — create pipe, write/read through it
--   F: pipe + fcntl F_DUPFD race potential
--   G: fstat via child thread (sys 189 — known to kill from make_syscall)
--   H: sendmsg/recvmsg with pipe fds (SCM_RIGHTS alternative)

print("=== PROBE 104b: FCNTL + PIPE EXPLORATION ===")
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
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

-- Syscall wrappers
local sc_socket=mk(97)
local sc_close=mk(6)
local sc_pipe=mk(42)
local sc_fcntl=mk(92)
local sc_write=mk(4)
local sc_read=mk(3)
local sc_fstat=mk(189)  -- known lethal from make_syscall

local function closef(fd) pcall(function() sc_close(uint64(fd)) end) end

local function canary()
    local c=N(native.fcall_with_rax(stub,20))
    return c==pid, c
end

-- Create a base socket for testing
local ok_s,sfd=pcall(function() return sc_socket(uint64(2),uint64(2),uint64(0)) end)
local test_fd=ok_s and N(sfd) or -1
print(string.format("test socket fd=%d", test_fd))

-- ============================================================
print("")
print("--- A: F_DUPFD (cmd=0) — alternative to dup2 ---")
-- fcntl(fd, F_DUPFD=0, arg) — dup fd, new fd >= arg
local ok_da,rv_da=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(0), uint64(100))
end)
local dup_fd=ok_da and N(rv_da) or -999
print(string.format("  F_DUPFD(fd=%d, minfd=100) = %d", test_fd, dup_fd))
if dup_fd>=100 then
    print("  ** F_DUPFD WORKS! fd duplication available! **")
    -- Verify the duped fd works
    local ok_f,rv_f=pcall(function()
        return sc_fcntl(uint64(dup_fd), uint64(3), uint64(0))  -- F_GETFL
    end)
    print(string.format("  F_GETFL on duped fd=%d: %d", dup_fd, ok_f and N(rv_f) or -999))
    closef(dup_fd)
end

-- ============================================================
print("")
print("--- B: F_DUPFD_CLOEXEC (cmd=17) ---")
local ok_db,rv_db=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(17), uint64(200))
end)
print(string.format("  F_DUPFD_CLOEXEC(fd=%d, minfd=200) = %d",
    test_fd, ok_db and N(rv_db) or -999))
local dc_fd=ok_db and N(rv_db) or -1
if dc_fd>=200 then
    print("  ** F_DUPFD_CLOEXEC WORKS! **")
    -- Check close-on-exec flag
    local ok_gc,rv_gc=pcall(function()
        return sc_fcntl(uint64(dc_fd), uint64(1), uint64(0))  -- F_GETFD
    end)
    print(string.format("  F_GETFD on duped fd: %d (expect 1=FD_CLOEXEC)",
        ok_gc and N(rv_gc) or -999))
    closef(dc_fd)
end

-- ============================================================
print("")
print("--- C: F_SETFL — set O_NONBLOCK ---")
-- F_SETFL = 4, O_NONBLOCK = 4
local ok_sf,rv_sf=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(4), uint64(4))
end)
print(string.format("  F_SETFL(O_NONBLOCK) = %d", ok_sf and N(rv_sf) or -999))
-- Verify
local ok_gf,rv_gf=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(3), uint64(0))
end)
print(string.format("  F_GETFL after = %d (expect 6=RDWR|NONBLOCK)",
    ok_gf and N(rv_gf) or -999))
-- Reset
pcall(function() sc_fcntl(uint64(test_fd), uint64(4), uint64(2)) end)

-- ============================================================
print("")
print("--- D: F_GETFD / F_SETFD ---")
local ok_gd,rv_gd=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(1), uint64(0))
end)
print(string.format("  F_GETFD = %d", ok_gd and N(rv_gd) or -999))
local ok_sd,rv_sd=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(2), uint64(1))  -- set FD_CLOEXEC
end)
print(string.format("  F_SETFD(FD_CLOEXEC) = %d", ok_sd and N(rv_sd) or -999))
-- Read back
local ok_gd2,rv_gd2=pcall(function()
    return sc_fcntl(uint64(test_fd), uint64(1), uint64(0))
end)
print(string.format("  F_GETFD after = %d (expect 1)", ok_gd2 and N(rv_gd2) or -999))
-- Reset
pcall(function() sc_fcntl(uint64(test_fd), uint64(2), uint64(0)) end)

-- ============================================================
print("")
print("--- E: pipe() deep — create, write, read ---")
-- FreeBSD pipe(): returns fd[0] in RAX, fd[1] in EDX
-- From Lua, make_syscall returns RAX only. We need fd[1] too.
-- Method: call pipe(), fd[0] in RAX. fd[1] is the next fd number.

local ok_p,rv_p=pcall(function() return sc_pipe() end)
local pipe_r=ok_p and N(rv_p) or -1
print(string.format("  pipe() = %d (read end)", pipe_r))

-- The write end should be pipe_r + 1 (assuming sequential fd allocation)
local pipe_w=pipe_r+1

-- Test: write to pipe_w, read from pipe_r
local wbuf=memory.alloc(32); z(wbuf,32)
wd(wbuf, 0x41424344)  -- "ABCD"
wd(wbuf+4, 0x45464748)

local ok_wr,rv_wr=pcall(function()
    return sc_write(uint64(pipe_w), uint64(wbuf), uint64(8))
end)
print(string.format("  write(%d, 8 bytes) = %d", pipe_w, ok_wr and N(rv_wr) or -999))

local rbuf=memory.alloc(32); z(rbuf,32)
local ok_rd,rv_rd=pcall(function()
    return sc_read(uint64(pipe_r), uint64(rbuf), uint64(8))
end)
local read_rv=ok_rd and N(rv_rd) or -999
local read_val=rd(rbuf)
print(string.format("  read(%d, 8) = %d, data=0x%X (expect 0x41424344)",
    pipe_r, read_rv, read_val or 0))

if read_val==0x41424344 then
    print("  ** PIPE READ/WRITE WORKS! Full bidirectional IPC! **")
end

-- Test F_DUPFD on pipe fds
local ok_dp,rv_dp=pcall(function()
    return sc_fcntl(uint64(pipe_r), uint64(0), uint64(300))
end)
print(string.format("  F_DUPFD on pipe read end = %d", ok_dp and N(rv_dp) or -999))
if ok_dp and N(rv_dp)>=300 then
    print("  ** PIPE FD DUPLICATION WORKS! **")
    closef(N(rv_dp))
end

closef(pipe_r)
closef(pipe_w)

-- ============================================================
print("")
print("--- F: Multiple pipes + fd duplication stress ---")
-- Create several pipes, dup their fds, verify no corruption
local pipes={}
for i=1,5 do
    local ok_pi,rv_pi=pcall(function() return sc_pipe() end)
    if ok_pi then
        local r=N(rv_pi); local w=r+1
        pipes[i]={r=r, w=w}
        -- Write a unique marker to each pipe
        wd(wbuf, 0x1000+i)
        pcall(function() sc_write(uint64(w), uint64(wbuf), uint64(4)) end)
    end
end
-- Read from each pipe and verify marker
local pipe_ok=0
for i=1,5 do
    if pipes[i] then
        z(rbuf,32)
        local ok_r,rv_r=pcall(function()
            return sc_read(uint64(pipes[i].r), uint64(rbuf), uint64(4))
        end)
        local val=rd(rbuf)
        if val==(0x1000+i) then pipe_ok=pipe_ok+1
        else print(string.format("  pipe %d: expected 0x%X got 0x%X", i, 0x1000+i, val or 0))
        end
        closef(pipes[i].r); closef(pipes[i].w)
    end
end
print(string.format("  %d/5 pipes read/write correctly", pipe_ok))

-- ============================================================
print("")
print("--- G: fstat [sys 189] — from MAIN (known lethal) ---")
print("  SKIPPING main (kills process). Testing from child only.")

-- Child thread fstat test
if SA then
    local inf2=memory.alloc(0x200); wd(inf2,0x160)
    pcall(function() mk(593)(uint64(0),inf2) end)
    local elo2=rd(inf2+0x108) or 0; local ehi2=rd(inf2+0x10C) or 0
    if ehi2<0 then ehi2=ehi2+0x100000000 end
    if elo2<0 then elo2=elo2+0x100000000 end
    local PRAX2=uint64(string.format("0x%X%08X",ehi2,elo2+0x992))
    local PRDI2=uint64(string.format("0x%X%08X",ehi2,elo2+0xC9DFE))
    local PRSI2=uint64(string.format("0x%X%08X",ehi2,elo2+0xD77D))
    local WMOV2=uint64(string.format("0x%X%08X",ehi2,elo2+0x92C67))

    local mm2=mk(477); local tc2=mk(430)
    local ok_r2,reg2=pcall(function()
        return mm2(uint64(0),uint64(4*0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if ok_r2 then
        local R2=N(reg2)
        local ts2=R2; wq(ts2,uint64(999)); wq(ts2+8,uint64(0))
        local sl2=R2+0x40; wq(sl2,uint64(0)); wq(sl2+8,uint64(200000000))
        local tb2=R2+0x80
        local RES2=R2+0x1000
        local stk2=R2+0x4000*2
        local ctx2=R2+0x4000*3

        -- Setup context for fstat(test_fd, stat_buf)
        local stat_buf=memory.alloc(0x200); z(stat_buf,0x200)
        z(ctx2,0x200)
        wq(ctx2+_MG,uint64(0x480)); wd(ctx2+_FL,0)
        wq(ctx2+_TP,uint64(0x10000))
        wq(ctx2+_CS,uint64(0x43)); wq(ctx2+_SS,uint64(0x3B))
        wq(ctx2+_IP,SA); wq(ctx2+_SP,uint64(stk2))
        wq(ctx2+_AX,uint64(189))    -- fstat
        wq(ctx2+_DI,uint64(test_fd))
        wq(ctx2+_SI,uint64(N(stat_buf)))

        -- Stack: after syscall, store result, then sleep
        wq(RES2, uint64(0xDEADCAFE))
        local off=0
        wq(stk2+off,PRDI2); off=off+8
        wq(stk2+off,uint64(RES2)); off=off+8
        wq(stk2+off,WMOV2); off=off+8
        wq(stk2+off,PRDI2); off=off+8
        wq(stk2+off,uint64(ts2)); off=off+8
        wq(stk2+off,PRSI2); off=off+8
        wq(stk2+off,uint64(0)); off=off+8
        wq(stk2+off,PRAX2); off=off+8
        wq(stk2+off,uint64(240)); off=off+8
        wq(stk2+off,SA); off=off+8

        wq(tb2,uint64(0))
        pcall(function() tc2(uint64(ctx2), uint64(tb2), uint64(0)) end)
        native.fcall_with_rax(stub,240,N(sl2),0)

        local fstat_rv=rd(RES2)
        local c=N(native.fcall_with_rax(stub,20))
        if c~=pid then
            print(string.format("  fstat from child: PROCESS KILLED (canary=%d)", c))
        else
            if fstat_rv==0xDEADCAFE then
                print("  fstat from child: SENTINEL (child died before writing)")
            else
                print(string.format("  fstat from child: rv=%d", fstat_rv))
                if fstat_rv==0 then
                    -- Dump stat structure
                    local dev=rd(stat_buf)
                    local ino=rd(stat_buf+4)
                    local mode=rd(stat_buf+8)
                    local nlink=rd(stat_buf+12)
                    print(string.format("    dev=%d ino=%d mode=0x%X nlink=%d",
                        dev or 0, ino or 0, mode or 0, nlink or 0))
                end
            end
        end
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "!!FAIL="..fc))
print("=== 104b COMPLETE ===")
