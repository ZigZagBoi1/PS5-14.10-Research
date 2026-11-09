-- CRASH_CLASS: MODERATE
-- PROBE 559b: is R10 from the thread context delivered as argument 4?
--
-- 549a tried to place argument 4 with a `pop rcx` in a chain and failed.
-- docs/THREADING_ALIVE_14_10.md:62-82 records that thr_create's context
-- stores the GPRs in syscall order, so +0x060 should be R10 and +0x068 R8.
-- Both children here run the same verified chain: the sysarch preamble, then
-- pop rdi / rsi / rdx, then the syscall, with argument 4 taken from the
-- context. sysctl(202) needs oldlenp as argument 4; 674 needs its count
-- pointer as argument 4.

print("=== PROBE 559b: CONTEXT ARG4 ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local n = N(v)
    return string.format("0x%08X", n < 0 and n + 0x100000000 or n)
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

local function child(rdi, rsi, rdx, r10, r8, r9, nr, tag)
    local ctx = memory.alloc(0x500)
    local ca = N(ctx)
    for i = 0, 0x4FC, 4 do wd(ca + i, 0) end
    wq(ca + 0x060, uint64(r10))
    wq(ca + 0x068, uint64(r8))
    wq(ca + 0x070, uint64(r9))
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
    emit(g_pop_rdi); emit(uint64(rdi))
    emit(g_pop_rsi); emit(uint64(rsi))
    emit(g_pop_rdx); emit(uint64(rdx))
    emit(g_pop_rax); emit(uint64(nr))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    wq(ca + 0x0e0, g_pop_rdi)
    wq(ca + 0x0f8, uint64(rsp))
    local tp = memory.alloc(8)
    wq(N(tp), uint64(0))
    local ok, rv = pcall(function() return sc_thr_create(ctx, uint64(N(tp)), uint64(0)) end)
    print(string.format("    [%s] thr_create ok=%s rv=%s tid=%d chain=%d alive=%s",
        tag, tostring(ok), tostring(N(rv)), rd(N(tp)) or 0, o, tostring(alive())))
    return o
end

local mib = memory.alloc(16)
wd(N(mib), 1); wd(N(mib) + 4, 14); wd(N(mib) + 8, 1); wd(N(mib) + 12, 1)
local obuf = memory.alloc(0x800)
local olen = memory.alloc(16)
wd(N(olen), 0x800); wd(N(olen) + 4, 0)

print("[A] control: sysctl from the parent")
local pok, pr = pcall(function() return mk(202)(uint64(N(mib)), uint64(3), uint64(N(obuf)), uint64(N(olen)), uint64(0), uint64(0)) end)
print(string.format("    ret=%s len=%d alive=%s", tostring(N(pr)), rd(N(olen)) or 0, tostring(alive())))

wd(N(olen), 0x800)
print("[B] child: sysctl, oldlenp only reachable as argument 4 (R10)")
child(N(mib), 3, N(obuf), N(olen), 0, 0, 202, "sysctl")
for i = 1, 700000 do end
print(string.format("    len after child=%d alive=%s", rd(N(olen)) or 0, tostring(alive())))

local buf2 = memory.alloc(0x10000)
local cnt2 = memory.alloc(0x40)
for i = 0, 0xFC00, 4 do wd(N(buf2) + i, 0) end
wd(N(cnt2), 0xCCCCCCCC)
print("[C] child: 674, count pointer as argument 4 (R10) and max as argument 5 (R8)")
child(N(buf2), 72, 512, N(cnt2), 512, 0, 674, "674")
for i = 1, 700000 do end
print(string.format("    count=%d rec0=%08X alive=%s", rd(N(cnt2)) or 0, rd(N(buf2)) or 0, tostring(alive())))
print("=== DONE ===")
