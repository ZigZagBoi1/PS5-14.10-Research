-- CRASH_CLASS: MODERATE
-- PROBE 559a: five syscall arguments from a thread context
--
-- Context: docs/THREADING_ALIVE_14_10.md records that thr_create's context
-- stores the GPRs in syscall argument order: +0x048 RDI, +0x050 RSI,
-- +0x058 RDX, +0x060 R10, +0x068 R8, +0x070 R9, +0x078 RAX. Chains built so
-- far only set RDI/RSI/RDX/RAX and then called the stub, so the fourth, fifth
-- and sixth arguments were never settable. This probe starts the child
-- DIRECTLY at the stub with RIP=fn_addr, so every argument comes from the
-- context and nothing is clobbered.
--
-- The test is aio_create (669): flags, data, count, mode, out. If R8 is
-- delivered the call returns 0 and writes an id.

print("=== PROBE 559a: CONTEXT GPR ARGUMENTS ===")
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
    if type(v) == "table" and v.h then return string.format("0x%08X%08X", v.h, v.l) end
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
local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local eb_n = N(eb)

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

local sc_thr_create = mk(430)
local sc_create = mk(669)
local sc_poll = mk(664)
local sc_delete = mk(662)

local data = memory.alloc(0x100)
local out = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
for i = 0, 0xFC, 4 do wd(N(out) + i, 0) end

-- [A] control: the parent, same buffers
local prv = N(sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out))))
print(string.format("[A] parent create ret=%d id=%08X alive=%s", prv, rd(N(out)) or 0, tostring(alive())))
for i = 0, 0xFC, 4 do wd(N(out) + i, 0) end

-- [B] the child: a normal chain for RDI/RSI/RDX/RAX, with R8 supplied by the
-- context. The first attempt started the child at the stub with no FS set and
-- the process died inside thr_create, so the sysarch preamble stays.
local ctx = memory.alloc(0x500)
local ca = N(ctx)
for i = 0, 0x4FC, 4 do wd(ca + i, 0) end
wq(ca + 0x060, uint64(0))                 -- R10 = arg4 (unused by 669)
wq(ca + 0x068, uint64(N(out)))            -- R8  = out pointer
wq(ca + 0x070, uint64(0))                 -- R9  = arg6
wd(ca + 0x0d0, 0)
wq(ca + 0x108, uint64(0x480))
wq(ca + 0x110, uint64(0x10000))
wq(ca + 0x0c0, uint64(0x43))
wq(ca + 0x100, uint64(0x3b))

local stk = memory.alloc(0x8000 + 0x4000)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - 8
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end
emit(g_pop_rdi);   emit(uint64(129))
emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
emit(g_pop_rax);   emit(uint64(165))
emit(stub)
emit(g_pop_rdi);   emit(uint64(1))          -- flags
emit(g_pop_rsi);   emit(uint64(N(data)))    -- data
emit(g_pop_rdx);   emit(uint64(1))          -- count
emit(g_pop_rax);   emit(uint64(669))
emit(stub)
emit(g_pop_rdi);   emit(uint64(0))
emit(g_pop_rax);   emit(uint64(431))
emit(stub)
wq(ca + 0x0e0, g_pop_rdi)
wq(ca + 0x0f8, uint64(rsp))

local tid_ptr = memory.alloc(8)
wq(N(tid_ptr), uint64(0))
print(string.format("[B] chain bytes=%d R8=%08X", off, N(out)))
local ok, rv = pcall(function() return sc_thr_create(ctx, uint64(N(tid_ptr)), uint64(0)) end)
print(string.format("[C] thr_new ok=%s rv=%s alive=%s", tostring(ok), tostring(N(rv)), tostring(alive())))
for i = 1, 900000 do end
local id = rd(N(out))
print(string.format("[D] child create id=%08X out[4]=%08X alive=%s", id or 0, rd(N(out) + 4) or 0, tostring(alive())))

if id and id ~= 0 then
    local cell = memory.alloc(8)
    local st = memory.alloc(8)
    wd(N(cell), id)
    wd(N(st), 0xCCCCCCCC)
    local pok = pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    print(string.format("[E] poll ok=%s status=%s", tostring(pok), fmt(rd(N(st)))))
    wd(N(st), 0xCCCCCCCC)
    local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    print(string.format("[F] delete ok=%s status=%s alive=%s", tostring(dok), fmt(rd(N(st))), tostring(alive())))
end
-- [G] second child: 674 needs arg4 (count out pointer) in R10 and arg5
-- (max count) in R8. If both context slots are delivered this writes a count.
local buf2 = memory.alloc(0x10000)
local cnt2 = memory.alloc(0x20)
for i = 0, 0xFCFF, 4 do wd(N(buf2) + i, 0) end
wd(N(cnt2), 0xCCCCCCCC)
local ctx2 = memory.alloc(0x500)
local c2 = N(ctx2)
for i = 0, 0x4FC, 4 do wd(c2 + i, 0) end
wq(c2 + 0x060, uint64(N(cnt2)))            -- R10 = arg4 = count pointer
wq(c2 + 0x068, uint64(512))                -- R8  = arg5 = max
wq(c2 + 0x070, uint64(0))
wd(c2 + 0x0d0, 0)
wq(c2 + 0x108, uint64(0x480))
wq(c2 + 0x110, uint64(0x10000))
wq(c2 + 0x0c0, uint64(0x43))
wq(c2 + 0x100, uint64(0x3b))
local stk2 = memory.alloc(0x4000 + 0x2000)
local sb2 = N(stk2)
local ss2 = 0x4000
local rsp2 = sb2 + ss2 - 8
local off2 = 0
local function emit2(v) wq(rsp2 + off2, v); off2 = off2 + 8 end
emit2(g_pop_rdi); emit2(uint64(129))
emit2(g_pop_rsi); emit2(uint64(N(fs_ptr)))
emit2(g_pop_rax); emit2(uint64(165))
emit2(stub)
emit2(g_pop_rdi); emit2(uint64(N(buf2)))
emit2(g_pop_rsi); emit2(uint64(72))
emit2(g_pop_rdx); emit2(uint64(512))
emit2(g_pop_rax); emit2(uint64(674))
emit2(stub)
emit2(g_pop_rdi); emit2(uint64(0))
emit2(g_pop_rax); emit2(uint64(431))
emit2(stub)
wq(c2 + 0x0e0, g_pop_rdi)
wq(c2 + 0x0f8, uint64(rsp2))
local tid_ptr2 = memory.alloc(8)
wq(N(tid_ptr2), uint64(0))
local ok2, rv2 = pcall(function() return sc_thr_create(ctx2, uint64(N(tid_ptr2)), uint64(0)) end)
print(string.format("[G] thr_new ok=%s rv=%s alive=%s", tostring(ok2), tostring(N(rv2)), tostring(alive())))
for i = 1, 900000 do end
print(string.format("[H] 674 from child: count=%d rec0=%08X alive=%s",
    rd(N(cnt2)) or 0, rd(N(buf2)) or 0, tostring(alive())))

print("=== DONE ===")
